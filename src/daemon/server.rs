use std::{
    fs,
    os::unix::{
        fs::PermissionsExt,
        io::{AsRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

use anyhow::Result;
use sha2::{Digest, Sha256};

use super::protocol::{Request, Response};
use crate::storage::filesystem;
use crate::vault::store::Vault;

pub const SOCKET_ENV: &str = "VAULTD_SOCKET";

pub fn runtime_base_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir).join("vaultd"),
        _ => {
            let uid = unsafe { libc::getuid() };
            std::env::temp_dir().join(format!("vaultd-{uid}"))
        }
    };

    if !base.exists() {
        fs::create_dir_all(&base)?;
        let _ = fs::set_permissions(&base, fs::Permissions::from_mode(0o700));
    } else {
        let _ = fs::set_permissions(&base, fs::Permissions::from_mode(0o700));
    }

    Ok(base)
}

pub fn project_hash(project_root: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(project_root.to_string_lossy().as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(32);
    for byte in digest.iter().take(16) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn socket_path_for_project(project_root: &Path, runtime_base: &Path) -> PathBuf {
    runtime_base.join(format!("vaultd-{}.sock", project_hash(project_root)))
}

pub fn current_project_socket_path() -> Result<PathBuf> {
    let project_root = filesystem::find_project_root()?;
    let runtime_base = runtime_base_dir()?;
    let path = socket_path_for_project(&project_root, &runtime_base);

    if path.as_os_str().as_encoded_bytes().len() >= 108 {
        anyhow::bail!("vaultd socket path too long for {}", path.display());
    }

    Ok(path)
}

pub fn socket_path() -> Result<PathBuf> {
    if let Some(sock) = std::env::var_os(SOCKET_ENV)
        && !sock.is_empty()
    {
        return Ok(PathBuf::from(sock));
    }

    current_project_socket_path()
}

pub fn is_running() -> Result<bool> {
    let path = current_project_socket_path()?;

    if !path.exists() {
        return Ok(false);
    }

    match UnixStream::connect(&path) {
        Ok(_) => Ok(true),
        Err(_) => {
            fs::remove_file(&path)?;
            Ok(false)
        }
    }
}

pub fn spawn_daemon_and_shell(vault: Vault, socket_path: PathBuf) -> Result<()> {
    let mut pipe_fds = [0 as libc::c_int; 2];

    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!("failed to create daemon ready pipe");
    }

    unsafe {
        libc::fcntl(pipe_fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(pipe_fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
    }

    let parent_pid = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };

    if pid < 0 {
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        anyhow::bail!("failed to fork daemon");
    }

    if pid == 0 {
        // Daemon child. Must never return to the caller (it would exec a
        // second shell). Always `_exit`.
        unsafe {
            libc::close(pipe_fds[0]);
        }

        let pidfd = match pidfd_open(parent_pid) {
            Ok(fd) => fd,
            Err(_) => {
                let _ = write_byte(pipe_fds[1], 1);
                unsafe {
                    libc::close(pipe_fds[1]);
                }
                unsafe { libc::_exit(1) };
            }
        };

        unsafe {
            libc::fcntl(pidfd, libc::F_SETFD, libc::FD_CLOEXEC);
        }

        if unsafe { libc::setsid() } < 0 {
            let _ = write_byte(pipe_fds[1], 1);
            unsafe {
                libc::close(pipe_fds[1]);
                libc::close(pidfd);
                libc::_exit(1);
            }
        }

        let path = socket_path;
        let result = daemon_main(vault, pidfd, pipe_fds[1], &path);

        unsafe {
            libc::close(pidfd);
        }

        if result.is_ok() {
            unsafe { libc::_exit(0) };
        } else {
            unsafe { libc::_exit(1) };
        }
    }

    unsafe {
        libc::close(pipe_fds[1]);
    }

    let ready = read_byte(pipe_fds[0]);

    unsafe {
        libc::close(pipe_fds[0]);
    }

    match ready {
        Ok(0) => {}
        Ok(_) => {
            let mut status = 0;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
            anyhow::bail!("vaultd daemon failed to start");
        }
        Err(error) => {
            let mut status = 0;
            unsafe {
                libc::waitpid(pid, &mut status, libc::WNOHANG);
            }
            anyhow::bail!("failed waiting for vaultd daemon: {error}");
        }
    }

    drop(vault);

    exec_vault_shell(&socket_path)
}

fn daemon_main(vault: Vault, pidfd: RawFd, ready_fd: RawFd, path: &Path) -> Result<()> {
    detach_standard_streams();

    if let Some(parent) = path.parent() {
        if let Err(error) = fs::create_dir_all(parent) {
            let _ = write_byte(ready_fd, 1);
            unsafe {
                libc::close(ready_fd);
            }
            return Err(error.into());
        }
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
    }

    if path.exists() {
        let _ = write_byte(ready_fd, 1);
        unsafe {
            libc::close(ready_fd);
        }
        anyhow::bail!("vaultd daemon socket already exists for this project");
    }

    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = write_byte(ready_fd, 1);
            unsafe {
                libc::close(ready_fd);
            }
            return Err(error.into());
        }
    };

    if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
        let _ = write_byte(ready_fd, 1);
        unsafe {
            libc::close(ready_fd);
        }
        drop(listener);
        return Err(error.into());
    }

    if let Err(error) = listener.set_nonblocking(true) {
        let _ = write_byte(ready_fd, 1);
        unsafe {
            libc::close(ready_fd);
        }
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(error.into());
    }

    if write_byte(ready_fd, 0).is_err() {
        drop(listener);
        let _ = fs::remove_file(path);
        unsafe {
            libc::close(ready_fd);
        }
        anyhow::bail!("failed to signal daemon readiness");
    }

    unsafe {
        libc::close(ready_fd);
    }

    let mut vault = vault;
    let _reason = serve_loop(&listener, &mut vault, pidfd)?;

    drop(listener);
    drop(vault);
    let _ = fs::remove_file(path);

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ShutdownReason {
    LockRequested,
    ShellExited,
}

fn serve_loop(listener: &UnixListener, vault: &mut Vault, pidfd: RawFd) -> Result<ShutdownReason> {
    let listener_fd = listener.as_raw_fd();

    loop {
        let mut fds = [
            libc::pollfd {
                fd: listener_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let ret = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };

        if ret < 0 {
            let err = std::io::Error::last_os_error();

            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            anyhow::bail!("daemon poll failed: {err}");
        }

        // pidfd becomes readable when the monitored shell process exits.
        // This pins the exact shell opened before exec; no pid reuse race.
        if fds[1].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            return Ok(ShutdownReason::ShellExited);
        }

        if fds[1].revents & libc::POLLNVAL != 0 {
            return Ok(ShutdownReason::ShellExited);
        }

        if fds[0].revents & libc::POLLNVAL != 0 {
            anyhow::bail!("daemon socket poll error");
        }

        if fds[0].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);

                    match handle_connection(stream, vault) {
                        Ok(true) => return Ok(ShutdownReason::LockRequested),
                        Ok(false) => {}
                        Err(_) => {}
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
    }
}

fn handle_connection(mut stream: UnixStream, vault: &mut Vault) -> Result<bool> {
    let request: Request = serde_json::from_reader(&mut stream)?;

    let should_stop = matches!(request, Request::Lock);

    let response = match request {
        Request::Ping => Response::Pong,

        Request::List => {
            let names = vault
                .credentials()
                .iter()
                .map(|credential| credential.name.clone())
                .collect();

            Response::CredentialNames(names)
        }

        Request::Get { name } => match vault.get(&name) {
            Ok(value) => Response::Credential {
                name,
                value: value.to_string(),
            },

            Err(error) => Response::Error(error.to_string()),
        },

        Request::Add { name, value } => match vault.add(name, value) {
            Ok(()) => Response::Success,
            Err(error) => Response::Error(error.to_string()),
        },

        Request::Set { name, value } => match vault.set(name, value) {
            Ok(()) => Response::Success,
            Err(error) => Response::Error(error.to_string()),
        },

        Request::Remove { name } => match vault.remove(&name) {
            Ok(()) => Response::Success,
            Err(error) => Response::Error(error.to_string()),
        },

        Request::Environment => Response::Environment(vault.environment()),

        Request::Lock => Response::Locked,
    };

    serde_json::to_writer(&mut stream, &response)?;

    stream.shutdown(std::net::Shutdown::Write)?;

    Ok(should_stop)
}

/// Open a pidfd for `pid` (Linux `pidfd_open`, no PID-reuse race).
fn pidfd_open(pid: libc::pid_t) -> Result<RawFd> {
    let fd = unsafe {
        libc::syscall(
            libc::SYS_pidfd_open as libc::c_long,
            pid as libc::c_int,
            0 as libc::c_int,
        )
    };

    if fd < 0 {
        anyhow::bail!("pidfd_open failed: {}", std::io::Error::last_os_error());
    }

    Ok(fd as RawFd)
}

fn write_byte(fd: RawFd, byte: u8) -> Result<()> {
    let buf = [byte];

    loop {
        let ret = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, 1) };

        if ret == 1 {
            return Ok(());
        }

        if ret < 0 {
            let err = std::io::Error::last_os_error();

            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            anyhow::bail!("pipe write failed: {err}");
        }

        anyhow::bail!("pipe write failed: short write");
    }
}

fn read_byte(fd: RawFd) -> Result<u8> {
    let mut buf = [0u8; 1];

    loop {
        let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };

        if ret == 1 {
            return Ok(buf[0]);
        }

        if ret == 0 {
            anyhow::bail!("daemon exited before signaling readiness");
        }

        if ret < 0 {
            let err = std::io::Error::last_os_error();

            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            anyhow::bail!("pipe read failed: {err}");
        }
    }
}

fn detach_standard_streams() {
    unsafe {
        libc::close(libc::STDIN_FILENO);
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);

        // Reopen 0,1,2 on /dev/null so later sockets do not reuse them.
        let fd = libc::open(c"/dev/null".as_ptr() as *const libc::c_char, libc::O_RDWR);

        if fd >= 0 {
            if fd != libc::STDIN_FILENO {
                libc::dup2(fd, libc::STDIN_FILENO);
            }
            libc::dup2(libc::STDIN_FILENO, libc::STDOUT_FILENO);
            libc::dup2(libc::STDIN_FILENO, libc::STDERR_FILENO);

            if fd != libc::STDIN_FILENO && fd != libc::STDOUT_FILENO && fd != libc::STDERR_FILENO {
                libc::close(fd);
            }
        }
    }
}

fn exec_vault_shell(socket_path: &Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    println!("Vault unlocked - entering vault shell (exit to auto-lock)");

    let _ = std::io::stdout().flush();

    let vaultd_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "vaultd".to_string());
    let vaultd_quoted = shell_single_quote(&vaultd_exe);
    let script = format!("eval \"$({vaultd_quoted} __env)\"; exec zsh -i");

    let err = std::process::Command::new("zsh")
        .arg("-i")
        .arg("-c")
        .arg(script)
        .env(SOCKET_ENV, socket_path)
        .exec();

    anyhow::bail!("failed to spawn vault shell (zsh): {err}")
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
