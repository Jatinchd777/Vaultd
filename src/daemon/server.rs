use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        io::{AsRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};

use anyhow::Result;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use super::protocol::{AuthenticatedRequest, Request, Response};
use crate::storage::filesystem;
use crate::vault::store::Vault;

pub const SOCKET_ENV: &str = "VAULTD_SOCKET";
pub const TOKEN_ENV: &str = "VAULTD_TOKEN";
pub const TOKEN_BYTES: usize = 32;

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
        let path = PathBuf::from(sock);
        validate_env_socket_path(&path)?;
        return Ok(path);
    }

    current_project_socket_path()
}

/// Reject `$VAULTD_SOCKET` values pointing outside the runtime dir.
/// Without this, any env control (direnv, Makefile, plugin) redirects
/// secrets to an attacker socket.
fn validate_env_socket_path(path: &Path) -> Result<()> {
    let runtime_base = runtime_base_dir()?;
    let runtime_canon = std::fs::canonicalize(&runtime_base).unwrap_or(runtime_base);
    // Resolve the parent (socket itself may not exist yet for the daemon).
    let parent = path.parent().unwrap_or(Path::new("."));
    let parent_canon =
        std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    if parent_canon != runtime_canon {
        anyhow::bail!("untrusted VAULTD_SOCKET: must live inside {}", runtime_canon.display());
    }
    if path.as_os_str().as_encoded_bytes().len() >= 108 {
        anyhow::bail!("vaultd socket path too long for {}", path.display());
    }
    Ok(())
}

pub fn token_path_for_project(project_root: &Path, runtime_base: &Path) -> PathBuf {
    runtime_base.join(format!("vaultd-{}.token", project_hash(project_root)))
}

pub fn current_project_token_path() -> Result<PathBuf> {
    let project_root = filesystem::find_project_root()?;
    let runtime_base = runtime_base_dir()?;
    Ok(token_path_for_project(&project_root, &runtime_base))
}

/// Sibling `<socket>.token` for a given socket path.
/// Used by the daemon (which only knows the bound socket path) and by
/// clients pinned via `$VAULTD_SOCKET`.
pub fn token_path_for_socket(socket_path: &Path) -> PathBuf {
    let file_name = socket_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let token_name = if let Some(stripped) = file_name.strip_suffix(".sock") {
        format!("{stripped}.token")
    } else {
        format!("{file_name}.token")
    };
    match socket_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(token_name),
        _ => PathBuf::from(token_name),
    }
}

pub fn generate_session_token() -> Result<[u8; TOKEN_BYTES]> {
    let mut token = [0u8; TOKEN_BYTES];
    OsRng
        .try_fill_bytes(&mut token)
        .map_err(|e| anyhow::anyhow!("failed to generate session token: {e}"))?;
    Ok(token)
}

pub fn encode_token_hex(token: &[u8; TOKEN_BYTES]) -> String {
    let mut out = String::with_capacity(TOKEN_BYTES * 2);
    for byte in token {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn decode_token_hex(s: &str) -> Result<[u8; TOKEN_BYTES]> {
    let s = s.trim();
    if s.len() != TOKEN_BYTES * 2 {
        anyhow::bail!("invalid session token length");
    }
    let mut out = [0u8; TOKEN_BYTES];
    let bytes = s.as_bytes();
    for i in 0..TOKEN_BYTES {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("invalid session token encoding"),
    }
}

/// Constant-time equality to avoid leaking prefix matches via timing.
fn token_eq(a: &[u8; TOKEN_BYTES], b: &[u8; TOKEN_BYTES]) -> bool {
    let mut diff = 0u8;
    for i in 0..TOKEN_BYTES {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn write_token_file(path: &Path, token: &[u8; TOKEN_BYTES]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let hex = encode_token_hex(token);
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts.mode(0o600);
    let mut file = opts.open(path)?;
    file.write_all(hex.as_bytes())?;
    file.flush()?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Load the token the client should present:
/// `$VAULTD_TOKEN` first (vault shell), otherwise the canonical
/// per-project token file (detached CLI invocations in tests and shell).
pub fn load_client_token() -> Result<[u8; TOKEN_BYTES]> {
    if let Some(env) = std::env::var_os(TOKEN_ENV)
        && !env.is_empty()
    {
        let s = env.to_string_lossy().into_owned();
        return decode_token_hex(&s);
    }
    // If the socket is pinned via env, the token sibling lives next to it.
    if let Some(sock) = std::env::var_os(SOCKET_ENV)
        && !sock.is_empty()
    {
        let sibling = token_path_for_socket(&PathBuf::from(sock));
        if sibling.exists() {
            let raw = fs::read_to_string(&sibling)?;
            return decode_token_hex(&raw);
        }
    }
    let path = current_project_token_path()?;
    let raw = fs::read_to_string(&path).map_err(|_| anyhow::anyhow!("vaultd daemon is not running"))?;
    decode_token_hex(&raw).map_err(|_| anyhow::anyhow!("vaultd daemon is not running"))
}

/// UID of the peer on a Unix socket via `SO_PEERCRED`.
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        anyhow::bail!("failed to query peer credentials: {}", std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

fn check_peer_uid(stream: &UnixStream) -> Result<()> {
    let peer = peer_uid(stream)?;
    let own = unsafe { libc::getuid() };
    if peer != own {
        anyhow::bail!("vaultd daemon authentication failed");
    }
    Ok(())
}

pub fn is_running() -> Result<bool> {
    let path = current_project_socket_path()?;

    if !path.exists() {
        return Ok(false);
    }

    // Never unlink a symlink: a planted link would delete an arbitrary file.
    if let Ok(meta) = fs::symlink_metadata(&path)
        && meta.file_type().is_symlink()
    {
        anyhow::bail!("vaultd socket path is a symlink: {}", path.display());
    }

    match UnixStream::connect(&path) {
        Ok(_) => Ok(true),
        Err(_) => {
            // Only remove stale filesystem sockets, never symlinks.
            if let Ok(meta) = fs::symlink_metadata(&path) {
                if !meta.file_type().is_symlink() {
                    let _ = fs::remove_file(&path);
                    // Best-effort stale token cleanup alongside the socket.
                    let _ = fs::remove_file(token_path_for_socket(&path));
                }
            }
            Ok(false)
        }
    }
}

pub fn spawn_daemon_and_shell(vault: Vault, socket_path: PathBuf) -> Result<()> {
    let session_token = generate_session_token()?;
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
        let result = daemon_main(vault, pidfd, pipe_fds[1], &path, &session_token);

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

    exec_vault_shell(&socket_path, &session_token)
}

fn daemon_main(
    vault: Vault,
    pidfd: RawFd,
    ready_fd: RawFd,
    path: &Path,
    expected_token: &[u8; TOKEN_BYTES],
) -> Result<()> {
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

    // Bind succeeded: now publish the session token. Writing after bind
    // avoids a losing racer clobbering the winner's token file.
    let token_path = token_path_for_socket(path);
    if let Err(error) = write_token_file(&token_path, expected_token) {
        let _ = write_byte(ready_fd, 1);
        unsafe {
            libc::close(ready_fd);
        }
        drop(listener);
        let _ = fs::remove_file(path);
        return Err(error);
    }

    if let Err(error) = listener.set_nonblocking(true) {
        let _ = write_byte(ready_fd, 1);
        unsafe {
            libc::close(ready_fd);
        }
        drop(listener);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(&token_path);
        return Err(error.into());
    }

    if write_byte(ready_fd, 0).is_err() {
        drop(listener);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(&token_path);
        unsafe {
            libc::close(ready_fd);
        }
        anyhow::bail!("failed to signal daemon readiness");
    }

    unsafe {
        libc::close(ready_fd);
    }

    let mut vault = vault;
    let _reason = serve_loop(&listener, &mut vault, pidfd, expected_token)?;

    drop(listener);
    drop(vault);
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(&token_path);

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ShutdownReason {
    LockRequested,
    ShellExited,
}

fn serve_loop(
    listener: &UnixListener,
    vault: &mut Vault,
    pidfd: RawFd,
    expected_token: &[u8; TOKEN_BYTES],
) -> Result<ShutdownReason> {
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

                    match handle_connection(stream, vault, expected_token) {
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

fn handle_connection(
    mut stream: UnixStream,
    vault: &mut Vault,
    expected_token: &[u8; TOKEN_BYTES],
) -> Result<bool> {
    // Defense in depth: filesystem perms already restrict to our UID,
    // but verify explicitly so a misconfigured umask never opens the vault.
    if check_peer_uid(&stream).is_err() {
        let _ = serde_json::to_writer(
            &mut stream,
            &Response::Error("vaultd daemon authentication failed".to_string()),
        );
        return Ok(false);
    }

    let envelope: AuthenticatedRequest = serde_json::from_reader(&mut stream)?;
    let presented = decode_token_hex(&envelope.token)
        .map_err(|_| anyhow::anyhow!("vaultd daemon authentication failed"))?;
    if !token_eq(&presented, expected_token) {
        let _ = serde_json::to_writer(
            &mut stream,
            &Response::Error("vaultd daemon authentication failed".to_string()),
        );
        return Ok(false);
    }

    let request = envelope.request;
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

fn exec_vault_shell(socket_path: &Path, session_token: &[u8; TOKEN_BYTES]) -> Result<()> {
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
        .env(TOKEN_ENV, encode_token_hex(session_token))
        .exec();

    anyhow::bail!("failed to spawn vault shell (zsh): {err}")
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
