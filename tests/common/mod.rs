//! Shared helpers for vaultd's black-box integration tests.
//!
//! Each test drives the compiled binary (`CARGO_BIN_EXE_vaultd`) inside an
//! isolated temp project directory with its own `XDG_RUNTIME_DIR`, so tests
//! never touch a real vault and never fight each other over the daemon
//! socket.
//!
//! Password prompts go through `rpassword`, which reads `/dev/tty` and
//! ignores piped stdin, so interactive commands (`init`, `unlock`, prompted
//! `add`) run under a real pty provided here. Non-interactive commands use
//! plain piped stdio.

#![allow(dead_code)]

use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Long enough for Argon2id derives plus process spawn, short enough to
/// fail fast if something hangs.
pub const TIMEOUT: Duration = Duration::from_secs(120);

pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_vaultd"))
}

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("vaultd-test-{}-{}-{}", std::process::id(), tag, n));
        if path.exists() {
            std::fs::remove_dir_all(&path).unwrap();
        }
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// An isolated playground: a fake project dir, a private runtime dir for
/// the daemon socket, and an empty home so the vault shell starts without
/// reading the developer's real zsh config.
pub struct Env {
    pub project: TempDir,
    pub runtime: TempDir,
    pub home: TempDir,
}

impl Env {
    pub fn new(tag: &str) -> Self {
        let home = TempDir::new(&format!("{tag}-home"));
        // An existing (even empty) .zshrc keeps zsh from stopping at its
        // first-run zsh-newuser-install prompt inside the vault shell.
        std::fs::write(home.path().join(".zshrc"), "").expect("write .zshrc");
        Self {
            project: TempDir::new(&format!("{tag}-proj")),
            runtime: TempDir::new(&format!("{tag}-rt")),
            home,
        }
    }

    pub fn socket(&self) -> PathBuf {
        let project_root = std::fs::canonicalize(self.project.path())
            .unwrap_or_else(|_| self.project.path().to_path_buf());
        let runtime_base = self.runtime.path().join("vaultd");
        vaultd::daemon::server::socket_path_for_project(&project_root, &runtime_base)
    }

    fn base_command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(binary());
        cmd.args(args)
            .current_dir(self.project.path())
            .env("XDG_RUNTIME_DIR", self.runtime.path())
            .env("HOME", self.home.path())
            .env("TERM", "dumb");
        // Never leak the outer shell's project binding into test children.
        cmd.env_remove("VAULTD_SOCKET");
        cmd
    }

    /// Piped stdio, detached from any controlling terminal. Only for
    /// commands that never prompt (prompts need a tty, see `spawn_pty`).
    pub fn command(&self, args: &[&str]) -> Command {
        let mut cmd = self.base_command(args);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Detach so a stray prompt fails fast instead of blocking on a
        // terminal inherited from the developer's shell.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        cmd
    }

    /// Run to completion. `input` is fed on stdin then closed. Panics on
    /// timeout. Only for commands that never prompt.
    pub fn run(&self, args: &[&str], input: &str) -> Output {
        let mut child = self.command(args).spawn().expect("failed to spawn vaultd");
        if !input.is_empty() {
            child
                .stdin
                .take()
                .expect("no stdin")
                .write_all(input.as_bytes())
                .expect("failed to write stdin");
        } else {
            drop(child.stdin.take());
        }
        wait_output(&mut child, TIMEOUT, &format!("vaultd {args:?}"))
    }

    /// Block until the daemon socket shows up.
    pub fn wait_for_socket(&self, timeout: Duration) {
        let start = Instant::now();
        while !self.socket().exists() {
            if start.elapsed() >= timeout {
                panic!("daemon socket never appeared at {:?}", self.socket());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // The socket file exists as soon as it is bound; give the accept
        // loop a beat before the first client connects.
        std::thread::sleep(Duration::from_millis(200));
    }

    /// Block until `path` disappears.
    pub fn wait_for_gone(&self, path: &Path, timeout: Duration) {
        let start = Instant::now();
        while path.exists() {
            if start.elapsed() >= timeout {
                panic!("{path:?} never disappeared");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Socket for an explicit project + runtime dir pair (shared-runtime tests).
/// Mirrors `vaultd::daemon::server` derivation: canonical root hashed into
/// `<runtime>/vaultd/vaultd-<hash>.sock`. Resolves upward like the binary,
/// so subdirectories map to their project root.
pub fn socket_for(project: &Path, runtime: &Path) -> PathBuf {
    let root = vaultd::storage::filesystem::find_project_root_from(project).unwrap_or_else(|_| {
        std::fs::canonicalize(project).unwrap_or_else(|_| project.to_path_buf())
    });
    let base = runtime.join("vaultd");
    vaultd::daemon::server::socket_path_for_project(&root, &base)
}

fn base_command_in(project: &Path, runtime: &Path, home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(binary());
    cmd.args(args)
        .current_dir(project)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("HOME", home)
        .env("TERM", "dumb");
    cmd.env_remove("VAULTD_SOCKET");
    cmd
}

/// Non-interactive run against explicit dirs (shared `XDG_RUNTIME_DIR`).
pub fn run_in(project: &Path, runtime: &Path, home: &Path, args: &[&str]) -> Output {
    let mut cmd = base_command_in(project, runtime, home, args);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("failed to spawn vaultd");
    drop(child.stdin.take());
    wait_output(&mut child, TIMEOUT, &format!("vaultd {args:?}"))
}

/// Pty run against explicit dirs, for `init`/`unlock` prompts.
pub fn spawn_pty_in(project: &Path, runtime: &Path, home: &Path, args: &[&str]) -> PtySession {
    let pty = Pty::open();
    let slave_path = pty.slave_path();
    let open_slave = || {
        let bytes = slave_path.as_os_str().as_bytes();
        let fd = unsafe { libc::open(bytes.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        assert!(fd >= 0, "failed to open pty slave");
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    let mut cmd = base_command_in(project, runtime, home, args);
    cmd.stdin(Stdio::from(open_slave()))
        .stdout(Stdio::from(open_slave()))
        .stderr(Stdio::from(open_slave()));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("failed to spawn vaultd");
    PtySession { child, pty }
}

pub fn init_vault_in(project: &Path, runtime: &Path, home: &Path, password: &str) {
    let mut session = spawn_pty_in(project, runtime, home, &["init"]);
    session.pty.read_until("Create master password:", TIMEOUT);
    session.pty.send(&format!("{password}\n"));
    session.pty.read_until("Confirm master password:", TIMEOUT);
    session.pty.send(&format!("{password}\n"));
    session.pty.read_until("Vault initialized", TIMEOUT);
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd init");
    assert!(status.success(), "init failed with {status}");
}

pub fn wait_for_path(path: &Path, timeout: Duration) {
    let start = Instant::now();
    while !path.exists() {
        if start.elapsed() >= timeout {
            panic!("{path:?} never appeared");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(200));
}

pub fn wait_for_gone_path(path: &Path, timeout: Duration) {
    let start = Instant::now();
    while path.exists() {
        if start.elapsed() >= timeout {
            panic!("{path:?} never disappeared");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A child attached to a real pty, for commands that prompt for passwords.
pub struct PtySession {
    pub child: Child,
    pub pty: Pty,
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Closing the master fd makes the shell see EIO and exit, which in
        // turn shuts the daemon down. Kill as backstop.
        let _ = self.child.kill();
    }
}

/// Spawn under a pty that becomes the child's controlling terminal, so
/// `/dev/tty` reads (rpassword) work.
pub fn spawn_pty(env: &Env, args: &[&str]) -> PtySession {
    let pty = Pty::open();
    let slave_path = pty.slave_path();
    let open_slave = || {
        let bytes = slave_path.as_os_str().as_bytes();
        let fd = unsafe { libc::open(bytes.as_ptr() as *const libc::c_char, libc::O_RDWR) };
        assert!(fd >= 0, "failed to open pty slave");
        unsafe { OwnedFd::from_raw_fd(fd) }
    };
    let mut cmd = env.base_command(args);
    cmd.stdin(Stdio::from(open_slave()))
        .stdout(Stdio::from(open_slave()))
        .stderr(Stdio::from(open_slave()));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn().expect("failed to spawn vaultd");
    PtySession { child, pty }
}

/// Run `init` through a pty, answering both password prompts. Panics if it
/// does not succeed.
pub fn init_vault(env: &Env, password: &str) {
    let mut session = spawn_pty(env, &["init"]);
    session.pty.read_until("Create master password:", TIMEOUT);
    session.pty.send(&format!("{password}\n"));
    session.pty.read_until("Confirm master password:", TIMEOUT);
    session.pty.send(&format!("{password}\n"));
    session.pty.read_until("Vault initialized", TIMEOUT);
    let status = wait_exit(&mut session.child, TIMEOUT, "vaultd init");
    assert!(status.success(), "init failed with {status}");
}

/// A pty master side: write input, wait for expected output.
pub struct Pty {
    master: RawFd,
}

impl Pty {
    pub fn open() -> Self {
        unsafe {
            let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(master >= 0, "posix_openpt failed");
            assert_eq!(libc::grantpt(master), 0, "grantpt failed");
            assert_eq!(libc::unlockpt(master), 0, "unlockpt failed");
            Self { master }
        }
    }

    pub fn slave_path(&self) -> PathBuf {
        unsafe {
            let mut buf = [0 as libc::c_char; 128];
            let r = libc::ptsname_r(self.master, buf.as_mut_ptr(), buf.len());
            assert_eq!(r, 0, "ptsname_r failed");
            let path = CStr::from_ptr(buf.as_ptr()).to_str().unwrap().to_owned();
            PathBuf::from(path)
        }
    }

    pub fn send(&self, text: &str) {
        let mut data = text.as_bytes();
        while !data.is_empty() {
            let n = unsafe {
                libc::write(
                    self.master,
                    data.as_ptr() as *const libc::c_void,
                    data.len(),
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("pty write failed: {e}");
            }
            data = &data[n as usize..];
        }
    }

    /// Read until the accumulated output contains `needle`, normalizing
    /// terminal `\r\n` to `\n`. Returns everything seen. Panics on timeout
    /// or EOF, including what was seen to ease debugging.
    pub fn read_until(&self, needle: &str, timeout: Duration) -> String {
        let start = Instant::now();
        let mut buf: Vec<u8> = Vec::new();
        loop {
            if start.elapsed() >= timeout {
                panic!(
                    "timed out waiting for {needle:?}; saw:\n{}",
                    String::from_utf8_lossy(&buf)
                );
            }
            let mut pfd = libc::pollfd {
                fd: self.master,
                events: libc::POLLIN,
                revents: 0,
            };
            let r = unsafe { libc::poll(&mut pfd, 1, 100) };
            if r < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("pty poll failed: {e}");
            }
            if r == 0 {
                continue;
            }
            let mut tmp = [0u8; 4096];
            let n = unsafe {
                libc::read(
                    self.master,
                    tmp.as_mut_ptr() as *mut libc::c_void,
                    tmp.len(),
                )
            };
            if n <= 0 {
                let text = String::from_utf8_lossy(&buf).replace("\r\n", "\n");
                if text.contains(needle) {
                    return text;
                }
                panic!("pty EOF before {needle:?}; saw:\n{text}");
            }
            buf.extend_from_slice(&tmp[..n as usize]);
            let text = String::from_utf8_lossy(&buf).replace("\r\n", "\n");
            if text.contains(needle) {
                return text;
            }
        }
    }
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.master);
        }
    }
}

fn wait_output(child: &mut Child, timeout: Duration, what: &str) -> Output {
    let status = wait_exit(child, timeout, what);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut out) = child.stdout.take() {
        out.read_to_end(&mut stdout).unwrap();
    }
    if let Some(mut err) = child.stderr.take() {
        err.read_to_end(&mut stderr).unwrap();
    }
    Output {
        status,
        stdout,
        stderr,
    }
}

/// Wait for a child to exit, killing it on timeout. Panics on timeout.
pub fn wait_exit(child: &mut Child, timeout: Duration, what: &str) -> ExitStatus {
    let start = Instant::now();
    loop {
        match child.try_wait().expect("try_wait failed") {
            Some(status) => return status,
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    panic!("timed out waiting for {what}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn have_zsh() -> bool {
    Command::new("zsh")
        .arg("-c")
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
