use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        io::{AsRawFd, RawFd},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Result;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use super::protocol::{AuthenticatedRequest, MAX_MESSAGE_BYTES, Request, Response};
use crate::storage::filesystem;
use crate::vault::store::Vault;

pub const SOCKET_ENV: &str = "VAULTD_SOCKET";
pub const TOKEN_ENV: &str = "VAULTD_TOKEN";
pub const TOKEN_BYTES: usize = 32;

/// Bound each connection: slow or huge peers must not stall the daemon.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Cap concurrent workers; beyond this the daemon replies `busy`.
const MAX_WORKERS: usize = 16;
/// Supervisor poll quantum: keeps `Lock` shutdown and thread reaping
/// responsive without a wake pipe.
const POLL_TIMEOUT_MS: i32 = 100;
/// Grace after `Lock` before the `SIGKILL` backstop: a vault shell
/// sitting at its prompt exits cleanly by itself via its auto-lock
/// hook (no `killed` report). The backstop is the zeroize guarantee
/// for shells that never reach a prompt.
const LOCK_CLEAN_EXIT_GRACE: Duration = Duration::from_millis(500);

/// Shell spawned for the vault session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    pub fn binary(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
        }
    }

    /// `true` for POSIX-style shells sharing `export` syntax.
    pub fn is_posix(self) -> bool {
        !matches!(self, Shell::Fish)
    }
}

/// Parse a shell name or path (`bash`, `/bin/bash`) into a supported shell.
pub fn parse_shell_name(s: &str) -> Result<Shell> {
    let base = s.rsplit('/').next().unwrap_or(s).trim();
    match base {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        other => {
            anyhow::bail!("unsupported shell '{other}': set VAULTD_SHELL to bash, zsh, or fish")
        }
    }
}

/// Pure selection logic, kept separate from env reads so it can be unit
/// tested without mutating process globals.
pub fn select_shell(
    override_name: Option<&str>,
    bash_marker: bool,
    zsh_marker: bool,
    fish_marker: bool,
    parent_comm: Option<&str>,
    shell_env: Option<&str>,
) -> Result<Shell> {
    if let Some(name) = override_name
        && !name.trim().is_empty()
    {
        return parse_shell_name(name);
    }
    // Invoking-shell markers beat parent comm and $SHELL. When several
    // are set (nested shells), prefer the innermost known marker in
    // fish, zsh, bash order.
    if fish_marker {
        return Ok(Shell::Fish);
    }
    match (bash_marker, zsh_marker) {
        (true, false) => return Ok(Shell::Bash),
        (false, true) => return Ok(Shell::Zsh),
        _ => {}
    }
    if let Some(comm) = parent_comm {
        let comm = comm.trim();
        if comm.contains("fish") {
            return Ok(Shell::Fish);
        }
        if comm.contains("bash") {
            return Ok(Shell::Bash);
        }
        if comm.contains("zsh") {
            return Ok(Shell::Zsh);
        }
    }
    if let Some(shell) = shell_env
        && !shell.trim().is_empty()
    {
        return parse_shell_name(shell);
    }
    Ok(Shell::Zsh)
}

fn parent_comm_name() -> Option<String> {
    let ppid = unsafe { libc::getppid() };
    let path = format!("/proc/{ppid}/comm");
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

/// Detect which shell invoked `unlock`: explicit `VAULTD_SHELL` wins,
/// then invoking-shell markers (`BASH_VERSION`/`ZSH_VERSION`/`FISH_VERSION`),
/// then the parent process name, then `$SHELL`. Falls back to `zsh`.
pub fn detect_shell() -> Result<Shell> {
    let override_name = std::env::var("VAULTD_SHELL").ok();
    let bash_marker = std::env::var_os("BASH_VERSION")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let zsh_marker = std::env::var_os("ZSH_VERSION")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let fish_marker = std::env::var_os("FISH_VERSION")
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    let parent_comm = parent_comm_name();
    let shell_env = std::env::var("SHELL").ok();
    select_shell(
        override_name.as_deref(),
        bash_marker,
        zsh_marker,
        fish_marker,
        parent_comm.as_deref(),
        shell_env.as_deref(),
    )
}

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
    let parent_canon = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    if parent_canon != runtime_canon {
        anyhow::bail!(
            "untrusted VAULTD_SOCKET: must live inside {}",
            runtime_canon.display()
        );
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
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
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
    let raw =
        fs::read_to_string(&path).map_err(|_| anyhow::anyhow!("vaultd daemon is not running"))?;
    decode_token_hex(&raw).map_err(|_| anyhow::anyhow!("vaultd daemon is not running"))
}

/// Shell subtree identity: the vault shell pid plus its starttime.
/// `exec` keeps both, so the pre-`exec` unlock pid identifies the
/// post-`exec` shell. Starttime pins the exact process, no pid-reuse race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellIdentity {
    pub pid: i32,
    pub starttime: u64,
}

/// Credentials of the peer on a Unix socket via `SO_PEERCRED`.
fn peer_cred(stream: &UnixStream) -> Result<libc::ucred> {
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
        anyhow::bail!(
            "failed to query peer credentials: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(cred)
}

fn check_peer_uid(stream: &UnixStream) -> Result<libc::ucred> {
    let cred = peer_cred(stream)?;
    let own = unsafe { libc::getuid() };
    if cred.uid != own {
        anyhow::bail!("vaultd daemon authentication failed");
    }
    Ok(cred)
}

/// Parse `/proc/<pid>/stat`: returns `(ppid, starttime)`.
/// `comm` may contain spaces/parens, so split after the last `)`.
fn proc_ppid_and_starttime(pid: i32) -> Result<(i32, u64)> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| anyhow::anyhow!("vaultd daemon authentication failed"))?;
    let rparen = text
        .rfind(')')
        .ok_or_else(|| anyhow::anyhow!("vaultd daemon authentication failed"))?;
    let after = text[rparen + 2..].split_whitespace().collect::<Vec<_>>();
    // after[0]=state(3), after[1]=ppid(4), ..., after[19]=starttime(22).
    if after.len() <= 19 {
        anyhow::bail!("vaultd daemon authentication failed");
    }
    let ppid: i32 = after[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("vaultd daemon authentication failed"))?;
    let starttime: u64 = after[19]
        .parse()
        .map_err(|_| anyhow::anyhow!("vaultd daemon authentication failed"))?;
    Ok((ppid, starttime))
}

fn proc_starttime(pid: i32) -> Result<u64> {
    Ok(proc_ppid_and_starttime(pid)?.1)
}

/// Identity of the current process for subtree checks (exposed for tests).
pub fn current_process_identity() -> Result<ShellIdentity> {
    let pid = unsafe { libc::getpid() };
    Ok(ShellIdentity {
        pid,
        starttime: proc_starttime(pid)?,
    })
}

/// `true` when `peer` is the shell itself or a descendant.
/// Walks `ppid` up to `init`; the final shell-pid match also requires
/// starttime equality so a recycled pid never passes. Fail closed.
pub fn is_in_shell_subtree(peer_pid: i32, shell: ShellIdentity) -> bool {
    if peer_pid <= 0 || shell.pid <= 0 {
        return false;
    }
    // Fast path: peer is the shell itself.
    if peer_pid == shell.pid {
        return proc_starttime(peer_pid).is_ok_and(|t| t == shell.starttime);
    }
    // Verify the shell root is still the same process we started.
    if proc_starttime(shell.pid).is_ok_and(|t| t != shell.starttime) {
        return false;
    }
    let mut current = peer_pid;
    for _ in 0..64 {
        let ppid = match proc_ppid_and_starttime(current) {
            Ok((ppid, _)) => ppid,
            Err(_) => return false,
        };
        if ppid == shell.pid {
            return proc_starttime(shell.pid).is_ok_and(|t| t == shell.starttime);
        }
        if ppid <= 1 {
            return false;
        }
        // Cycle guard: ppid must make progress toward init.
        if ppid == current {
            return false;
        }
        current = ppid;
    }
    false
}

fn check_shell_subtree(stream: &UnixStream, shell: &ShellIdentity, peer_pid: i32) -> Result<()> {
    let _ = stream;
    if !is_in_shell_subtree(peer_pid, *shell) {
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
            if let Ok(meta) = fs::symlink_metadata(&path)
                && !meta.file_type().is_symlink()
            {
                let _ = fs::remove_file(&path);
                // Best-effort stale token cleanup alongside the socket.
                let _ = fs::remove_file(token_path_for_socket(&path));
            }
            Ok(false)
        }
    }
}

pub fn spawn_daemon_and_shell(vault: Vault, socket_path: PathBuf) -> Result<()> {
    // Validate the shell before forking so an unsupported value fails
    // fast without starting a daemon that would immediately shut down.
    let shell = detect_shell()?;
    let session_token = generate_session_token()?;
    // The unlock pid becomes the vault shell pid after `exec`
    // (same pid + starttime), so capture it now for subtree auth.
    let shell_pid = unsafe { libc::getpid() };
    let shell_starttime =
        proc_starttime(shell_pid).map_err(|_| anyhow::anyhow!("failed to query shell identity"))?;
    let shell_identity = ShellIdentity {
        pid: shell_pid,
        starttime: shell_starttime,
    };
    let mut pipe_fds = [0 as libc::c_int; 2];

    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        anyhow::bail!("failed to create daemon ready pipe");
    }

    unsafe {
        libc::fcntl(pipe_fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(pipe_fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
    }

    let parent_pid = shell_identity.pid;
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
        let result = daemon_main(
            vault,
            pidfd,
            pipe_fds[1],
            &path,
            &session_token,
            shell_identity,
        );

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

    // zsh functions cannot survive the `exec` into the final shell, so
    // the auto-lock hook travels via a generated `ZDOTDIR` init. A
    // write failure only loses the clean exit (the daemon `SIGKILL`
    // backstop still guarantees the lock), so warn and continue.
    let zdotdir = if shell == Shell::Zsh {
        match hook_dir_for_socket(&socket_path) {
            Some(dir) => match write_zsh_hook(&dir, &user_zsh_rc()) {
                Ok(()) => Some(dir),
                Err(error) => {
                    eprintln!("warning: vaultd zsh hook unavailable: {error:#}");
                    None
                }
            },
            None => None,
        }
    } else {
        None
    };

    exec_vault_shell(shell, &socket_path, &session_token, zdotdir)
}

fn daemon_main(
    vault: Vault,
    pidfd: RawFd,
    ready_fd: RawFd,
    path: &Path,
    expected_token: &[u8; TOKEN_BYTES],
    shell_identity: ShellIdentity,
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

    let vault = Arc::new(Mutex::new(vault));
    let reason = match serve_loop(
        &listener,
        Arc::clone(&vault),
        pidfd,
        expected_token,
        shell_identity,
    ) {
        Ok(reason) => reason,
        Err(error) => {
            drop(listener);
            drop(vault);
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(&token_path);
            if let Some(hook_dir) = hook_dir_for_socket(path) {
                let _ = fs::remove_dir_all(hook_dir);
            }
            // Daemon is going away unexpectedly: don't leave the vault
            // shell orphaned with secrets in its environment.
            terminate_vault_shell(pidfd);
            return Err(error);
        }
    };

    drop(listener);
    drop(vault);
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(&token_path);
    if let Some(hook_dir) = hook_dir_for_socket(path) {
        let _ = fs::remove_dir_all(hook_dir);
    }

    if reason == ShutdownReason::LockRequested {
        // `Lock` stopped the daemon but the vault shell (watched via
        // pidfd) would otherwise survive with secrets still exported.
        // A shell at its prompt exits cleanly by itself via its
        // auto-lock hook once the socket is gone; the `SIGKILL`
        // backstop below is the zeroize guarantee for the rest.
        std::thread::sleep(LOCK_CLEAN_EXIT_GRACE);
        if !pidfd_has_exited(pidfd) {
            terminate_vault_shell(pidfd);
        }
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum ShutdownReason {
    LockRequested,
    ShellExited,
}

fn serve_loop(
    listener: &UnixListener,
    vault: Arc<Mutex<Vault>>,
    pidfd: RawFd,
    expected_token: &[u8; TOKEN_BYTES],
    shell_identity: ShellIdentity,
) -> Result<ShutdownReason> {
    let expected_token = *expected_token;
    let lock_requested = Arc::new(AtomicBool::new(false));
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let listener_fd = listener.as_raw_fd();

    loop {
        // Reap finished workers so the vec stays bounded.
        workers.retain(|h| !h.is_finished());

        if lock_requested.load(Ordering::SeqCst) {
            for h in std::mem::take(&mut workers) {
                let _ = h.join();
            }
            return Ok(ShutdownReason::LockRequested);
        }

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

        let ret =
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, POLL_TIMEOUT_MS) };

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
            for h in std::mem::take(&mut workers) {
                let _ = h.join();
            }
            return Ok(ShutdownReason::ShellExited);
        }

        if fds[1].revents & libc::POLLNVAL != 0 {
            for h in std::mem::take(&mut workers) {
                let _ = h.join();
            }
            return Ok(ShutdownReason::ShellExited);
        }

        if fds[0].revents & libc::POLLNVAL != 0 {
            anyhow::bail!("daemon socket poll error");
        }

        if ret == 0 {
            continue;
        }

        if fds[0].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0 {
            match listener.accept() {
                Ok((stream, _)) => {
                    workers.retain(|h| !h.is_finished());
                    if workers.len() >= MAX_WORKERS {
                        reject_busy(stream);
                        continue;
                    }
                    let vault = Arc::clone(&vault);
                    let flag = Arc::clone(&lock_requested);
                    workers.push(std::thread::spawn(move || {
                        let _ = handle_connection(
                            stream,
                            vault,
                            &expected_token,
                            &flag,
                            shell_identity,
                        );
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {}
            }
        }
    }
}

/// Immediate `busy` reply when all worker slots are taken.
/// Never blocks the supervisor loop.
fn reject_busy(stream: UnixStream) {
    let mut stream = stream;
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let _ = serde_json::to_writer(
        &mut stream,
        &Response::Error("vaultd daemon is busy".to_string()),
    );
    let _ = stream.shutdown(std::net::Shutdown::Write);
}

fn read_envelope_capped(stream: &mut UnixStream) -> Result<AuthenticatedRequest> {
    let mut buf = Vec::new();
    let mut limited = stream.take((MAX_MESSAGE_BYTES + 1) as u64);
    limited.read_to_end(&mut buf)?;
    if buf.len() > MAX_MESSAGE_BYTES {
        anyhow::bail!("vaultd request is too large");
    }
    Ok(serde_json::from_slice(&buf)?)
}

fn handle_connection(
    stream: UnixStream,
    vault: Arc<Mutex<Vault>>,
    expected_token: &[u8; TOKEN_BYTES],
    lock_requested: &AtomicBool,
    shell_identity: ShellIdentity,
) -> Result<bool> {
    let mut stream = stream;
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));

    // Defense in depth: filesystem perms already restrict to our UID,
    // but verify explicitly so a misconfigured umask never opens the vault.
    let peer_pid = match check_peer_uid(&stream) {
        Ok(cred) => cred.pid,
        Err(_) => {
            let _ = serde_json::to_writer(
                &mut stream,
                &Response::Error("vaultd daemon authentication failed".to_string()),
            );
            return Ok(false);
        }
    };

    // Drain the request first so early rejection doesn't RST the peer
    // with unread bytes (outsider would see reset instead of auth failed).
    let envelope = match read_envelope_capped(&mut stream) {
        Ok(env) => env,
        Err(_) => {
            let _ = serde_json::to_writer(
                &mut stream,
                &Response::Error("vaultd daemon authentication failed".to_string()),
            );
            return Ok(false);
        }
    };
    // Then bind to the vault-shell subtree: only the shell itself and its
    // descendants may use the daemon, even with a valid token.
    if check_shell_subtree(&stream, &shell_identity, peer_pid).is_err() {
        let _ = serde_json::to_writer(
            &mut stream,
            &Response::Error("vaultd daemon authentication failed".to_string()),
        );
        return Ok(false);
    }

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

    // Hold the vault lock only while computing the response, never
    // across network I/O.
    let response = {
        let mut vault = vault
            .lock()
            .map_err(|_| anyhow::anyhow!("vaultd daemon is busy"))?;
        match request {
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
        }
    };

    serde_json::to_writer(&mut stream, &response)?;

    stream.shutdown(std::net::Shutdown::Write)?;

    if should_stop {
        lock_requested.store(true, Ordering::SeqCst);
    }

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

/// Best-effort signal to the vault shell via its pidfd.
/// Uses the raw `pidfd_send_signal` syscall so the exact shell watched
/// since `fork` is signaled; no PID-reuse race. Errors (notably `ESRCH`
/// when the shell already exited) are ignored by design.
fn pidfd_send_signal(pidfd: RawFd, sig: libc::c_int) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal as libc::c_long,
            pidfd as libc::c_int,
            sig as libc::c_int,
            std::ptr::null::<libc::c_void>(),
            0 as libc::c_int,
        );
    }
}

/// Non-blocking check: `true` once the pidfd's process has exited.
fn pidfd_has_exited(pidfd: RawFd) -> bool {
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
    ret > 0 && (pfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP) != 0)
}

/// End the vault shell after `Lock` (or an unexpected daemon failure).
/// Lock is zeroize: the shell holds secrets in its environment, so it
/// dies via `SIGKILL` — no traps, no history save. Best-effort: an
/// already-exited shell (`ESRCH`) is ignored.
fn terminate_vault_shell(pidfd: RawFd) {
    pidfd_send_signal(pidfd, libc::SIGKILL);
}

/// Directory holding the generated zsh init for a vault session,
/// derived from the socket path so the unlock parent (writer) and the
/// daemon (cleaner) agree without extra plumbing. Holds no secrets,
/// only the auto-lock hook.
pub fn hook_dir_for_socket(socket_path: &Path) -> Option<PathBuf> {
    let name = socket_path.file_name()?.to_string_lossy();
    let hash = name.strip_prefix("vaultd-")?.strip_suffix(".sock")?;
    let parent = socket_path.parent().filter(|p| !p.as_os_str().is_empty())?;
    Some(parent.join(format!("zsh-{hash}")))
}

/// Write the zsh init for a vault session: user rc first, then the
/// auto-lock hook that exits the shell at the next prompt once the
/// daemon socket is gone. zsh functions cannot survive the `exec`
/// into the final shell, so the hook travels via `ZDOTDIR`, not env.
fn write_zsh_hook(dir: &Path, user_rc: &str) -> Result<()> {
    fs::create_dir_all(dir)?;
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    let content = format!(
        "# vaultd vault-shell init (auto-generated, holds no secrets).\n\
         if [ -f {user_rc} ]; then\n\
         \x20 source {user_rc}\n\
         fi\n\
         _vaultd_autolock() {{\n\
         \x20 [ -S \"${{VAULTD_SOCKET:-}}\" ] || exit 0\n\
         }}\n\
         typeset -ga precmd_functions\n\
         if (( ! ${{precmd_functions[(I)_vaultd_autolock]}} )); then\n\
         \x20 precmd_functions+=(_vaultd_autolock)\n\
         fi\n"
    );
    fs::write(dir.join(".zshrc"), content)?;
    let _ = fs::set_permissions(dir.join(".zshrc"), fs::Permissions::from_mode(0o600));
    Ok(())
}

/// Single-quote a path for embedding in the generated zsh init.
fn zsh_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The user's own zsh rc, resolved before `ZDOTDIR` is overridden:
/// `$ZDOTDIR/.zshrc` when set, else `$HOME/.zshrc`.
fn user_zsh_rc() -> String {
    if let Ok(dir) = std::env::var("ZDOTDIR")
        && !dir.trim().is_empty()
    {
        return zsh_single_quote(&format!("{dir}/.zshrc"));
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.trim().is_empty()
    {
        return zsh_single_quote(&format!("{home}/.zshrc"));
    }
    "'~/.zshrc'".to_string()
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

fn exec_vault_shell(
    shell: Shell,
    socket_path: &Path,
    session_token: &[u8; TOKEN_BYTES],
    zdotdir: Option<PathBuf>,
) -> Result<()> {
    use std::io::Write;
    use std::os::unix::process::CommandExt;

    let binary = shell.binary();
    println!("Vault unlocked - entering vault shell ({binary}, exit to auto-lock)");

    let _ = std::io::stdout().flush();

    let vaultd_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "vaultd".to_string());

    if shell == Shell::Fish {
        // Capital `-C` runs init commands then stays interactive;
        // lowercase `-c` would exit at once and the daemon would
        // auto-lock via its pidfd watch.
        let init = format!(
            "{} __env --shell fish | source",
            shell_single_quote(&vaultd_exe)
        );
        let err = std::process::Command::new("fish")
            .arg("-i")
            .arg("-C")
            .arg(init)
            .env(SOCKET_ENV, socket_path)
            .env(TOKEN_ENV, encode_token_hex(session_token))
            .exec();

        anyhow::bail!("failed to spawn vault shell (fish): {err}")
    }

    let vaultd_quoted = shell_single_quote(&vaultd_exe);
    let script = format!(
        "eval \"$({vaultd_quoted} __env --shell {})\"; exec {binary} -i",
        binary
    );

    let mut cmd = std::process::Command::new(binary);
    cmd.arg("-i")
        .arg("-c")
        .arg(script)
        .env(SOCKET_ENV, socket_path)
        .env(TOKEN_ENV, encode_token_hex(session_token));
    if let Some(dir) = zdotdir {
        cmd.env("ZDOTDIR", dir);
    }
    let err = cmd.exec();

    anyhow::bail!("failed to spawn vault shell ({binary}): {err}")
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
