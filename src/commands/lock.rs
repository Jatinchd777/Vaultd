use std::time::{Duration, Instant};

use anyhow::Result;

use crate::daemon::{client, server};

/// Upper bound for the daemon to finish teardown after it answered
/// `Locked`. Teardown is one poll quantum plus file removal, so this
/// is generous; expiry still returns success (the daemon owns the
/// rest, including the shell `SIGKILL` backstop).
const LOCK_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(2);

pub fn run() -> Result<()> {
    client::lock()?;

    println!("✓ Vault locked");

    // Don't exit before the socket is actually gone. A vault shell
    // renders its next prompt (and its auto-lock hook) when this
    // client exits — exiting first would let the hook observe a
    // still-present socket and miss the lock entirely.
    if let Ok(socket) = server::socket_path() {
        let start = Instant::now();
        while socket.exists() && start.elapsed() < LOCK_TEARDOWN_TIMEOUT {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    Ok(())
}
