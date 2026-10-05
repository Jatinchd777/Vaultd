//! vaultd's integration suite, run as a single test target.
//!
//! Tests are split by area but share one harness (`common`), driving the
//! real CLI binary in isolated temp directories.

mod cli;
mod common;
mod crypto;
mod vault;
