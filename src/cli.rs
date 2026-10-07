use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "vaultd",
    version,
    about = "Secure project-local credential management"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize a new vault in the current directory.
    Init,

    /// Unlock the vault and verify the master password.
    Unlock,

    /// Lock the vault.
    Lock,

    /// Get the value of a credential.
    Get {
        /// Name of the credential.
        name: String,
    },

    /// Update the value of a credential.
    Set {
        /// Name of the credential.
        name: String,
        /// New value. If omitted, prompt securely.
        value: Option<String>,
    },

    /// Store a new credential.
    Add {
        /// Credential name.
        name: String,

        /// Credential value. If omitted, prompt securely.
        value: Option<String>,
    },

    /// Remove a credential.
    Remove {
        /// Name of the credential.
        name: String,
    },

    /// List credentials stored in the vault.
    List,

    #[command(name = "__env", hide = true)]
    Env,
}
