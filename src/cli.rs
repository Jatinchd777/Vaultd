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

    /// Locks the vault from accessing it
    Lock,

    /// Get the value of the env variable
    Get {
        /// Name of the env variable
        name: String,
    },

    /// Set the value of env variable
    Set {
        /// Name of the env variable
        name: String,
        /// new updating Value
        value: Option<String>,
    },

    Add {
        /// Credential name.
        name: String,

        /// Credential value. If omitted, prompt securely.
        value: Option<String>,
    },

    /// Removes the env variable
    Remove {
        /// Name of the env variable
        name: String,
    },

    /// List credentials stored in the vault.
    List,

    #[command(name = "__env", hide = true)]
    Env,
}
