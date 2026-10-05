use anyhow::Result;

use crate::cli::Command;

pub mod add;
pub mod env;
pub mod get;
pub mod init;
pub mod list;
pub mod lock;
pub mod remove;
pub mod set;
pub mod unlock;

pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Init => init::run(),
        Command::Unlock => unlock::run(),
        Command::Lock => lock::run(),
        Command::Remove { name } => remove::run(name),
        Command::Set { name, value } => set::run(name, value),
        Command::Get { name } => get::run(name),
        Command::Add { name, value } => add::run(name, value),
        Command::List => list::run(),
        Command::Env => env::run(),
    }
}
