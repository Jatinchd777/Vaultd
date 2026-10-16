use std::process::ExitCode;

use anyhow::Result;

use crate::cli::Command;

pub mod add;
pub mod env;
pub mod get;
pub mod init;
pub mod list;
pub mod lock;
pub mod passwd;
pub mod remove;
pub mod run;
pub mod set;
pub mod unlock;

pub fn run(command: Command) -> Result<ExitCode> {
    match command {
        Command::Init => init::run().map(|()| ExitCode::SUCCESS),
        Command::Unlock => unlock::run().map(|()| ExitCode::SUCCESS),
        Command::Lock => lock::run().map(|()| ExitCode::SUCCESS),
        Command::Remove { name } => remove::run(name).map(|()| ExitCode::SUCCESS),
        Command::Set { name, value } => set::run(name, value).map(|()| ExitCode::SUCCESS),
        Command::Get { name } => get::run(name).map(|()| ExitCode::SUCCESS),
        Command::Add { name, value } => add::run(name, value).map(|()| ExitCode::SUCCESS),
        Command::List => list::run().map(|()| ExitCode::SUCCESS),
        Command::Passwd => passwd::run().map(|()| ExitCode::SUCCESS),
        Command::Run { command } => run::run(command),
        Command::Env { shell } => env::run(shell).map(|()| ExitCode::SUCCESS),
    }
}
