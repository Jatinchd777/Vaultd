use std::{io::Read, os::unix::net::UnixStream};

use anyhow::Result;

use super::{
    protocol::{Request, Response},
    server,
};

fn request(request: Request) -> Result<Response> {
    let socket = server::socket_path()?;
    let mut stream = UnixStream::connect(&socket)
        .map_err(|_| anyhow::anyhow!("vaultd daemon is not running"))?;

    serde_json::to_writer(&mut stream, &request)?;

    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response_bytes = Vec::new();

    stream.read_to_end(&mut response_bytes)?;

    Ok(serde_json::from_slice(&response_bytes)?)
}

pub fn list() -> Result<Vec<String>> {
    match request(Request::List)? {
        Response::CredentialNames(names) => Ok(names),

        Response::Error(error) => anyhow::bail!("{error}"),

        _ => anyhow::bail!("unexpected response from vaultd"),
    }
}

pub fn get(name: String) -> Result<String> {
    match request(Request::Get { name })? {
        Response::Credential { value, .. } => Ok(value),

        Response::Error(error) => anyhow::bail!("{error}"),

        _ => anyhow::bail!("unexpected response from vaultd"),
    }
}

pub fn add(name: String, value: String) -> Result<()> {
    match request(Request::Add { name, value })? {
        Response::Success => Ok(()),

        Response::Error(error) => anyhow::bail!("{error}"),

        _ => anyhow::bail!("unexpected response from vaultd"),
    }
}

pub fn set(name: String, value: String) -> Result<()> {
    match request(Request::Set { name, value })? {
        Response::Success => Ok(()),

        Response::Error(error) => anyhow::bail!("{error}"),

        _ => anyhow::bail!("unexpected response from vaultd"),
    }
}

pub fn remove(name: String) -> Result<()> {
    match request(Request::Remove { name })? {
        Response::Success => Ok(()),

        Response::Error(error) => anyhow::bail!("{error}"),

        _ => anyhow::bail!("unexpected response from vaultd"),
    }
}

pub fn environment() -> Result<Vec<(String, String)>> {
    match request(Request::Environment)? {
        Response::Environment(environment) => Ok(environment),

        Response::Error(error) => anyhow::bail!("{error}"),

        _ => anyhow::bail!("unexpected response from vaultd"),
    }
}

pub fn lock() -> Result<()> {
    match request(Request::Lock)? {
        Response::Locked => Ok(()),

        Response::Error(error) => anyhow::bail!("{error}"),

        _ => anyhow::bail!("unexpected response from vaultd"),
    }
}
