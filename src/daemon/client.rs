use std::{io::Read, os::unix::net::UnixStream};

use anyhow::Result;

use super::{
    protocol::{AuthenticatedRequest, Request, Response},
    server,
};

fn request(body: Request) -> Result<Response> {
    let socket = server::socket_path()?;
    let token = server::load_client_token()?;
    let mut stream = UnixStream::connect(&socket)
        .map_err(|_| anyhow::anyhow!("vaultd daemon is not running"))?;

    // Verify we are talking to our own daemon before sending secrets.
    // This blocks spoofed sockets owned by another UID.
    {
        use std::os::unix::io::AsRawFd;
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
        if ret == 0 {
            let own = unsafe { libc::getuid() };
            if cred.uid != own {
                anyhow::bail!("vaultd daemon authentication failed");
            }
        }
    }

    let envelope = AuthenticatedRequest {
        token: server::encode_token_hex(&token),
        request: body,
    };
    serde_json::to_writer(&mut stream, &envelope)?;

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
