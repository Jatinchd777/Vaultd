use std::{io::Read, os::unix::net::UnixStream, time::Duration};

use anyhow::Result;

use super::{
    protocol::{AuthenticatedRequest, MAX_MESSAGE_BYTES, Request, Response},
    server,
};

const IO_TIMEOUT: Duration = Duration::from_secs(10);

fn request(body: Request) -> Result<Response> {
    let socket = server::socket_path()?;
    let token = server::load_client_token()?;
    let mut stream = UnixStream::connect(&socket)
        .map_err(|_| anyhow::anyhow!("vaultd daemon is not running"))?;
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    // Verify we are talking to our own daemon before sending secrets.
    // This blocks spoofed sockets owned by another UID. Fail closed:
    // if the peer credentials cannot be queried, refuse to proceed.
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
        if ret != 0 {
            anyhow::bail!("vaultd daemon authentication failed");
        }
        let own = unsafe { libc::getuid() };
        if cred.uid != own {
            anyhow::bail!("vaultd daemon authentication failed");
        }
    }

    let envelope = AuthenticatedRequest {
        token: server::encode_token_hex(&token),
        request: body,
    };
    serde_json::to_writer(&mut stream, &envelope)?;

    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response_bytes = Vec::new();
    let mut limited = stream.take((MAX_MESSAGE_BYTES + 1) as u64);
    limited.read_to_end(&mut response_bytes)?;
    if response_bytes.len() > MAX_MESSAGE_BYTES {
        anyhow::bail!("vaultd response is too large");
    }

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
