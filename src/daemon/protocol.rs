use serde::{Deserialize, Serialize};

/// Upper bound for a single IPC message in either direction.
/// Caps memory use when reading from a peer that may be malicious
/// (any process running as our UID can connect).
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    Ping,

    List,

    Get { name: String },

    Add { name: String, value: String },

    Set { name: String, value: String },

    Remove { name: String },

    Environment,

    Lock,
}

/// Wire envelope: every request must present the per-session token.
/// The token is a 64-char hex encoding of 32 random bytes generated at
/// `unlock` time. It is never derived from anything guessable.
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub token: String,
    pub request: Request,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Pong,

    CredentialNames(Vec<String>),

    Credential { name: String, value: String },

    Environment(Vec<(String, String)>),

    Success,

    Locked,

    Error(String),
}
