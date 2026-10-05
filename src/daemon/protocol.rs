use serde::{Deserialize, Serialize};

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
