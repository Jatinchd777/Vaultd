use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Credential {
    pub name: String,
    pub value: String,
}
