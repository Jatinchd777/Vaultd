use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub cipher: String,
    pub kdf: KdfConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfConfig {
    pub algorithm: String,
    pub salt: String,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
}
