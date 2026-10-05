use std::fs;
use std::path::Path;

pub const VAULT_DIR: &str = ".vaultd";
pub const MANIFEST_FILE: &str = "manifest";
pub const VAULT_FILE: &str = "vault";

pub fn create_vault_directory() -> anyhow::Result<()> {
    let path = Path::new(VAULT_DIR);

    if path.exists() {
        anyhow::bail!("vault already exists at {}", path.display());
    }

    fs::create_dir(path)?;
    Ok(())
}

pub fn write_manifest(contents: &[u8]) -> anyhow::Result<()> {
    fs::write(Path::new(VAULT_DIR).join(MANIFEST_FILE), contents)?;
    Ok(())
}

pub fn write_vault(contents: &[u8]) -> anyhow::Result<()> {
    fs::write(Path::new(VAULT_DIR).join(VAULT_FILE), contents)?;
    Ok(())
}

pub fn read_manifest() -> anyhow::Result<Vec<u8>> {
    Ok(fs::read(Path::new(VAULT_DIR).join(MANIFEST_FILE))?)
}

pub fn read_vault() -> anyhow::Result<Vec<u8>> {
    Ok(fs::read(Path::new(VAULT_DIR).join(VAULT_FILE))?)
}
