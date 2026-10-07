use std::fs;
use std::path::{Path, PathBuf};

pub const VAULT_DIR: &str = ".vaultd";
pub const MANIFEST_FILE: &str = "manifest";
pub const VAULT_FILE: &str = "vault";

pub fn find_project_root_from(start: &Path) -> anyhow::Result<PathBuf> {
    let mut dir: &Path = if start.is_file() {
        start.parent().ok_or_else(|| {
            anyhow::anyhow!("no vault found: searched up from {}", start.display())
        })?
    } else {
        start
    };

    loop {
        if dir.join(VAULT_DIR).is_dir() {
            return Ok(fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf()));
        }

        match dir.parent() {
            Some(parent) => dir = parent,
            None => anyhow::bail!(
                "no vault found: no {} in current directory or parents",
                VAULT_DIR
            ),
        }
    }
}

pub fn find_project_root() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    find_project_root_from(&cwd)
}

pub fn vault_dir() -> anyhow::Result<PathBuf> {
    Ok(find_project_root()?.join(VAULT_DIR))
}

pub fn manifest_path() -> anyhow::Result<PathBuf> {
    Ok(vault_dir()?.join(MANIFEST_FILE))
}

pub fn vault_path() -> anyhow::Result<PathBuf> {
    Ok(vault_dir()?.join(VAULT_FILE))
}

pub fn create_vault_directory() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;

    if find_project_root_from(&cwd).is_ok() {
        let existing = find_project_root_from(&cwd)?;
        anyhow::bail!("vault already exists at {}", existing.display());
    }

    let path = Path::new(VAULT_DIR);

    if path.exists() {
        anyhow::bail!("vault already exists at {}", path.display());
    }

    fs::create_dir(path)?;
    Ok(())
}

pub fn write_manifest(contents: &[u8]) -> anyhow::Result<()> {
    fs::write(manifest_path()?, contents)?;
    Ok(())
}

pub fn write_vault(contents: &[u8]) -> anyhow::Result<()> {
    fs::write(vault_path()?, contents)?;
    Ok(())
}

pub fn read_manifest() -> anyhow::Result<Vec<u8>> {
    Ok(fs::read(manifest_path()?)?)
}

pub fn read_vault() -> anyhow::Result<Vec<u8>> {
    Ok(fs::read(vault_path()?)?)
}
