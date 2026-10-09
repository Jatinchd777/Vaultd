use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
        let candidate = dir.join(VAULT_DIR);
        // Never treat a symlinked `.vaultd` as a project: a planted link
        // in a subdirectory must not hijack resolution to an
        // attacker-controlled directory. Skip it and keep walking up.
        if candidate.is_dir()
            && fs::symlink_metadata(&candidate)
                .map(|m| !m.file_type().is_symlink())
                .unwrap_or(false)
        {
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

    // Use symlink_metadata (not `exists`, which follows links) so a
    // planted symlink — including a dangling one — is never replaced
    // with a real directory and never followed.
    if fs::symlink_metadata(path).is_ok() {
        anyhow::bail!("vault already exists at {}", path.display());
    }

    // mode(0o700) is masked by the umask at mkdir time, so the result
    // can only be 0o700 or more restrictive — never more permissive.
    // The explicit chmod below then restores exactly 0o700 when the
    // umask was overly restrictive.
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Refuse to follow a symlink at `path`. Prevents a planted
/// `.vaultd`, `manifest`, or `vault` symlink from redirecting reads or
/// — worse — writes to an arbitrary file.
fn reject_symlink(path: &Path) -> anyhow::Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        anyhow::bail!(
            "refusing to follow symlink at {}",
            path.display()
        );
    }
    Ok(())
}

/// Tighten permissions on the vault directory and its files if they
/// exist. Best-effort: used after reads to repair `0644`/`0755` modes
/// produced by `git clone` (git does not preserve `0600`/`0700`).
fn harden_existing_permissions() {
    if let Ok(dir) = vault_dir()
        && reject_symlink(&dir).is_ok()
        && dir.exists()
    {
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        for file in [MANIFEST_FILE, VAULT_FILE] {
            let p = dir.join(file);
            if reject_symlink(&p).is_ok() && p.exists() {
                let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o600));
            }
        }
    }
}

fn write_secure_file(path: PathBuf, contents: &[u8]) -> anyhow::Result<()> {
    // The parent is always the vault dir: make sure it is not a symlink
    // and that it is owner-only before placing secrets inside it.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        reject_symlink(parent)?;
        if parent.exists() {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }

    // Never overwrite a symlink: that would write ciphertext to the
    // link target.
    reject_symlink(&path)?;

    // mode(0o600) can only be narrowed by the umask, never widened, so
    // a fresh file is never group/other-readable even under umask 022.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts.mode(0o600);
    let mut file = opts.open(&path)?;
    file.write_all(contents)?;
    file.flush()?;
    // OpenOptions `mode` only applies at creation; an existing 0644
    // file (e.g. from git) stays 0644 unless we chmod it.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub fn write_manifest(contents: &[u8]) -> anyhow::Result<()> {
    write_secure_file(manifest_path()?, contents)
}

pub fn write_vault(contents: &[u8]) -> anyhow::Result<()> {
    write_secure_file(vault_path()?, contents)
}

pub fn read_manifest() -> anyhow::Result<Vec<u8>> {
    let path = manifest_path()?;
    // Reject both a symlinked file and a symlinked `.vaultd` dir so reads
    // never follow a planted link outside the project.
    if let Some(parent) = path.parent() {
        reject_symlink(parent)?;
    }
    reject_symlink(&path)?;
    let data = fs::read(&path)?;
    harden_existing_permissions();
    Ok(data)
}

pub fn read_vault() -> anyhow::Result<Vec<u8>> {
    let path = vault_path()?;
    if let Some(parent) = path.parent() {
        reject_symlink(parent)?;
    }
    reject_symlink(&path)?;
    let data = fs::read(&path)?;
    harden_existing_permissions();
    Ok(data)
}
