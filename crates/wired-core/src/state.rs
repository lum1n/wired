//! On-disk state: node keys, the anchor's network secret and name registry.

use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use iroh::SecretKey;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    invite::NetworkSecret,
    proto::{Cert, Snapshot},
};

/// `$XDG_CONFIG_HOME/wired`, falling back to `~/.config/wired`.
pub fn default_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("XDG_CONFIG_HOME").filter(|d| !d.is_empty()) {
        return PathBuf::from(d).join("wired");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".config").join("wired")
}

/// Writes `data` to `path` atomically, readable only by the owner.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(&tmp).with_context(|| format!("write {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn load_or_create_32(path: &Path, create: impl FnOnce() -> [u8; 32]) -> Result<[u8; 32]> {
    match fs::read(path) {
        Ok(b) => b.as_slice().try_into().with_context(|| format!("{} is not a 32-byte key", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let b = create();
            write_private(path, &b)?;
            Ok(b)
        }
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

pub fn load_or_create_key(dir: &Path, name: &str) -> Result<SecretKey> {
    let b = load_or_create_32(&dir.join(format!("{name}.key")), || SecretKey::generate().to_bytes())?;
    Ok(SecretKey::from_bytes(&b))
}

/// Reads a postcard file; `None` if it does not exist.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(postcard::from_bytes(&b).with_context(|| format!("parse {}", path.display()))?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_private(path, &postcard::to_stdvec(value)?)
}

pub fn anchor_path(dir: &Path) -> PathBuf {
    dir.join("anchor").join("state")
}

pub fn member_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.state"))
}

pub fn admin_socket(dir: &Path) -> PathBuf {
    dir.join("anchor").join("admin.sock")
}

fn invite_path(dir: &Path) -> PathBuf {
    dir.join("anchor").join("invite")
}

/// Keeps the current invite so `wired invite` works without a running anchor.
pub fn save_invite(dir: &Path, invite: &str) -> Result<()> {
    write_private(&invite_path(dir), invite.as_bytes())
}

pub fn load_invite(dir: &Path) -> Result<String> {
    let path = invite_path(dir);
    fs::read_to_string(&path).with_context(|| format!("read {} (has an anchor run here?)", path.display()))
}

/// Everything an anchor needs to restart where it left off.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorDisk {
    pub network_id: [u8; 16],
    pub root: [u8; 32],
    /// Current join secret (the root's; replicas learn it from snapshots).
    pub secret: NetworkSecret,
    pub snapshot: Snapshot,
    /// Root only: replica keys allowed to become anchors.
    pub approved: BTreeSet<[u8; 32]>,
    /// Replica only: its anchor certificate from the root.
    pub cert: Option<Cert>,
}

/// A member's cache, so it can start while no anchor is reachable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberDisk {
    pub network_id: [u8; 16],
    pub root: [u8; 32],
    pub cert: Cert,
    pub snapshot: Snapshot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_stable_and_private() {
        let dir = std::env::temp_dir().join(format!("wired-state-{}", rand::random::<u64>()));
        let a = load_or_create_key(&dir, "n").unwrap();
        let b = load_or_create_key(&dir, "n").unwrap();
        assert_eq!(a.public(), b.public());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.join("n.key")).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::remove_dir_all(dir).ok();
    }
}
