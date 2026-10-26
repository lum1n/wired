//! On-disk state: node keys, the anchor's network secret and name registry.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use iroh::SecretKey;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    invite::{AnchorInfo, NetworkSecret, RelayInfo},
    proto::{Cert, Snapshot},
};

/// Starts every node state file since snapshots are signed. Older files have no header.
const FORMAT: &[u8] = b"wired-state/2\n";

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

/// Reads a node state file, converting one in the format before snapshots were signed.
/// `None` if it does not exist.
fn load_state<T: DeserializeOwned, Old: DeserializeOwned + Into<T>>(path: &Path) -> Result<Option<T>> {
    let b = match fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    let parsed = match b.strip_prefix(FORMAT) {
        Some(rest) => postcard::from_bytes(rest),
        None => postcard::from_bytes::<Old>(&b).map(Into::into),
    };
    Ok(Some(parsed.with_context(|| format!("parse {}", path.display()))?))
}

fn save_state<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut data = FORMAT.to_vec();
    data.extend(postcard::to_stdvec(value)?);
    write_private(path, &data)
}

pub fn load_anchor(dir: &Path) -> Result<Option<AnchorDisk>> {
    load_state::<AnchorDisk, OldAnchorDisk>(&anchor_path(dir))
}

pub fn save_anchor(dir: &Path, disk: &AnchorDisk) -> Result<()> {
    save_state(&anchor_path(dir), disk)
}

pub fn load_member(dir: &Path, name: &str) -> Result<Option<MemberDisk>> {
    load_state::<MemberDisk, OldMemberDisk>(&member_path(dir, name))
}

pub fn save_member(dir: &Path, name: &str, disk: &MemberDisk) -> Result<()> {
    save_state(&member_path(dir, name), disk)
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

// The format before snapshots were signed. Its snapshots load unsigned.

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct OldSnapshot {
    version: u64,
    members: BTreeMap<String, [u8; 32]>,
    denied: BTreeSet<[u8; 32]>,
    anchors: Vec<AnchorInfo>,
    relays: Vec<RelayInfo>,
    secret: Option<NetworkSecret>,
}

impl From<OldSnapshot> for Snapshot {
    fn from(o: OldSnapshot) -> Self {
        let OldSnapshot { version, members, denied, anchors, relays, secret } = o;
        Snapshot { version, members, denied, anchors, relays, secret, sig: Vec::new() }
    }
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct OldAnchorDisk {
    network_id: [u8; 16],
    root: [u8; 32],
    secret: NetworkSecret,
    snapshot: OldSnapshot,
    approved: BTreeSet<[u8; 32]>,
    cert: Option<Cert>,
}

impl From<OldAnchorDisk> for AnchorDisk {
    fn from(o: OldAnchorDisk) -> Self {
        let OldAnchorDisk { network_id, root, secret, snapshot, approved, cert } = o;
        AnchorDisk { network_id, root, secret, snapshot: snapshot.into(), approved, cert }
    }
}

#[derive(Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct OldMemberDisk {
    network_id: [u8; 16],
    root: [u8; 32],
    cert: Cert,
    snapshot: OldSnapshot,
}

impl From<OldMemberDisk> for MemberDisk {
    fn from(o: OldMemberDisk) -> Self {
        let OldMemberDisk { network_id, root, cert, snapshot } = o;
        MemberDisk { network_id, root, cert, snapshot: snapshot.into() }
    }
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

    #[test]
    fn state_saved_before_snapshots_were_signed_still_loads() {
        let dir = std::env::temp_dir().join(format!("wired-state-{}", rand::random::<u64>()));
        let key = SecretKey::generate();
        let cert = crate::cert::issue(&key, None, [1; 16], key.public(), "laptop", crate::proto::Role::Member);
        let old = OldMemberDisk {
            network_id: [1; 16],
            root: *key.public().as_bytes(),
            cert: cert.clone(),
            snapshot: OldSnapshot {
                version: 7,
                members: [("laptop".to_string(), *key.public().as_bytes())].into(),
                denied: [[2; 32]].into(),
                anchors: Vec::new(),
                relays: Vec::new(),
                secret: None,
            },
        };
        write_private(&member_path(&dir, "laptop"), &postcard::to_stdvec(&old).unwrap()).unwrap();
        let disk = load_member(&dir, "laptop").unwrap().unwrap();
        assert_eq!((&disk.cert, disk.snapshot.version, disk.snapshot.sig.len()), (&cert, 7, 0));
        assert!(disk.snapshot.denied.contains(&[2; 32]));
        // Saved again, it is in the new format.
        save_member(&dir, "laptop", &disk).unwrap();
        assert!(fs::read(member_path(&dir, "laptop")).unwrap().starts_with(FORMAT));
        assert_eq!(load_member(&dir, "laptop").unwrap().unwrap().snapshot, disk.snapshot);
        fs::remove_dir_all(dir).ok();
    }
}
