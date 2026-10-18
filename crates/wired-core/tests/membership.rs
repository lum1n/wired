//! Allowlists, revocation, replicas, cached restarts and the admin socket.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wired_core::{AnchorConfig, ErrorCode, Invite, Node, RemoteError, SecretKey};

fn init_logs() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn local_anchor(replica_of: Option<Invite>) -> AnchorConfig {
    let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();
    AnchorConfig { bind: lo, relay_bind: lo, qad_bind: Some(lo), public_host: Some("127.0.0.1".into()), replica_of }
}

async fn root(name: &str) -> Node {
    Node::builder(name).anchor(local_anchor(None)).ephemeral().spawn().await.unwrap()
}

async fn member(name: &str, invite: &str) -> anyhow::Result<Node> {
    Node::builder(name).invite(invite.parse()?).ephemeral().spawn().await
}

async fn member_with_key(name: &str, invite: &str, key: &SecretKey) -> anyhow::Result<Node> {
    Node::builder(name).invite(invite.parse()?).secret_key(key.clone()).ephemeral().spawn().await
}

fn code(e: &anyhow::Error) -> Option<ErrorCode> {
    e.downcast_ref::<RemoteError>().map(|r| r.code)
}

fn serve_echo(node: &Node, service: &str, allow: Option<&[&str]>) {
    let mut ln = match allow {
        Some(a) => node.listen_allow(service, a.iter().copied()).unwrap(),
        None => node.listen(service).unwrap(),
    };
    tokio::spawn(async move {
        while let Some(mut s) = ln.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                if s.read_to_end(&mut buf).await.is_ok() {
                    let _ = s.write_all(&buf).await;
                    let _ = s.shutdown().await;
                }
            });
        }
    });
}

async fn echo(from: &Node, target: &str) -> anyhow::Result<()> {
    let mut s = tokio::time::timeout(Duration::from_secs(20), from.dial(target)).await??;
    s.write_all(b"ping").await?;
    s.shutdown().await?;
    let mut out = Vec::new();
    s.read_to_end(&mut out).await?;
    anyhow::ensure!(out == b"ping", "bad echo {out:?}");
    Ok(())
}

/// Polls `cond` for up to `secs` seconds.
async fn eventually(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..secs * 20 {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    cond()
}

#[tokio::test(flavor = "multi_thread")]
async fn allowlist_restricts_a_service_to_named_nodes() {
    init_logs();
    let vps = root("vps").await;
    let a = member("a", &vps.invite()).await.unwrap();
    let b = member("b", &vps.invite()).await.unwrap();
    serve_echo(&b, "admin", Some(&["a"]));

    echo(&a, "admin@b").await.unwrap();
    let denied = echo(&vps, "admin@b").await.unwrap_err();
    assert_eq!(code(&denied), Some(ErrorCode::Denied), "{denied:#}");

    for n in [a, b, vps] {
        n.close().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_cuts_off_immediately_and_rotates_the_invite() {
    init_logs();
    let vps = root("vps").await;
    let old_invite = vps.invite();
    let laptop_key = SecretKey::generate();
    let laptop = member_with_key("laptop", &old_invite, &laptop_key).await.unwrap();
    let desktop = member("desktop", &old_invite).await.unwrap();

    // An open stream from laptop to desktop, mid-conversation.
    let mut ln = desktop.listen("hold").unwrap();
    let mut held = laptop.dial("hold@desktop").await.unwrap();
    held.write_all(b"x").await.unwrap();
    let mut server_side = ln.accept().await.unwrap();

    let new_invite = vps.revoke("laptop").unwrap();
    assert_ne!(new_invite, old_invite);

    // Desktop drops the connection as soon as the revocation reaches it.
    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(5), server_side.read(&mut buf)).await;
    assert!(matches!(read, Ok(Err(_)) | Ok(Ok(1)) | Ok(Ok(0))), "stream survived revocation: {read:?}");
    let read = tokio::time::timeout(Duration::from_secs(5), held.read(&mut buf)).await.expect("laptop side hung");
    assert!(matches!(read, Err(_) | Ok(0)), "laptop could still read: {read:?}");

    // Laptop can no longer reach anyone, and cannot come back under any key.
    serve_echo(&desktop, "echo", None);
    assert!(echo(&laptop, "echo@desktop").await.is_err());
    let again = member_with_key("laptop", &new_invite, &laptop_key).await.unwrap_err();
    assert_eq!(code(&again), Some(ErrorCode::Denied), "{again:#}");
    let fresh_key = member("laptop2", &old_invite).await.unwrap_err();
    assert_eq!(code(&fresh_key), Some(ErrorCode::Unauthorized), "{fresh_key:#}");

    // The new invite works, the name is free again, and existing members are unaffected.
    let replacement = member("laptop", &new_invite).await.unwrap();
    echo(&replacement, "echo@desktop").await.unwrap();
    assert!(!vps.members().iter().any(|m| m.id == laptop_key.public()));

    for n in [replacement, laptop, desktop, vps] {
        n.close().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn replica_keeps_the_network_running_when_the_root_is_down() {
    init_logs();
    let vps = root("vps").await;
    let invite: Invite = vps.invite().parse().unwrap();

    // A replica must be approved before it can serve.
    let vps2 = Node::builder("vps2").anchor(local_anchor(Some(invite.clone()))).ephemeral().spawn().await.unwrap();
    assert!(!vps.members().iter().any(|m| m.name == "vps2"));
    vps.approve_anchor(vps2.id()).unwrap();
    assert!(
        eventually(20, || vps.members().iter().any(|m| m.name == "vps2" && m.anchor)).await,
        "replica never registered"
    );

    let laptop_key = SecretKey::generate();
    let laptop = member_with_key("laptop", &vps.invite(), &laptop_key).await.unwrap();
    let desktop = member("desktop", &vps.invite()).await.unwrap();
    serve_echo(&desktop, "echo", None);
    assert!(eventually(10, || laptop.members().iter().any(|m| m.name == "vps2")).await);
    assert!(eventually(10, || vps2.members().iter().any(|m| m.name == "desktop")).await);

    // Invites issued from now on list both anchors.
    let invite: Invite = vps.invite().parse().unwrap();
    assert_eq!(invite.anchors.len(), 2);
    vps.close().await;

    // A known node restarts with the root gone: it renews at the replica, and
    // its replica-issued certificate is accepted by peers.
    laptop.close().await;
    let laptop =
        tokio::time::timeout(Duration::from_secs(20), member_with_key("laptop", &invite.encode(), &laptop_key))
            .await
            .expect("restart hung")
            .unwrap();
    echo(&laptop, "echo@desktop").await.unwrap();

    // New keys still need the root.
    let stranger = member("stranger", &invite.encode()).await.unwrap_err();
    assert_eq!(code(&stranger), Some(ErrorCode::NotPrimary), "{stranger:#}");

    for n in [laptop, desktop, vps2] {
        n.close().await;
    }
}

fn temp_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("wired-{tag}-{}", rand::random::<u64>()))
}

#[tokio::test(flavor = "multi_thread")]
async fn member_starts_from_cache_when_no_anchor_is_reachable() {
    init_logs();
    let vps = root("vps").await;
    let invite = vps.invite();
    let dir = temp_dir("cache");
    let laptop = Node::builder("laptop").invite(invite.parse().unwrap()).state_dir(&dir).spawn().await.unwrap();
    let id = laptop.id();
    laptop.close().await;
    vps.close().await;

    let laptop = tokio::time::timeout(
        Duration::from_secs(30),
        Node::builder("laptop").invite(invite.parse().unwrap()).state_dir(&dir).spawn(),
    )
    .await
    .expect("cached start hung")
    .expect("cached start failed");
    assert_eq!(laptop.id(), id);
    assert!(laptop.members().iter().any(|m| m.name == "vps"));
    laptop.close().await;
    std::fs::remove_dir_all(dir).ok();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn admin_socket_and_root_restart() {
    init_logs();
    let dir = temp_dir("admin");
    let spawn_root = || Node::builder("vps").anchor(local_anchor(None)).state_dir(&dir).spawn();
    let vps = spawn_root().await.unwrap();
    let laptop = member("laptop", &vps.invite()).await.unwrap();

    let members = wired_core::admin::request(&dir, "members").await.unwrap();
    assert!(members.contains("laptop\t") && members.contains("vps\t"), "{members}");
    let bad = wired_core::admin::request(&dir, "revoke ghost").await.unwrap_err();
    assert!(format!("{bad}").contains("unknown node"), "{bad}");

    // The registry survives a restart; the network keeps its identity.
    let old: Invite = vps.invite().parse().unwrap();
    vps.close().await;
    let vps = spawn_root().await.unwrap();
    let new: Invite = vps.invite().parse().unwrap();
    assert_eq!((new.network_id, new.root, &new.secret), (old.network_id, old.root, &old.secret));
    assert!(vps.members().iter().any(|m| m.name == "laptop"));

    let out = wired_core::admin::request(&dir, "revoke laptop").await.unwrap();
    assert!(out.trim().starts_with("wired1"), "{out}");
    assert!(!vps.members().iter().any(|m| m.name == "laptop"));

    laptop.close().await;
    vps.close().await;
    std::fs::remove_dir_all(dir).ok();
}
