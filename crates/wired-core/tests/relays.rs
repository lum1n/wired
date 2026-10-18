//! Relays apart from anchors: a root nobody can reach directly, with relays
//! served by members behind a forwarding proxy (as on exe.dev).

use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use wired_core::{AnchorConfig, Invite, Node, PathKind, RelayServe};

fn init_logs() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// A root with no relay and no direct sockets: like a laptop behind NAT.
async fn unreachable_root() -> Node {
    let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cfg = AnchorConfig { bind: lo, public_host: None, replica_of: None };
    Node::builder("home").anchor(cfg).relay_only().ephemeral().spawn().await.unwrap()
}

/// A free local port (racy, fine for tests).
async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port()
}

/// Stands in for exe.dev's proxy: forwards every connection on `public` to `target`.
async fn forwarding_proxy(target: SocketAddr) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            tokio::spawn(async move {
                if let Ok(mut outbound) = TcpStream::connect(target).await {
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
            });
        }
    });
    port
}

/// A member serving a relay behind a proxy, joined through that relay.
async fn vm(name: &str, root: &Node) -> Node {
    let relay_port = free_port().await;
    let proxy_port = forwarding_proxy(SocketAddr::from(([127, 0, 0, 1], relay_port))).await;
    let url = format!("http://127.0.0.1:{proxy_port}");
    // The root must know the relay before the VM can join through it.
    root.add_relay(&url).unwrap();
    let invite: Invite = root.invite().parse().unwrap();
    let serve = RelayServe::BehindProxy { bind: SocketAddr::from(([127, 0, 0, 1], relay_port)), url };
    tokio::time::timeout(
        Duration::from_secs(30),
        Node::builder(name).invite(invite).relay(serve).relay_only().ephemeral().spawn(),
    )
    .await
    .expect("join hung")
    .unwrap()
}

fn serve_echo(node: &Node) {
    let mut ln = node.listen("echo").unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn root_behind_nat_and_a_vm_relay_reach_each_other() {
    init_logs();
    let home = unreachable_root().await;
    assert!(home.relays().is_empty());
    let robin = vm("robin", &home).await;
    serve_echo(&home);
    serve_echo(&robin);

    // Both directions, all through robin's relay.
    echo(&home, "echo@robin").await.unwrap();
    echo(&robin, "echo@home").await.unwrap();
    assert_eq!(home.path("robin"), Some(PathKind::Relay));

    // The relay is listed once, with what robin announced about it.
    let relays = home.relays();
    assert_eq!(relays.len(), 1, "{relays:?}");
    assert_eq!(relays[0].owner, Some(*robin.id().as_bytes()));
    let (url, _) = robin.served_relay().unwrap();
    assert_eq!(relays[0].url, url);

    // Revoking robin drops its relay from the network.
    home.revoke("robin").unwrap();
    assert!(home.relays().is_empty());

    robin.close().await;
    home.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn members_on_different_relays_reach_each_other() {
    init_logs();
    let home = unreachable_root().await;
    let a = vm("a", &home).await;
    let b = vm("b", &home).await;
    for n in [&home, &a, &b] {
        serve_echo(n);
    }
    // Wait until everyone knows both relays.
    for _ in 0..100 {
        if a.relays().len() == 2 && b.relays().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    echo(&a, "echo@b").await.unwrap();
    echo(&b, "echo@a").await.unwrap();
    echo(&home, "echo@a").await.unwrap();
    echo(&home, "echo@b").await.unwrap();
    for n in [a, b, home] {
        n.close().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn relays_admit_only_the_network_and_not_revoked_keys() {
    init_logs();
    let home = unreachable_root().await;
    let robin = vm("robin", &home).await;
    let laptop_key = wired_core::SecretKey::generate();
    let laptop = Node::builder("laptop")
        .invite(home.invite().parse().unwrap())
        .secret_key(laptop_key.clone())
        .relay_only()
        .ephemeral()
        .spawn()
        .await
        .unwrap();

    let (url, _) = robin.served_relay().unwrap();
    let url: iroh::RelayUrl = url.parse().unwrap();
    let invite: Invite = home.invite().parse().unwrap();
    let token = wired_core::relay::token(&invite.network_id);
    let connect = |key: wired_core::SecretKey, token: Option<String>| {
        let url = url.clone();
        async move {
            let tls = iroh::tls::CaTlsConfig::default().client_config(wired_core::tls::provider()).unwrap();
            let mut b =
                iroh_relay::client::ClientBuilder::new(url, key, iroh::dns::DnsResolver::new()).tls_client_config(tls);
            if let Some(t) = token {
                b = b.auth_token(t);
            }
            b.connect().await.map(|_| ())
        }
    };

    // Strangers without the network's token are refused; members get in.
    assert!(connect(wired_core::SecretKey::generate(), None).await.is_err());
    assert!(connect(wired_core::SecretKey::generate(), Some("nope".into())).await.is_err());
    connect(laptop_key.clone(), Some(token.clone())).await.unwrap();

    // A revoked key is refused even with the token.
    home.revoke("laptop").unwrap();
    let mut refused = false;
    for _ in 0..100 {
        if connect(laptop_key.clone(), Some(token.clone())).await.is_err() {
            refused = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(refused, "revoked key still admitted by the relay");

    for n in [laptop, robin, home] {
        n.close().await;
    }
}
