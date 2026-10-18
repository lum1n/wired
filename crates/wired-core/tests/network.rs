use std::{net::SocketAddr, time::Duration};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wired_core::{AnchorConfig, Invite, NetworkSecret, Node, RelayServe};

fn init_logs() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

fn local_anchor() -> AnchorConfig {
    let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();
    AnchorConfig { bind: lo, public_host: Some("127.0.0.1".into()), replica_of: None }
}

fn local_relay() -> RelayServe {
    let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();
    RelayServe::Public { bind: lo, qad_bind: Some(lo), public_host: Some("127.0.0.1".into()) }
}

async fn anchor(name: &str) -> Node {
    Node::builder(name).anchor(local_anchor()).relay(local_relay()).ephemeral().spawn().await.unwrap()
}

async fn member(name: &str, invite: &str) -> anyhow::Result<Node> {
    Node::builder(name).invite(invite.parse()?).ephemeral().spawn().await
}

/// Echo service: reads until EOF, writes it back.
fn serve_echo(node: &Node, service: &str) {
    let mut ln = node.listen(service).unwrap();
    tokio::spawn(async move {
        while let Some(mut s) = ln.accept().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                s.read_to_end(&mut buf).await.unwrap();
                let reply = format!("{}:{}", s.peer().name, String::from_utf8_lossy(&buf));
                s.write_all(reply.as_bytes()).await.unwrap();
                s.shutdown().await.unwrap();
            });
        }
    });
}

async fn roundtrip(from: &Node, target: &str, msg: &str) -> anyhow::Result<String> {
    let mut s = from.dial(target).await?;
    s.write_all(msg.as_bytes()).await?;
    s.shutdown().await?;
    let mut out = String::new();
    s.read_to_string(&mut out).await?;
    Ok(out)
}

#[tokio::test(flavor = "multi_thread")]
async fn anchor_reaches_member_and_members_reach_each_other() {
    init_logs();
    let vps = anchor("vps").await;
    let invite = vps.invite();
    let laptop = member("laptop", &invite).await.unwrap();
    let desktop = member("desktop", &invite).await.unwrap();
    serve_echo(&laptop, "echo");
    serve_echo(&vps, "echo");

    // The scenario: the public host calls a service on the member.
    let got =
        tokio::time::timeout(Duration::from_secs(20), roundtrip(&vps, "echo@laptop", "hi")).await.unwrap().unwrap();
    assert_eq!(got, "vps:hi");

    // Members reach each other, and the anchor's own services.
    assert_eq!(roundtrip(&desktop, "echo@laptop", "yo").await.unwrap(), "desktop:yo");
    assert_eq!(roundtrip(&laptop, "echo@vps", "hey").await.unwrap(), "laptop:hey");

    // Unknown service and unknown node fail cleanly.
    assert!(laptop.dial("nope@vps").await.is_err());
    assert!(laptop.dial("echo@ghost").await.is_err());

    for n in [laptop, desktop, vps] {
        n.close().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_secret_is_rejected() {
    init_logs();
    let vps = anchor("vps").await;
    let mut forged: Invite = vps.invite().parse().unwrap();
    forged.secret = NetworkSecret::generate();
    let res = member("intruder", &forged.encode()).await;
    assert!(res.is_err(), "joined with the wrong secret");
    vps.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn names_belong_to_their_first_key() {
    init_logs();
    let vps = anchor("vps").await;
    let invite = vps.invite();
    let first = member("laptop", &invite).await.unwrap();
    let res = member("laptop", &invite).await;
    assert!(res.is_err(), "second key took an existing name");
    first.close().await;
    vps.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn expose_and_forward_tcp() {
    init_logs();
    let vps = anchor("vps").await;
    let laptop = member("laptop", &vps.invite()).await.unwrap();

    // An existing TCP service on the laptop.
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 5];
                s.read_exact(&mut buf).await.unwrap();
                s.write_all(b"pong:").await.unwrap();
                s.write_all(&buf).await.unwrap();
            });
        }
    });

    let _exposed = laptop.expose("api", tcp_addr.to_string()).unwrap();
    let fwd = vps.forward("127.0.0.1:0", "api@laptop").await.unwrap();

    let mut c = tokio::net::TcpStream::connect(fwd.local_addr().unwrap()).await.unwrap();
    c.write_all(b"hello").await.unwrap();
    let mut out = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(20), c.read_exact(&mut out)).await.unwrap().unwrap();
    assert_eq!(&out, b"pong:hello");

    laptop.close().await;
    vps.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_only_members_talk_through_the_anchor_relay() {
    init_logs();
    let vps = anchor("vps").await;
    let invite = vps.invite();
    let a = Node::builder("a").invite(invite.parse().unwrap()).ephemeral().relay_only().spawn().await.unwrap();
    let b = Node::builder("b").invite(invite.parse().unwrap()).ephemeral().relay_only().spawn().await.unwrap();
    serve_echo(&b, "echo");
    let got =
        tokio::time::timeout(Duration::from_secs(20), roundtrip(&a, "echo@b", "via-relay")).await.unwrap().unwrap();
    assert_eq!(got, "a:via-relay");
    assert_eq!(a.path("b"), Some(wired_core::PathKind::Relay));
    for n in [a, b, vps] {
        n.close().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn loopback_members_go_direct() {
    init_logs();
    let vps = anchor("vps").await;
    let invite = vps.invite();
    let a = member("a", &invite).await.unwrap();
    let b = member("b", &invite).await.unwrap();
    serve_echo(&b, "echo");
    roundtrip(&a, "echo@b", "x").await.unwrap();
    let mut direct = false;
    for _ in 0..50 {
        if a.path("b") == Some(wired_core::PathKind::Direct) {
            direct = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(direct, "path never became direct: {:?}", a.path("b"));
    for n in [a, b, vps] {
        n.close().await;
    }
}
