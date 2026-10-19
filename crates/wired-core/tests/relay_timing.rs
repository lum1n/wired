//! The root learns a relay's URL before the relay exists, as when the app lists an exe.dev
//! server's relay and the server starts it after: the root fails to reach it meanwhile and backs
//! off, and the server must still get in through it.

use std::{net::SocketAddr, time::Duration};

use tokio::net::TcpListener;
use wired_core::{AnchorConfig, Invite, Node, RelayServe};

#[tokio::test(flavor = "multi_thread")]
async fn a_server_joins_through_its_relay_after_the_root_backed_off_from_it() {
    let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let cfg = AnchorConfig { bind: lo, public_host: None, replica_of: None };
    let home = Node::builder("home").anchor(cfg).relay_only().ephemeral().spawn().await.unwrap();
    let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let url = format!("http://127.0.0.1:{port}");
    home.add_relay(&url).unwrap();
    // Before this fix, 5 s of the relay missing made the join time out.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let invite: Invite = home.invite().parse().unwrap();
    let serve = RelayServe::BehindProxy { bind: SocketAddr::from(([127, 0, 0, 1], port)), url };
    let robin = tokio::time::timeout(
        Duration::from_secs(150),
        Node::builder("robin").invite(invite).relay(serve).relay_only().ephemeral().spawn(),
    )
    .await
    .expect("join hung")
    .unwrap();
    robin.close().await;
    home.close().await;
}
