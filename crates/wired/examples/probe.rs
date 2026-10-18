//! Test helper for `tests/interop/nat.sh`.
//!
//! `probe serve <name>` joins (WIRED_INVITE) and echoes on service `echo`.
//! `probe dial <name> <node>` joins, round-trips through `echo@<node>`, then
//! waits for a direct path and prints `path=Direct` or `path=Relay`.

use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wired::{Node, PathKind};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let state = std::env::temp_dir().join(format!("wired-probe-{}", std::process::id()));
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["serve", name] => {
            let node = Node::builder(*name).state_dir(&state).spawn().await?;
            let mut ln = node.listen("echo")?;
            eprintln!("probe: {name} serving echo");
            while let Some(mut s) = ln.accept().await {
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    if s.read_to_end(&mut buf).await.is_ok() {
                        let _ = s.write_all(&buf).await;
                        let _ = s.shutdown().await;
                    }
                });
            }
            Ok(())
        }
        ["dial", name, peer] => {
            let node = Node::builder(*name).state_dir(&state).spawn().await?;
            let target = format!("echo@{peer}");
            let mut s =
                tokio::time::timeout(Duration::from_secs(20), node.dial(&target)).await.context("dial timed out")??;
            s.write_all(b"ping").await?;
            s.shutdown().await?;
            let mut out = Vec::new();
            s.read_to_end(&mut out).await?;
            ensure!(out == b"ping", "bad echo: {out:?}");
            println!("roundtrip=ok");
            // Hole punching continues after the first (relayed) packets; give it time.
            let mut path = node.path(peer);
            for _ in 0..100 {
                if path == Some(PathKind::Direct) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                path = node.path(peer);
            }
            match path {
                Some(p) => println!("path={p:?}"),
                None => bail!("no connection to {peer}"),
            }
            node.close().await;
            Ok(())
        }
        _ => bail!("usage: probe serve <name> | probe dial <name> <node>"),
    }
}
