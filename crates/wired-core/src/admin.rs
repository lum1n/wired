//! Local admin socket for a running anchor (`wired revoke`, `approve`, ...).
//!
//! The socket lives in the anchor's state directory (mode 0700) and is itself
//! mode 0600, so only the user running the anchor can use it. Protocol: one
//! command line in; `ok` plus output, or `error: <message>`, back.

use std::{os::unix::fs::PermissionsExt, path::Path, path::PathBuf};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};

use crate::{node::Node, state};

pub(crate) fn spawn(node: Node, path: PathBuf) -> Result<JoinHandle<()>> {
    // A stale socket from a previous run would make bind fail.
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let node = node.clone();
            tokio::spawn(async move {
                let _ = handle(&node, sock).await;
            });
        }
    }))
}

async fn handle(node: &Node, sock: UnixStream) -> Result<()> {
    let (r, mut w) = sock.into_split();
    let mut line = String::new();
    BufReader::new(r.take(4096)).read_line(&mut line).await?;
    let out = match dispatch(node, line.trim()) {
        Ok(s) => format!("ok\n{s}"),
        Err(e) => format!("error: {e:#}\n"),
    };
    w.write_all(out.as_bytes()).await?;
    w.shutdown().await?;
    Ok(())
}

fn dispatch(node: &Node, line: &str) -> Result<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    Ok(match parts.as_slice() {
        ["invite"] => format!("{}\n", node.invite()),
        ["rotate"] => format!("{}\n", node.rotate_invite()?),
        ["revoke", name] => format!("{}\n", node.revoke(name)?),
        ["approve", id] => {
            node.approve_anchor(id.parse().context("not a node id")?)?;
            "approved\n".into()
        }
        ["relays"] => node
            .relays()
            .iter()
            .map(|r| format!("{}\t{}\n", r.url, if r.pin.is_some() { "pinned" } else { "ca" }))
            .collect(),
        ["relay", "add", url] => {
            node.add_relay(url)?;
            "added\n".into()
        }
        ["relay", "remove", url] => {
            node.remove_relay(url)?;
            "removed\n".into()
        }
        ["members"] => node
            .members()
            .iter()
            .map(|m| format!("{}\t{}\t{}\n", m.name, m.id, if m.anchor { "anchor" } else { "member" }))
            .collect(),
        _ => bail!(
            "unknown command {line:?}; try invite, rotate, revoke <name>, approve <id>, members, relays, relay add|remove <url>"
        ),
    })
}

/// Sends `command` to the anchor running with state directory `dir`.
pub async fn request(dir: &Path, command: &str) -> Result<String> {
    let path = state::admin_socket(dir);
    let mut sock = UnixStream::connect(&path)
        .await
        .with_context(|| format!("connect to {} (is the anchor running?)", path.display()))?;
    sock.write_all(format!("{command}\n").as_bytes()).await?;
    sock.shutdown().await?;
    let mut out = String::new();
    sock.read_to_string(&mut out).await?;
    match out.strip_prefix("ok\n") {
        Some(rest) => Ok(rest.to_string()),
        None => bail!("{}", out.trim().trim_start_matches("error: ")),
    }
}
