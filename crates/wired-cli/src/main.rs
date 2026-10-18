//! `wired`: run a node without writing code, or put an existing TCP service on a network.

use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use wired::{AnchorConfig, Node, Task};

#[derive(Parser)]
#[command(name = "wired", version, about = "Encrypted service-to-service networking")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run an anchor on a publicly reachable host and print the network invite.
    Anchor {
        #[arg(long, default_value = "anchor")]
        name: String,
        /// UDP port for peers and TCP port for the HTTPS relay.
        #[arg(long, default_value_t = 7443)]
        port: u16,
        /// UDP port for QUIC address discovery (0 disables it).
        #[arg(long, default_value_t = 7842)]
        qad_port: u16,
        /// Host name or IP to put in the invite (default: the default route's IP).
        #[arg(long)]
        public_host: Option<String>,
        /// Run as a replica of this network (approve it on the root with `wired approve <id>`).
        #[arg(long, value_name = "INVITE", hide_env_values = true)]
        replica_of: Option<String>,
        #[command(flatten)]
        common: Common,
    },
    /// Join a network as a member.
    Join {
        #[arg(long)]
        name: String,
        /// Network invite.
        #[arg(long, env = "WIRED_INVITE", hide_env_values = true)]
        invite: String,
        #[command(flatten)]
        common: Common,
    },
    /// Print the current invite of the anchor using this state directory.
    Invite {
        #[command(flatten)]
        admin: Admin,
    },
    /// Remove a node now. Rotates the invite; prints the new one.
    Revoke {
        name: String,
        #[command(flatten)]
        admin: Admin,
    },
    /// Replace the invite (e.g. if it leaked). Existing members are unaffected.
    Rotate {
        #[command(flatten)]
        admin: Admin,
    },
    /// Allow a replica anchor (by node id) to join as an anchor.
    Approve {
        id: String,
        #[command(flatten)]
        admin: Admin,
    },
    /// List the network's members.
    Members {
        #[command(flatten)]
        admin: Admin,
    },
}

/// Talks to a running anchor over its local admin socket.
#[derive(Args)]
struct Admin {
    /// The anchor's state directory (default: $XDG_CONFIG_HOME/wired).
    #[arg(long, env = "WIRED_STATE_DIR")]
    state_dir: Option<PathBuf>,
}

impl Admin {
    fn dir(&self) -> PathBuf {
        self.state_dir.clone().unwrap_or_else(wired_core::state::default_dir)
    }

    async fn run(&self, command: &str) -> Result<()> {
        print!("{}", wired_core::admin::request(&self.dir(), command).await?);
        Ok(())
    }
}

#[derive(Args)]
struct Common {
    /// Serve a local TCP address as a service: `api=127.0.0.1:8080`. Repeatable.
    #[arg(long, value_name = "SERVICE=ADDR")]
    expose: Vec<String>,
    /// Only let these nodes use an exposed service: `api=vps,desktop`. Repeatable.
    #[arg(long, value_name = "SERVICE=NODE[,NODE]")]
    allow: Vec<String>,
    /// Listen locally and forward to a remote service: `127.0.0.1:9000=api@laptop`. Repeatable.
    #[arg(long, value_name = "ADDR=SERVICE@NODE")]
    forward: Vec<String>,
    /// Where keys and anchor state live (default: $XDG_CONFIG_HOME/wired).
    #[arg(long, env = "WIRED_STATE_DIR")]
    state_dir: Option<PathBuf>,
}

fn split_pair(s: &str) -> Result<(&str, &str)> {
    let (a, b) = s.split_once('=').with_context(|| format!("{s:?}: expected LEFT=RIGHT"))?;
    ensure!(!a.is_empty() && !b.is_empty(), "{s:?}: expected LEFT=RIGHT");
    Ok((a, b))
}

async fn run(builder: wired::Builder, common: Common) -> Result<()> {
    let builder = match common.state_dir {
        Some(d) => builder.state_dir(d),
        None => builder,
    };
    let node = builder.spawn().await?;
    eprintln!("wired: {} is up (id {})", node.name(), node.id());
    if node.is_root() {
        eprintln!("wired: invite (treat it like a password):");
        println!("{}", node.invite());
    } else if node.is_anchor() {
        eprintln!("wired: replica; if not yet approved, run on the root: wired approve {}", node.id());
    }

    let mut allow: HashMap<&str, Vec<&str>> = HashMap::new();
    for a in &common.allow {
        let (service, names) = split_pair(a)?;
        allow.entry(service).or_default().extend(names.split(',').filter(|n| !n.is_empty()));
    }
    let mut tasks: Vec<Task> = Vec::new();
    for e in &common.expose {
        let (service, addr) = split_pair(e)?;
        match allow.remove(service) {
            Some(names) => {
                tasks.push(node.expose_allow(service, addr, names.iter().copied())?);
                eprintln!("wired: exposing {addr} as {service}@{} to {}", node.name(), names.join(", "));
            }
            None => {
                tasks.push(node.expose(service, addr)?);
                eprintln!("wired: exposing {addr} as {service}@{} to all members", node.name());
            }
        }
    }
    if let Some(service) = allow.keys().next() {
        bail!("--allow given for {service:?}, which is not exposed");
    }
    for f in &common.forward {
        let (addr, target) = split_pair(f)?;
        let t = node.forward(addr, target).await?;
        eprintln!("wired: forwarding {} -> {target}", t.local_addr().expect("forward has an address"));
        tasks.push(t);
    }

    tokio::signal::ctrl_c().await?;
    drop(tasks);
    node.close().await;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "wired_core=info,warn".into()),
        )
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().cmd {
        Cmd::Anchor { name, port, qad_port, public_host, replica_of, common } => {
            let any = |p| SocketAddr::from(([0, 0, 0, 0], p));
            let cfg = AnchorConfig {
                bind: any(port),
                relay_bind: any(port),
                qad_bind: (qad_port != 0).then(|| any(qad_port)),
                public_host,
                replica_of: replica_of.map(|i| i.parse()).transpose()?,
            };
            run(Node::builder(name).anchor(cfg), common).await
        }
        Cmd::Join { name, invite, common } => run(Node::builder(name).invite(invite.parse()?), common).await,
        Cmd::Invite { admin } => match wired_core::admin::request(&admin.dir(), "invite").await {
            Ok(out) => {
                print!("{out}");
                Ok(())
            }
            // Not running: fall back to the last invite it saved.
            Err(_) => {
                println!("{}", wired_core::state::load_invite(&admin.dir())?.trim());
                Ok(())
            }
        },
        Cmd::Revoke { name, admin } => admin.run(&format!("revoke {name}")).await,
        Cmd::Rotate { admin } => admin.run("rotate").await,
        Cmd::Approve { id, admin } => admin.run(&format!("approve {id}")).await,
        Cmd::Members { admin } => admin.run("members").await,
    }
}
