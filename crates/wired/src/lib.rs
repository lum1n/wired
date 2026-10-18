//! Wired: embeddable, encrypted service-to-service networking.
//!
//! ```no_run
//! # async fn demo() -> anyhow::Result<()> {
//! // On the public host:
//! let vps = wired::Node::builder("vps").anchor(Default::default()).relay(wired::RelayServe::public()).spawn().await?;
//! println!("{}", vps.invite());
//!
//! // On a machine behind NAT, with WIRED_INVITE set:
//! let laptop = wired::Node::builder("laptop").spawn().await?;
//! let _api = laptop.expose_allow("api", "127.0.0.1:8080", ["vps"])?;
//!
//! // Back on the public host:
//! let stream = vps.dial("api@laptop").await?;
//! # Ok(()) }
//! ```

pub use wired_core::relay;
pub use wired_core::{
    AnchorConfig, AnchorInfo, Builder, ErrorCode, Invite, Listener, Member, NetworkSecret, Node, PathKind, PeerInfo,
    PublicKey, RelayInfo, RelayServe, RemoteError, SecretKey, Stream, Task,
    node::{parse_target, valid_name},
};
#[cfg(unix)]
pub use wired_core::{admin, bridge};
