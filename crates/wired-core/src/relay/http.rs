//! The relay's HTTP(S) listener. iroh-relay's own drops a connection that hasn't
//! upgraded to a WebSocket within 30 seconds, but not one that upgrades and then
//! never finishes the relay handshake, so a stranger without the network's token
//! could hold connections open forever. This one closes every connection that
//! isn't an admitted relay client by then, and caps how many may be waiting at once.

use std::{
    net::Shutdown,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use hyper::{Request, Response, StatusCode, body::Incoming, server::conn::http1, service::Service};
use hyper_util::rt::TokioIo;
use iroh_relay::{
    http::{RELAY_PATH, RELAY_PROBE_PATH},
    server::{
        http_server::{BytesBody, HyperError, RelayService, RelayServiceWithNotify},
        streams::MaybeTlsStream,
    },
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;
use tracing::debug;

/// How long a connection has to become an admitted relay client.
pub(super) const ADMIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Connections that may be waiting to be admitted at once. Others are dropped on accept.
const MAX_WAITING: usize = 256;

/// Serves `service` on `listener` (over TLS with `tls`) until the task is aborted.
/// Aborting it also closes every connection not yet admitted.
pub(super) fn serve(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    service: RelayService,
    timeout: Duration,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let slots = Arc::new(Semaphore::new(MAX_WAITING));
        let mut waiting = JoinSet::new();
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(e) => {
                    // Out of file descriptors, say: let some close before trying again.
                    debug!("relay accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            while waiting.try_join_next().is_some() {}
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                debug!(%peer, "too many relay connections waiting to be admitted");
                continue;
            };
            waiting.spawn(admit(stream, tls.clone(), service.clone(), timeout, slot));
        }
    })
}

/// Serves one connection until the relay admits it as a client, it closes, or `timeout` passes.
async fn admit(
    stream: TcpStream,
    tls: Option<TlsAcceptor>,
    service: RelayService,
    timeout: Duration,
    _slot: OwnedSemaphorePermit,
) {
    let Ok((stream, closer)) = Closer::new(stream) else { return };
    // iroh-relay notifies this once it has admitted the client: after the handshake and the token.
    let admitted = Arc::new(Notify::new());
    let on_admit = admitted.notified();
    tokio::pin!(on_admit);
    on_admit.as_mut().enable();
    let routes = Routes { relay: RelayServiceWithNotify::new(service, admitted.clone()), upgraded: Default::default() };
    let upgraded = routes.upgraded.clone();
    let serving = async move {
        let io = match tls {
            Some(tls) => MaybeTlsStream::Tls(tls.accept(stream).await?),
            None => MaybeTlsStream::Plain(stream),
        };
        http1::Builder::new().serve_connection(TokioIo::new(io), routes).with_upgrades().await?;
        anyhow::Ok(())
    };
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(serving, deadline);
    tokio::select! {
        _ = &mut on_admit => return closer.disarm(),
        _ = &mut deadline => return,
        res = &mut serving => {
            if let Err(e) = res {
                debug!("relay connection: {e:#}");
            }
            // Serving ends at a WebSocket upgrade; the relay handshake goes on elsewhere.
            if !upgraded.load(Ordering::Relaxed) {
                return;
            }
        }
    }
    tokio::select! {
        _ = on_admit => closer.disarm(),
        _ = deadline => {}
    }
}

/// A second handle on a connection's socket, which shuts it down when dropped
/// unless disarmed. Its other handle may be with a task iroh-relay spawned.
struct Closer(Option<std::net::TcpStream>);

impl Closer {
    fn new(stream: TcpStream) -> std::io::Result<(TcpStream, Self)> {
        let stream = stream.into_std()?;
        let dup = stream.try_clone()?;
        Ok((TcpStream::from_std(stream)?, Self(Some(dup))))
    }

    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for Closer {
    fn drop(&mut self) {
        if let Some(s) = &self.0 {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

/// The relay's routes: `/relay` and `/ping` (clients measure latency with it).
struct Routes {
    relay: RelayServiceWithNotify,
    /// Whether the connection asked for a WebSocket upgrade.
    upgraded: Arc<AtomicBool>,
}

impl Service<Request<Incoming>> for Routes {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        if req.uri().path() == RELAY_PROBE_PATH {
            let empty: BytesBody = Box::new(http_body_util::Full::new(hyper::body::Bytes::new()));
            let res = Response::builder().status(StatusCode::OK).header("Access-Control-Allow-Origin", "*").body(empty);
            return std::future::ready(res.map_err(Into::into));
        }
        if req.uri().path() == RELAY_PATH {
            self.upgraded.store(true, Ordering::Relaxed);
        }
        self.relay.call(req)
    }
}
