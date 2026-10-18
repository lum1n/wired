//! C ABI over `wired`, for cgo. See `include/wired.h`.
//!
//! Every call that can fail returns 0 on success or -1 with a message in `*err`
//! (free it with `wired_string_free`). Errors are returned per call, not kept
//! in thread-local storage, because cgo calls may hop OS threads. Blocking calls
//! run on a shared tokio runtime; streams come back as socket descriptors.

#![allow(clippy::missing_safety_doc)]

use std::{
    ffi::{CStr, CString, c_char, c_int},
    net::{IpAddr, SocketAddr},
    os::fd::IntoRawFd,
    sync::{Arc, LazyLock},
};

use anyhow::{Context, Result, anyhow};
use tokio::{runtime::Runtime, sync::Notify};

static RT: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread().enable_all().thread_name("wired").build().expect("tokio runtime")
});

pub struct WiredNode {
    node: wired::Node,
}

pub struct WiredListener {
    ln: tokio::sync::Mutex<Option<wired::Listener>>,
    closed: Arc<Notify>,
}

unsafe fn opt_str<'a>(p: *const c_char) -> Result<Option<&'a str>> {
    if p.is_null() {
        return Ok(None);
    }
    let s = unsafe { CStr::from_ptr(p) }.to_str().context("string is not UTF-8")?;
    Ok((!s.is_empty()).then_some(s))
}

unsafe fn req_str<'a>(p: *const c_char, what: &str) -> Result<&'a str> {
    unsafe { opt_str(p) }?.ok_or_else(|| anyhow!("{what} is required"))
}

fn c_string(s: impl Into<Vec<u8>>) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

/// Runs `f`, storing an error message in `err` on failure.
fn ffi(err: *mut *mut c_char, f: impl FnOnce() -> Result<()>) -> c_int {
    match f() {
        Ok(()) => 0,
        Err(e) => {
            if !err.is_null() {
                unsafe { *err = c_string(format!("{e:#}")) };
            }
            -1
        }
    }
}

fn common(mut b: wired::Builder, state_dir: Option<&str>, ephemeral: c_int) -> wired::Builder {
    if let Some(d) = state_dir {
        b = b.state_dir(d);
    }
    if ephemeral != 0 {
        b = b.ephemeral();
    }
    b
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Serving a relay behind a TLS-terminating proxy, from optional `url` and `bind`.
unsafe fn behind_proxy(url: *const c_char, bind: *const c_char) -> Result<Option<wired::RelayServe>> {
    match (unsafe { opt_str(url) }?, unsafe { opt_str(bind) }?) {
        (Some(url), Some(bind)) => {
            Ok(Some(wired::RelayServe::BehindProxy { bind: bind.parse()?, url: url.to_string() }))
        }
        (None, None) => Ok(None),
        _ => anyhow::bail!("relay_url and relay_bind go together"),
    }
}

/// `relay_url`/`relay_bind` (nullable): serve a relay behind a TLS-terminating proxy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_join(
    name: *const c_char,
    invite: *const c_char,
    state_dir: *const c_char,
    ephemeral: c_int,
    relay_url: *const c_char,
    relay_bind: *const c_char,
    out: *mut *mut WiredNode,
    err: *mut *mut c_char,
) -> c_int {
    ffi(err, || {
        let mut b = wired::Node::builder(unsafe { req_str(name, "name") }?);
        if let Some(inv) = unsafe { opt_str(invite) }? {
            b = b.invite(inv.parse()?);
        }
        if let Some(serve) = unsafe { behind_proxy(relay_url, relay_bind) }? {
            b = b.relay(serve);
        }
        let b = common(b, unsafe { opt_str(state_dir) }?, ephemeral);
        let node = RT.block_on(b.spawn())?;
        unsafe { *out = Box::into_raw(Box::new(WiredNode { node })) };
        Ok(())
    })
}

/// Starts an anchor. Its relay: behind a proxy when `relay_url`/`relay_bind`
/// are set; none when `no_relay`; otherwise public on `port` (with QUIC
/// address discovery on `qad_port`, which `< 0` disables). `replica_of`
/// (nullable) is the invite of the network to replicate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_anchor(
    name: *const c_char,
    bind_host: *const c_char,
    port: u16,
    qad_port: i32,
    public_host: *const c_char,
    replica_of: *const c_char,
    no_relay: c_int,
    relay_url: *const c_char,
    relay_bind: *const c_char,
    state_dir: *const c_char,
    ephemeral: c_int,
    out: *mut *mut WiredNode,
    err: *mut *mut c_char,
) -> c_int {
    ffi(err, || {
        let host: IpAddr = unsafe { opt_str(bind_host) }?.unwrap_or("0.0.0.0").parse()?;
        let public_host = unsafe { opt_str(public_host) }?.map(str::to_string);
        let cfg = wired::AnchorConfig {
            bind: SocketAddr::new(host, port),
            public_host: public_host.clone(),
            replica_of: unsafe { opt_str(replica_of) }?.map(str::parse).transpose()?,
        };
        let serve = match (unsafe { behind_proxy(relay_url, relay_bind) }?, no_relay != 0) {
            (Some(s), _) => Some(s),
            (None, true) => None,
            (None, false) => Some(wired::RelayServe::Public {
                bind: SocketAddr::new(host, port),
                qad_bind: match qad_port {
                    p if p < 0 => None,
                    p => Some(SocketAddr::new(host, u16::try_from(p).context("qad port out of range")?)),
                },
                public_host,
            }),
        };
        let mut b = wired::Node::builder(unsafe { req_str(name, "name") }?).anchor(cfg);
        if let Some(s) = serve {
            b = b.relay(s);
        }
        let b = common(b, unsafe { opt_str(state_dir) }?, ephemeral);
        let node = RT.block_on(b.spawn())?;
        unsafe { *out = Box::into_raw(Box::new(WiredNode { node })) };
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_node_name(n: *const WiredNode) -> *mut c_char {
    c_string(unsafe { &*n }.node.name())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_node_id(n: *const WiredNode) -> *mut c_char {
    c_string(unsafe { &*n }.node.id().to_string())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_node_invite(n: *const WiredNode) -> *mut c_char {
    c_string(unsafe { &*n }.node.invite())
}

/// Blocks until connected; `*fd` receives a non-blocking socket descriptor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_dial(
    n: *const WiredNode,
    target: *const c_char,
    fd: *mut c_int,
    err: *mut *mut c_char,
) -> c_int {
    ffi(err, || {
        let node = &unsafe { &*n }.node;
        let target = unsafe { req_str(target, "target") }?;
        let raw = RT.block_on(async {
            let stream = node.dial(target).await?;
            anyhow::Ok(wired::bridge::stream_to_fd(stream)?.into_raw_fd())
        })?;
        unsafe { *fd = raw };
        Ok(())
    })
}

/// 0 = no connection, 1 = direct, 2 = relay.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_path(n: *const WiredNode, peer: *const c_char) -> c_int {
    let Ok(Some(peer)) = (unsafe { opt_str(peer) }) else { return 0 };
    match unsafe { &*n }.node.path(peer) {
        None => 0,
        Some(wired::PathKind::Direct) => 1,
        Some(wired::PathKind::Relay) => 2,
    }
}

/// `allow` (nullable): comma-separated node names that may connect. NULL
/// allows every member; an empty string allows nobody.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_listen(
    n: *const WiredNode,
    service: *const c_char,
    allow: *const c_char,
    out: *mut *mut WiredListener,
    err: *mut *mut c_char,
) -> c_int {
    ffi(err, || {
        let node = &unsafe { &*n }.node;
        let service = unsafe { req_str(service, "service") }?;
        // NULL allows every member; an empty string allows nobody.
        let ln = if allow.is_null() {
            node.listen(service)
        } else {
            let a = unsafe { CStr::from_ptr(allow) }.to_str().context("allowlist is not UTF-8")?;
            node.listen_allow(service, a.split(',').filter(|s| !s.is_empty()))
        }?;
        let l = WiredListener { ln: tokio::sync::Mutex::new(Some(ln)), closed: Arc::new(Notify::new()) };
        unsafe { *out = Box::into_raw(Box::new(l)) };
        Ok(())
    })
}

/// Blocks for the next stream. Returns 0 with `*fd` set, 1 when the listener
/// is closed, or -1 on error. `peer_name`/`peer_id` must be freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_accept(
    l: *const WiredListener,
    fd: *mut c_int,
    peer_name: *mut *mut c_char,
    peer_id: *mut *mut c_char,
    err: *mut *mut c_char,
) -> c_int {
    let l = unsafe { &*l };
    let mut closed = false;
    let rc = ffi(err, || {
        RT.block_on(async {
            let mut guard = l.ln.lock().await;
            let Some(ln) = guard.as_mut() else {
                closed = true;
                return Ok(());
            };
            let stream = tokio::select! {
                s = ln.accept() => s,
                _ = l.closed.notified() => None,
            };
            let Some(stream) = stream else {
                guard.take();
                closed = true;
                return Ok(());
            };
            let peer = stream.peer().clone();
            let raw = wired::bridge::stream_to_fd(stream)?.into_raw_fd();
            unsafe {
                *fd = raw;
                *peer_name = c_string(peer.name);
                *peer_id = c_string(peer.id.to_string());
            }
            Ok(())
        })
    });
    if rc == 0 && closed { 1 } else { rc }
}

/// Unblocks a pending `wired_accept` and unregisters the service.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_listener_close(l: *const WiredListener) {
    let l = unsafe { &*l };
    l.closed.notify_one();
    if let Ok(mut g) = l.ln.try_lock() {
        g.take();
    }
}

/// Frees a listener. Call only after `wired_accept` has returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_listener_free(l: *mut WiredListener) {
    if !l.is_null() {
        let l = unsafe { Box::from_raw(l) };
        // Dropping the listener needs a runtime context.
        let _guard = RT.enter();
        drop(l);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_node_is_root(n: *const WiredNode) -> c_int {
    unsafe { &*n }.node.is_root() as c_int
}

/// One member per line: `name<TAB>id<TAB>anchor|member`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_members(n: *const WiredNode) -> *mut c_char {
    let lines: String = unsafe { &*n }
        .node
        .members()
        .iter()
        .map(|m| format!("{}\t{}\t{}\n", m.name, m.id, if m.anchor { "anchor" } else { "member" }))
        .collect();
    c_string(lines)
}

/// Root only: removes `name` now; `*invite` receives the new invite.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_revoke(
    n: *const WiredNode,
    name: *const c_char,
    invite: *mut *mut c_char,
    err: *mut *mut c_char,
) -> c_int {
    ffi(err, || {
        let new = unsafe { &*n }.node.revoke(unsafe { req_str(name, "name") }?)?;
        unsafe { *invite = c_string(new) };
        Ok(())
    })
}

/// Root only: replaces the invite; `*invite` receives the new one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_rotate_invite(
    n: *const WiredNode,
    invite: *mut *mut c_char,
    err: *mut *mut c_char,
) -> c_int {
    ffi(err, || {
        let new = unsafe { &*n }.node.rotate_invite()?;
        unsafe { *invite = c_string(new) };
        Ok(())
    })
}

/// One relay per line: `url<TAB>pinned|ca`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_relays(n: *const WiredNode) -> *mut c_char {
    let lines: String = unsafe { &*n }
        .node
        .relays()
        .iter()
        .map(|r| format!("{}\t{}\n", r.url, if r.pin.is_some() { "pinned" } else { "ca" }))
        .collect();
    c_string(lines)
}

/// Root only: lists a relay (e.g. `https://robin.exe.xyz`) for the whole network.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_add_relay(n: *const WiredNode, url: *const c_char, err: *mut *mut c_char) -> c_int {
    ffi(err, || unsafe { &*n }.node.add_relay(unsafe { req_str(url, "url") }?))
}

/// Root only: stops listing a relay.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_remove_relay(n: *const WiredNode, url: *const c_char, err: *mut *mut c_char) -> c_int {
    ffi(err, || unsafe { &*n }.node.remove_relay(unsafe { req_str(url, "url") }?))
}

/// Root only: lets the replica anchor with this id join.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_approve_anchor(n: *const WiredNode, id: *const c_char, err: *mut *mut c_char) -> c_int {
    ffi(err, || {
        let id = unsafe { req_str(id, "id") }?.parse().context("not a node id")?;
        unsafe { &*n }.node.approve_anchor(id)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_node_close(n: *const WiredNode) {
    let node = unsafe { &*n }.node.clone();
    RT.block_on(node.close());
}

/// Frees a node handle. Close it first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wired_node_free(n: *mut WiredNode) {
    if !n.is_null() {
        let n = unsafe { Box::from_raw(n) };
        let _guard = RT.enter();
        drop(n);
    }
}
