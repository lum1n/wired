//! Hands streams to other runtimes (Node, Go, Swift) as Unix socket descriptors.
//!
//! Each Wired stream is pumped into one end of a `socketpair(2)`; the caller gets
//! the other end and wraps it in its native socket type. Only control calls
//! cross the FFI boundary, and backpressure and half-close come from the kernel.

use std::os::fd::OwnedFd;

use crate::Stream;

/// Bridges `stream` to a new socket and returns the caller's end (non-blocking).
/// Must be called from within a tokio runtime.
pub fn stream_to_fd(stream: Stream) -> std::io::Result<OwnedFd> {
    let (mut ours, theirs) = tokio::net::UnixStream::pair()?;
    tokio::spawn(async move {
        let mut stream = stream;
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut ours).await;
    });
    Ok(theirs.into_std()?.into())
}
