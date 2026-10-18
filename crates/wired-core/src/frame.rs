//! Length-prefixed postcard frames, used for every control message on the wire.

use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound for one control frame. The largest is a network snapshot
/// (~60 bytes per member), so this allows networks of well over 10k nodes.
pub const MAX_FRAME: usize = 1024 * 1024;

pub async fn write<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<()> {
    let buf = postcard::to_stdvec(msg).context("encode frame")?;
    if buf.len() > MAX_FRAME {
        bail!("frame too large: {} bytes", buf.len());
    }
    w.write_all(&(buf.len() as u32).to_be_bytes()).await?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Limit for frames from peers that have not authenticated yet (Join, Hello).
pub const MAX_UNAUTHENTICATED_FRAME: usize = 64 * 1024;

pub async fn read<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    read_limited(r, MAX_FRAME).await
}

pub async fn read_limited<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R, max: usize) -> Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await.context("read frame length")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        bail!("frame too large: {len} bytes");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.context("read frame body")?;
    postcard::from_bytes(&buf).context("decode frame")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write(&mut a, &("hello".to_string(), 42u32)).await.unwrap();
        let got: (String, u32) = read(&mut b).await.unwrap();
        assert_eq!(got, ("hello".to_string(), 42));
    }

    #[tokio::test]
    async fn rejects_oversized_length() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes()).await.unwrap();
        assert!(read::<_, u32>(&mut b).await.is_err());
    }
}
