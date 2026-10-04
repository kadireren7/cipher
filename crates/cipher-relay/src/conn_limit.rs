//! Cap on simultaneously open client connections. A connection that cannot get a permit is dropped at
//! accept time (before any TLS work), so a connection flood cannot exhaust file descriptors or memory.
use axum_server::accept::Accept;
use std::future::{ready, Ready};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Debug)]
pub struct LimitAcceptor {
    sem: Arc<Semaphore>,
}

impl LimitAcceptor {
    pub fn new(max_connections: usize) -> Self {
        Self { sem: Arc::new(Semaphore::new(max_connections.max(1))) }
    }
}

/// A TCP stream that holds a connection permit for its whole lifetime.
#[derive(Debug)]
pub struct PermitStream {
    inner: TcpStream,
    _permit: OwnedSemaphorePermit,
}

impl AsyncRead for PermitStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PermitStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl<S> Accept<TcpStream, S> for LimitAcceptor {
    type Stream = PermitStream;
    type Service = S;
    type Future = Ready<io::Result<(PermitStream, S)>>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        match self.sem.clone().try_acquire_owned() {
            Ok(permit) => {
                let _ = stream.set_nodelay(true);
                ready(Ok((PermitStream { inner: stream, _permit: permit }, service)))
            }
            Err(_) => ready(Err(io::Error::other("connection limit reached"))),
        }
    }
}
