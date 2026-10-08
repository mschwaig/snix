//! A [super::Writer] that can be used for tests

use tonic::async_trait;

use crate::{B3Digest, blobstore::Writer};

/// Implements [super::Writer] and panics if the expected data wasn't written on close.
pub struct MockWriter {
    hasher: parking_lot::RwLock<blake3::Hasher>,
    expected_digest: B3Digest,
    closed: bool,
}

impl MockWriter {
    /// Constructs a new [MockWriter] expecting the passed digest.
    pub fn new(expected_digest: B3Digest) -> Self {
        Self {
            hasher: Default::default(),
            expected_digest,
            closed: false,
        }
    }
}

impl Drop for MockWriter {
    fn drop(&mut self) {
        // Only panic if the test isn't already panicking for another reason (as in test cases for MockWriter itself)
        if !self.closed && !std::thread::panicking() {
            panic!(
                "MockWriter with expected digest {} was not closed",
                self.expected_digest
            );
        }
    }
}

impl tokio::io::AsyncWrite for MockWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.closed {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "already closed",
            )));
        }
        self.hasher.write().update(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl Writer for MockWriter {
    async fn close(&mut self) -> std::io::Result<crate::B3Digest> {
        let actual_digest: B3Digest = self.hasher.read().finalize().into();

        if self.expected_digest != actual_digest {
            panic!(
                "unexpected digest {} encountered, expected {}",
                actual_digest, self.expected_digest
            )
        }

        self.closed = true;

        Ok(actual_digest)
    }
}

#[cfg(test)]
mod test {
    use tokio::io::AsyncWriteExt;

    use super::MockWriter;
    use crate::{blobstore::Writer, chunkstore::Chunk};

    #[tokio::test]
    async fn ok() {
        let digest = Chunk::from_static(b"foo").digest();
        let mut mock_writer = MockWriter::new(digest);
        mock_writer
            .write_all(b"foo")
            .await
            .expect("write to succeed");

        let actual_digest = mock_writer.close().await.expect("close to succeed");
        assert_eq!(
            digest, actual_digest,
            "expect returned digest to match data written into"
        );
    }

    #[tokio::test]
    #[should_panic]
    async fn panic_wrong_data_written() {
        let digest = Chunk::from_static(b"foo").digest();
        let mut mock_writer = MockWriter::new(digest);
        mock_writer
            .write_all(b"bar")
            .await
            .expect("write to succeed");

        // panics
        let _ = mock_writer.close().await;
    }

    #[tokio::test]
    #[should_panic]
    async fn panic_drop_without_close() {
        let digest = Chunk::from_static(b"foo").digest();
        let mut mock_writer = MockWriter::new(digest);
        mock_writer
            .write_all(b"foo")
            .await
            .expect("write to succeed");

        // panics on drop
        drop(mock_writer)
    }
}
