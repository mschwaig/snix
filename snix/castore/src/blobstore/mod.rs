#![deny(missing_docs)]
//! [BlobMeta] storage, used to assemble blobs from more granular Chunks.
use auto_impl::auto_impl;
use tonic::async_trait;

mod blob_meta;
mod blob_reader;
mod blob_writer;

#[cfg(feature = "mocks")]
mod mock_writer;

pub mod combinators;
pub mod grpc;
pub mod memory;
pub mod object_store;

use crate::{
    B3Digest,
    composition::{Registry, ServiceBuilder},
};
pub use blob_meta::BlobMeta;
pub use blob_reader::{BlobReader, LimitBlobReader};
pub use blob_writer::BlobWriter;

#[cfg(feature = "mocks")]
pub use mock_writer::MockWriter;

/// Retrieves and stores [BlobMeta] about Blobs.
/// Blobs can consist of multiple Chunks.
/// Blobs are keyed by the BLAKE3 digest of their entire data.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
#[auto_impl(&, &mut, Arc, Box)]
pub trait BlobStore: Send + Sync {
    /// Retrieves a [BlobMeta] for a given blob digest.
    async fn get(&self, digest: &B3Digest) -> Result<Option<BlobMeta>, Error>;

    /// Checks if a [BlobMeta] for a given blob exists.
    async fn has(&self, digest: &B3Digest) -> Result<bool, Error>;

    /// Persists a [BlobMeta] for the given blob digest.
    async fn put(&self, digest: &B3Digest, blob_meta: BlobMeta) -> Result<(), Error>;
}

/// Error returned from all BlobStores.
///
/// Usually boxes an inner, more backend-specific error.
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct Error(#[from] Box<dyn std::error::Error + Send + Sync + 'static>);

/// Registers the builtin [BlobStore]s with the registry.
pub(crate) fn register_blob_stores(reg: &mut Registry) {
    reg.register::<Box<dyn ServiceBuilder<Output = dyn BlobStore>>, combinators::CacheConfig>(
        "cache",
    );
    reg.register::<Box<dyn ServiceBuilder<Output = dyn BlobStore>>, grpc::GRPCBlobStoreConfig>(
        "grpc",
    );
    reg.register::<Box<dyn ServiceBuilder<Output = dyn BlobStore>>, memory::MemoryBlobStoreConfig>(
        "memory",
    );
    reg.register::<Box<dyn ServiceBuilder<Output = dyn BlobStore>>, object_store::ObjectStoreBlobStoreConfig>("objectstore");
    reg.register::<Box<dyn ServiceBuilder<Output = dyn BlobStore>>, combinators::PriorityConfig>(
        "priority",
    );
    reg.register::<Box<dyn ServiceBuilder<Output = dyn BlobStore>>, combinators::RaceConfig>(
        "race",
    );
}

/// A [tokio::io::AsyncWrite] that the user needs to close() afterwards to persist.
/// On success, it returns the digest of the written blob.
#[async_trait]
pub trait Writer: tokio::io::AsyncWrite + Send + Unpin {
    /// Signal there's no more data to be written, and return the digest of the
    /// contents written.
    ///
    /// Closing an already-closed BlobWriter is a no-op.
    async fn close(&mut self) -> std::io::Result<crate::B3Digest>;
}

/// BlobReader is a [tokio::io::AsyncRead] that also allows seeking.
pub trait Reader:
    tokio::io::AsyncRead + tokio::io::AsyncSeek + std::any::Any + Send + Unpin
{
}
