use futures::StreamExt;
use std::io::{self, Cursor};

use crate::{
    B3Digest,
    blobstore::BlobMeta,
    chunkstore::{Chunk, ChunkStore},
};

impl BlobMeta {
    /// Returns a stream of bytes of actual blob bytes.
    ///
    /// Both a start_offset and a size limit to read can be specified.
    ///
    /// `start_offset` must be inside the range of the blob.
    /// If `limit_size` is set, the last element in the stream will contain a chunk with truncated data.
    /// If `limit_size` would point past the end of the blob, it's clamped to the end.
    ///
    /// Chunks not part of that range are skipped entirely.
    /// The returned Cursor into the first chunk is advanced to the desired start_offset.
    ///
    /// Queries the passed ChunkStore, with configurable concurrency.
    pub fn bytes_stream(
        &self,
        start_offset: u64,
        limit_size: Option<u64>,
        fetch_concurrency: usize,
        chunk_store: impl ChunkStore + Clone + 'static,
    ) -> impl futures::Stream<Item = std::io::Result<Cursor<Chunk>>> + 'static {
        // Calculate the range of chunks we want to iterate over

        // The index of the chunk to start with, and the number of bytes to skip from the front of it.
        let (start_idx, skip_from_first) = self.chunk_idx_from(start_offset);

        // specifies the position in the blob that is just outside the range
        let end = if let Some(size) = limit_size {
            start_offset
                .checked_add(size)
                .expect("offset + size overlows u64::MAX")
                .min(self.blob_len())
        } else {
            self.blob_len()
        };

        // Calculate the last chunk idx that holds our data,
        // and how many bytes from there we want to include.
        let (end_idx, len_last) = self.chunk_idx_until(end);

        let chunk_metas = self.chunk_metas.clone();

        // produce a stream of byte chunks, if the range is not empty
        let chunk_idxs = (start_offset < end)
            .then_some(start_idx..=end_idx)
            .into_iter()
            .flatten();

        tokio_stream::iter(chunk_idxs)
            .map(move |i| {
                let start_pos = if i == start_idx { skip_from_first } else { 0 };

                // get a cursor over the chunk, seeked to start_pos
                fetch_chunk_and_seek(
                    chunk_metas[i].digest,
                    start_pos,
                    (i == end_idx).then_some(len_last),
                    chunk_store.clone(),
                )
            })
            .buffered(fetch_concurrency)
    }
}

/// Fetches a Chunk, wraps it in a Cursor and seeks to the specified position, optionally truncating to a size.
async fn fetch_chunk_and_seek(
    chunk_digest: B3Digest,
    start_pos: u64,
    truncate_size: Option<u64>,
    chunk_store: impl ChunkStore,
) -> io::Result<Cursor<Chunk>> {
    let chunk = chunk_store
        .get(&chunk_digest)
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("chunk {0} not found", chunk_digest),
            )
        })?;

    let chunk_len = chunk.len();

    let chunk = if let Some(s) = truncate_size {
        debug_assert!(
            chunk_len as u64 >= s,
            "Snix bug: truncate_size is larger than chunk_len"
        );
        Chunk::from(bytes::Bytes::from(chunk).slice(0..s as usize))
    } else {
        chunk
    };

    let mut cursor = Cursor::new(chunk);

    // Set the chunk position
    if start_pos > 0 {
        debug_assert!(
            chunk_len as u64 > start_pos,
            "Snix bug: chunk size is smaller than bytes to skip"
        );
        cursor.set_position(start_pos);
    }

    Ok::<_, io::Error>(cursor)
}

#[cfg(test)]
mod test {
    use std::{
        io::Cursor,
        sync::{Arc, LazyLock},
    };

    use futures::TryStreamExt;
    use mockall::predicate;

    use crate::{
        blobstore::BlobMeta,
        chunkstore::{Chunk, MockChunkStore},
    };

    const CHUNK_1: Chunk = Chunk::from_static(b"ab");
    const CHUNK_2: Chunk = Chunk::from_static(b"c");
    const CHUNK_3: Chunk = Chunk::from_static(b"de");
    static BLOB_1_META: LazyLock<BlobMeta> = LazyLock::new(|| {
        BlobMeta::from_digests_and_sizes([
            (CHUNK_1.digest(), CHUNK_1.len() as u64),
            (CHUNK_2.digest(), CHUNK_2.len() as u64),
        ])
    });
    static BLOB_2_META: LazyLock<BlobMeta> = LazyLock::new(|| {
        BlobMeta::from_digests_and_sizes([
            (CHUNK_1.digest(), CHUNK_1.len() as u64),
            (CHUNK_2.digest(), CHUNK_2.len() as u64),
            (CHUNK_3.digest(), CHUNK_3.len() as u64),
        ])
    });

    async fn collect_chunks(
        s: impl futures::Stream<Item = std::io::Result<Cursor<Chunk>>>,
    ) -> Vec<Vec<u8>> {
        s.map_ok(|c| c.get_ref().as_ref()[c.position() as usize..].to_vec())
            .try_collect()
            .await
            .expect("to not fail")
    }

    /// Sets offset to the beginning of the second chunk, ensures the first chunk is not fetched.
    #[tokio::test]
    async fn chunked_get_skip() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store
            .expect_get()
            .with(predicate::eq(CHUNK_2.digest()))
            .return_once(|_| Ok(Some(CHUNK_2.to_owned())));

        let chunks =
            collect_chunks((*BLOB_1_META).bytes_stream(2, None, 10, Arc::new(chunk_store))).await;

        assert_eq!(vec![b"c".to_vec()], chunks);
    }

    /// Skip the first byte in the first chunk
    #[tokio::test]
    async fn chunked_skip_one_byte() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store
            .expect_get()
            .returning(|digest| {
                if *digest == CHUNK_1.digest() {
                    Ok(Some(CHUNK_1.to_owned()))
                } else if *digest == CHUNK_2.digest() {
                    Ok(Some(CHUNK_2.to_owned()))
                } else {
                    panic!("called with unexpected digest")
                }
            })
            .times(2);

        let chunks =
            collect_chunks((*BLOB_1_META).bytes_stream(1, None, 10, Arc::new(chunk_store))).await;
        assert_eq!(vec![b"b".to_vec(), b"c".to_vec()], chunks, "data to match");
    }

    /// Skip to the end
    #[tokio::test]
    async fn chunked_skip_end() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store.expect_get().never();

        let chunks =
            collect_chunks((*BLOB_1_META).bytes_stream(3, None, 10, Arc::new(chunk_store))).await;
        assert_eq!(Vec::<Vec<u8>>::new(), chunks, "data to match");
    }

    #[tokio::test]
    async fn read_empty() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store.expect_get().never();

        let blob_meta = BlobMeta::from_digests_and_sizes([]);
        let chunks =
            collect_chunks(blob_meta.bytes_stream(0, None, 10, Arc::new(chunk_store))).await;

        assert_eq!(Vec::<Vec<u8>>::new(), chunks, "data to match");
    }

    #[tokio::test]
    async fn read_right_at_end_empty() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store.expect_get().never();
        let chunk_store = Arc::new(chunk_store);

        for (start_offset, size) in [(3, None), (3, Some(1))] {
            let chunks = collect_chunks(BLOB_1_META.bytes_stream(
                start_offset,
                size,
                10,
                Arc::new(chunk_store.clone()),
            ))
            .await;

            assert_eq!(0, chunks.len(), "expect 0 chunks");
        }
    }

    #[tokio::test]
    #[should_panic]
    async fn offset_past_end_panic() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store.expect_get().never();
        let mut stream = BLOB_1_META.bytes_stream(4, None, 10, Arc::new(chunk_store));
        let _ = stream.try_next().await;
    }

    #[tokio::test]
    async fn size_past_end_clamp() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store
            .expect_get()
            .returning(|digest| {
                if *digest == CHUNK_1.digest() {
                    Ok(Some(CHUNK_1.to_owned()))
                } else if *digest == CHUNK_2.digest() {
                    Ok(Some(CHUNK_2.to_owned()))
                } else {
                    panic!("called with unexpected digest")
                }
            })
            .times(2);
        let chunks =
            collect_chunks(BLOB_1_META.bytes_stream(1, Some(20), 10, Arc::new(chunk_store))).await;
        let data = chunks.iter().fold(vec![], |mut i, e| {
            i.extend_from_slice(e);
            i
        });
        assert_eq!(b"bc", &data[..], "expect data to match")
    }

    #[tokio::test]
    async fn size_actually_limits() {
        let mut chunk_store = MockChunkStore::new();
        chunk_store
            .expect_get()
            .with(predicate::eq(CHUNK_1.digest()))
            .return_once(|_| Ok(Some(CHUNK_1.to_owned())));
        let chunks =
            collect_chunks(BLOB_1_META.bytes_stream(0, Some(1), 10, Arc::new(chunk_store))).await;
        let data = chunks.iter().fold(vec![], |mut i, e| {
            i.extend_from_slice(e);
            i
        });
        assert_eq!(b"a", &data[..], "expect data to match")
    }

    use proptest::prelude::*;
    proptest! {
        /// Reads various subslices from BLOB_2 (5 bytes) and ensures they come back correctly.
        #[test]
        fn test_start_end_offsets(
            // start
            start_offset in 0usize..5,
            // end
            size in 0usize..5
        ) {
            let blob_2_data = b"abcde";
            // skip too large sizes
            if start_offset + size > blob_2_data.len() {
                return Ok(());
            }

            let mut chunk_store = MockChunkStore::new();
            chunk_store
                .expect_get()
                .returning(|digest| {
                    if *digest == CHUNK_1.digest() {
                        Ok(Some(CHUNK_1.to_owned()))
                    } else if *digest == CHUNK_2.digest() {
                        Ok(Some(CHUNK_2.to_owned()))
                    } else if *digest == CHUNK_3.digest() {
                        Ok(Some(CHUNK_3.to_owned()))
                    } else {
                        panic!("called with unexpected digest")
                    }
                });

            let tokio_runtime = tokio::runtime::Runtime::new().expect("to construct runtime");
            tokio_runtime.block_on(async {
                let stream = BLOB_2_META.bytes_stream(start_offset as u64, Some(size as u64), 10, Arc::new(chunk_store));
                let mut reader = tokio_util::io::StreamReader::new(stream);

                let mut buf = Vec::new();
                use tokio::io::AsyncReadExt;
                reader.read_to_end(&mut buf).await.expect("read to succeed");
                assert_eq!(size, buf.len(), "expect size to match");
                assert_eq!(&&blob_2_data[start_offset..start_offset + size], &buf.as_slice(), "expect data to be equal");
            });
        }
    }
}
