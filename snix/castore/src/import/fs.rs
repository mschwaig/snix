//! Import from a real filesystem.

use futures::StreamExt;
use futures::stream::BoxStream;
use std::fs::FileType;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use tokio::io::BufReader;
use tokio_util::io::InspectReader;
use tracing::Instrument;
use tracing::Span;
use tracing::info_span;
use tracing::instrument;
use tracing_indicatif::span_ext::IndicatifSpanExt;
use walkdir::DirEntry;
use walkdir::WalkDir;

use crate::blobservice::BlobService;
use crate::directoryservice::DirectoryService;
use crate::refscan::{
    ReferenceReader, ReferenceScanner, RewritePattern, RewritingReferenceReader, rewrite_in_place,
};
use crate::{B3Digest, Node};

use super::IngestionEntry;
use super::IngestionError;
use super::ingest_entries;

/// Ingests the contents at a given path into the snix store, interacting with a [BlobService] and
/// [DirectoryService]. It returns the root node or an error.
///
/// It does not follow symlinks at the root, they will be ingested as actual symlinks.
///
/// This function will walk the filesystem using `walkdir` and will consume
/// `O(#number of entries)` space.
#[instrument(
    skip(blob_service, directory_service, reference_scanner),
    fields(path),
    err
)]
pub async fn ingest_path<BS, DS, P, P2>(
    blob_service: BS,
    directory_service: DS,
    path: P,
    reference_scanner: Option<&ReferenceScanner<P2>>,
) -> Result<Node, IngestionError<Error>>
where
    P: AsRef<std::path::Path> + std::fmt::Debug,
    BS: BlobService + Clone,
    DS: DirectoryService,
    P2: AsRef<[u8]> + Send + Sync,
{
    let span = Span::current();

    let iter = WalkDir::new(path.as_ref())
        .follow_links(false)
        .follow_root_links(false)
        .contents_first(true)
        .into_iter();

    let entries =
        dir_entries_to_ingestion_stream(blob_service, iter, path.as_ref(), reference_scanner);
    ingest_entries(
        directory_service,
        entries.inspect({
            let span = span.clone();
            move |e| {
                if e.is_ok() {
                    span.pb_inc(1)
                }
            }
        }),
    )
    .await
}

/// Converts an iterator of [walkdir::DirEntry]s into a stream of ingestion entries.
/// This can then be fed into [ingest_entries] to ingest all the entries into the castore.
///
/// The produced stream is buffered, so uploads can happen concurrently.
///
/// The root is the [std::path::Path] in the filesystem that is being ingested
/// into castore.
pub fn dir_entries_to_ingestion_stream<'a, BS, I, P>(
    blob_service: BS,
    iter: I,
    root: &'a std::path::Path,
    reference_scanner: Option<&'a ReferenceScanner<P>>,
) -> BoxStream<'a, Result<IngestionEntry, Error>>
where
    BS: BlobService + Clone + 'a,
    I: Iterator<Item = Result<DirEntry, walkdir::Error>> + Send + 'a,
    P: AsRef<[u8]> + Send + Sync,
{
    let prefix = root.parent().unwrap_or_else(|| std::path::Path::new(""));

    Box::pin(
        futures::stream::iter(iter)
            .map(move |x| {
                let blob_service = blob_service.clone();
                async move {
                    match x {
                        Ok(dir_entry) => {
                            dir_entry_to_ingestion_entry(
                                blob_service,
                                &dir_entry,
                                prefix,
                                reference_scanner,
                            )
                            .await
                        }
                        Err(e) => Err(Error::Stat(
                            prefix.to_path_buf(),
                            e.into_io_error().expect("walkdir err must be some"),
                        )),
                    }
                }
            })
            .buffered(50),
    )
}

/// Converts a [walkdir::DirEntry] into an [IngestionEntry], uploading blobs to the
/// provided [BlobService].
///
/// The prefix path is stripped from the path of each entry. This is usually the parent path
/// of the path being ingested so that the last element of the stream only has one component.
pub async fn dir_entry_to_ingestion_entry<BS, P>(
    blob_service: BS,
    entry: &DirEntry,
    prefix: &std::path::Path,
    reference_scanner: Option<&ReferenceScanner<P>>,
) -> Result<IngestionEntry, Error>
where
    BS: BlobService,
    P: AsRef<[u8]>,
{
    let file_type = entry.file_type();

    let fs_path = entry
        .path()
        .strip_prefix(prefix)
        .expect("Snix bug: failed to strip root path prefix");

    // convert to castore PathBuf
    let path = crate::path::PathBuf::from_host_path(fs_path, false)
        .unwrap_or_else(|e| panic!("Snix bug: walkdir direntry cannot be parsed: {}", e));

    if file_type.is_dir() {
        Ok(IngestionEntry::Dir { path })
    } else if file_type.is_symlink() {
        let target = std::fs::read_link(entry.path())
            .map_err(|e| Error::Stat(entry.path().to_path_buf(), e))?
            .into_os_string()
            .into_vec();

        if let Some(reference_scanner) = &reference_scanner {
            reference_scanner.scan(&target);
        }

        Ok(IngestionEntry::Symlink { path, target })
    } else if file_type.is_file() {
        let metadata = entry
            .metadata()
            .map_err(|e| Error::Stat(entry.path().to_path_buf(), e.into()))?;

        let digest = upload_blob(blob_service, entry.path().to_path_buf(), reference_scanner)
            .instrument({
                let span = info_span!("upload_blob", "indicatif.pb_show" = tracing::field::Empty);
                span.pb_set_message(&format!("Uploading blob for {:?}", fs_path));
                span.pb_set_style(&snix_tracing::PB_TRANSFER_STYLE);

                span
            })
            .await?;

        Ok(IngestionEntry::Regular {
            path,
            size: metadata.size(),
            // If it's executable by the user, it'll become executable.
            // This matches nix's dump() function behaviour.
            executable: metadata.permissions().mode() & 64 != 0,
            digest,
        })
    } else {
        return Err(Error::FileType(fs_path.to_path_buf(), file_type));
    }
}

/// Uploads the file at the provided [std::path::Path] the the [BlobService].
#[instrument(skip(blob_service, reference_scanner), fields(path), err)]
async fn upload_blob<BS, P>(
    blob_service: BS,
    path: impl AsRef<std::path::Path>,
    reference_scanner: Option<&ReferenceScanner<P>>,
) -> Result<B3Digest, Error>
where
    BS: BlobService,
    P: AsRef<[u8]>,
{
    let span = Span::current();
    span.pb_start();

    let file = tokio::fs::File::open(path.as_ref())
        .await
        .map_err(|e| Error::BlobRead(path.as_ref().to_path_buf(), e))?;

    let metadata = file
        .metadata()
        .await
        .map_err(|e| Error::Stat(path.as_ref().to_path_buf(), e))?;

    span.pb_set_length(metadata.len());
    let reader = InspectReader::new(file, |d| {
        span.pb_inc(d.len() as u64);
    });

    let mut writer = blob_service.open_write().await;
    if let Some(reference_scanner) = reference_scanner {
        let mut reader = ReferenceReader::new(reference_scanner, BufReader::new(reader));
        tokio::io::copy(&mut reader, &mut writer)
            .await
            .map_err(|e| Error::BlobRead(path.as_ref().to_path_buf(), e))?;
    } else {
        tokio::io::copy(&mut BufReader::new(reader), &mut writer)
            .await
            .map_err(|e| Error::BlobRead(path.as_ref().to_path_buf(), e))?;
    }

    let digest = writer
        .close()
        .await
        .map_err(|e| Error::BlobFinalize(path.as_ref().to_path_buf(), e))?;

    Ok(digest)
}

/// Parallel to [`ingest_path`] but routes file contents and symlink targets
/// through a [`RewritePattern`], substituting matched needles with their
/// replacement bytes before they enter the castore.
///
/// Built for the constructive trace flow: rewrite input-addressed store-path
/// hash references to the corresponding content-addressed equivalents while
/// ingesting an output, so the resulting castore [`Node`] reflects the
/// rewritten content directly. Rewrites are length-preserving (see
/// [`RewritePattern::new`]), so the [`IngestionEntry::Regular::size`] taken
/// from the on-disk metadata stays correct.
#[instrument(skip(blob_service, directory_service, rewrite_pattern), fields(path), err)]
pub async fn ingest_path_with_rewrites<BS, DS, P, P2>(
    blob_service: BS,
    directory_service: DS,
    path: P,
    rewrite_pattern: &RewritePattern<P2>,
) -> Result<Node, IngestionError<Error>>
where
    P: AsRef<std::path::Path> + std::fmt::Debug,
    BS: BlobService + Clone,
    DS: DirectoryService,
    P2: AsRef<[u8]> + Send + Sync,
{
    let span = Span::current();

    let iter = WalkDir::new(path.as_ref())
        .follow_links(false)
        .follow_root_links(false)
        .contents_first(true)
        .into_iter();

    let entries = dir_entries_to_ingestion_stream_with_rewrites(
        blob_service,
        iter,
        path.as_ref(),
        rewrite_pattern,
    );
    ingest_entries(
        directory_service,
        entries.inspect({
            let span = span.clone();
            move |e| {
                if e.is_ok() {
                    span.pb_inc(1)
                }
            }
        }),
    )
    .await
}

/// Rewriting counterpart of [`dir_entries_to_ingestion_stream`].
pub fn dir_entries_to_ingestion_stream_with_rewrites<'a, BS, I, P>(
    blob_service: BS,
    iter: I,
    root: &'a std::path::Path,
    rewrite_pattern: &'a RewritePattern<P>,
) -> BoxStream<'a, Result<IngestionEntry, Error>>
where
    BS: BlobService + Clone + 'a,
    I: Iterator<Item = Result<DirEntry, walkdir::Error>> + Send + 'a,
    P: AsRef<[u8]> + Send + Sync,
{
    let prefix = root.parent().unwrap_or_else(|| std::path::Path::new(""));

    Box::pin(
        futures::stream::iter(iter)
            .map(move |x| {
                let blob_service = blob_service.clone();
                async move {
                    match x {
                        Ok(dir_entry) => {
                            dir_entry_to_ingestion_entry_with_rewrites(
                                blob_service,
                                &dir_entry,
                                prefix,
                                rewrite_pattern,
                            )
                            .await
                        }
                        Err(e) => Err(Error::Stat(
                            prefix.to_path_buf(),
                            e.into_io_error().expect("walkdir err must be some"),
                        )),
                    }
                }
            })
            .buffered(50),
    )
}

/// Rewriting counterpart of [`dir_entry_to_ingestion_entry`].
pub async fn dir_entry_to_ingestion_entry_with_rewrites<BS, P>(
    blob_service: BS,
    entry: &DirEntry,
    prefix: &std::path::Path,
    rewrite_pattern: &RewritePattern<P>,
) -> Result<IngestionEntry, Error>
where
    BS: BlobService,
    P: AsRef<[u8]>,
{
    let file_type = entry.file_type();

    let fs_path = entry
        .path()
        .strip_prefix(prefix)
        .expect("Snix bug: failed to strip root path prefix");

    let path = crate::path::PathBuf::from_host_path(fs_path, false)
        .unwrap_or_else(|e| panic!("Snix bug: walkdir direntry cannot be parsed: {}", e));

    if file_type.is_dir() {
        Ok(IngestionEntry::Dir { path })
    } else if file_type.is_symlink() {
        let mut target = std::fs::read_link(entry.path())
            .map_err(|e| Error::Stat(entry.path().to_path_buf(), e))?
            .into_os_string()
            .into_vec();

        let _ = rewrite_in_place(rewrite_pattern, &mut target, 0);

        Ok(IngestionEntry::Symlink { path, target })
    } else if file_type.is_file() {
        let metadata = entry
            .metadata()
            .map_err(|e| Error::Stat(entry.path().to_path_buf(), e.into()))?;

        let digest = upload_blob_with_rewrites(
            blob_service,
            entry.path().to_path_buf(),
            rewrite_pattern,
        )
        .instrument({
            let span = info_span!("upload_blob", "indicatif.pb_show" = tracing::field::Empty);
            span.pb_set_message(&format!("Uploading blob for {:?}", fs_path));
            span.pb_set_style(&snix_tracing::PB_TRANSFER_STYLE);

            span
        })
        .await?;

        Ok(IngestionEntry::Regular {
            path,
            size: metadata.size(),
            executable: metadata.permissions().mode() & 64 != 0,
            digest,
        })
    } else {
        return Err(Error::FileType(fs_path.to_path_buf(), file_type));
    }
}

/// Rewriting counterpart of `upload_blob`: streams the on-disk file through
/// [`RewritingReferenceReader`] so the blob written into the service contains
/// the rewritten bytes.
#[instrument(skip(blob_service, rewrite_pattern), fields(path), err)]
async fn upload_blob_with_rewrites<BS, P>(
    blob_service: BS,
    path: impl AsRef<std::path::Path>,
    rewrite_pattern: &RewritePattern<P>,
) -> Result<B3Digest, Error>
where
    BS: BlobService,
    P: AsRef<[u8]>,
{
    let span = Span::current();
    span.pb_start();

    let file = tokio::fs::File::open(path.as_ref())
        .await
        .map_err(|e| Error::BlobRead(path.as_ref().to_path_buf(), e))?;

    let metadata = file
        .metadata()
        .await
        .map_err(|e| Error::Stat(path.as_ref().to_path_buf(), e))?;

    span.pb_set_length(metadata.len());
    let reader = InspectReader::new(file, |d| {
        span.pb_inc(d.len() as u64);
    });

    let mut writer = blob_service.open_write().await;
    let mut reader = RewritingReferenceReader::new(rewrite_pattern, BufReader::new(reader));
    tokio::io::copy(&mut reader, &mut writer)
        .await
        .map_err(|e| Error::BlobRead(path.as_ref().to_path_buf(), e))?;

    let digest = writer
        .close()
        .await
        .map_err(|e| Error::BlobFinalize(path.as_ref().to_path_buf(), e))?;

    Ok(digest)
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unsupported file type at {0}: {1:?}")]
    FileType(std::path::PathBuf, FileType),

    #[error("unable to stat {0}: {1}")]
    Stat(std::path::PathBuf, std::io::Error),

    #[error("unable to open {0}: {1}")]
    Open(std::path::PathBuf, std::io::Error),

    #[error("unable to read {0}: {1}")]
    BlobRead(std::path::PathBuf, std::io::Error),

    // TODO: proper error for blob finalize
    #[error("unable to finalize blob {0}: {1}")]
    BlobFinalize(std::path::PathBuf, std::io::Error),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::blobservice::{BlobService, MemoryBlobService};
    use crate::directoryservice::MemoryDirectoryService;
    use crate::refscan::{RewriteEntry, RewritePattern};

    fn rewrite_entry(needle: &'static str, replacement: &'static [u8]) -> RewriteEntry<&'static str> {
        RewriteEntry {
            needle,
            replacement: replacement.to_vec(),
            record_positions: false,
        }
    }

    #[tokio::test]
    async fn ingest_path_with_rewrites_substitutes_file_and_symlink() {
        // Simulate a tiny store path: one regular file containing a needle,
        // one symlink whose target contains a needle. Confirm both end up
        // rewritten in the resulting castore tree.
        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();

        let file_path = root.join("file.txt");
        std::fs::write(
            &file_path,
            b"prefix /nix/store/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-foo suffix",
        )
        .unwrap();

        let symlink_path = root.join("link");
        symlink(
            "/nix/store/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB-bar",
            &symlink_path,
        )
        .unwrap();

        let pattern: RewritePattern<&str> = RewritePattern::new(vec![
            rewrite_entry(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                b"11111111111111111111111111111111",
            ),
            rewrite_entry(
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
                b"22222222222222222222222222222222",
            ),
        ]);

        let blob_service = MemoryBlobService::default();
        let directory_service = MemoryDirectoryService::default();

        let root_node = ingest_path_with_rewrites(
            blob_service.clone(),
            directory_service.clone(),
            &root,
            &pattern,
        )
        .await
        .expect("ingest must succeed");

        // The root is a directory; walk its single Directory record to
        // confirm both entries are rewritten.
        let dir_digest = match root_node {
            Node::Directory { digest, .. } => digest,
            other => panic!("expected root directory, got {:?}", other),
        };
        let directory = directory_service
            .get(&dir_digest)
            .await
            .expect("dir lookup")
            .expect("dir present");

        let (mut file_seen, mut symlink_seen) = (false, false);
        for (name, node) in directory.nodes() {
            match node {
                Node::File { digest, size, .. } => {
                    assert_eq!(name.as_ref(), b"file.txt");
                    let mut blob_reader = blob_service
                        .open_read(&digest)
                        .await
                        .expect("blob lookup")
                        .expect("blob present");
                    let mut bytes = Vec::new();
                    blob_reader.read_to_end(&mut bytes).await.unwrap();
                    let s = std::str::from_utf8(&bytes).unwrap();
                    assert!(s.contains("/nix/store/11111111111111111111111111111111-foo"));
                    assert!(!s.contains("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
                    assert_eq!(*size as usize, bytes.len(), "size matches rewritten blob");
                    file_seen = true;
                }
                Node::Symlink { target } => {
                    assert_eq!(name.as_ref(), b"link");
                    let target = std::str::from_utf8(target.as_ref()).unwrap();
                    assert_eq!(
                        target,
                        "/nix/store/22222222222222222222222222222222-bar"
                    );
                    symlink_seen = true;
                }
                Node::Directory { .. } => panic!("no subdirs expected"),
            }
        }
        assert!(file_seen && symlink_seen);
    }

    #[tokio::test]
    async fn ingest_path_with_rewrites_no_op_with_empty_pattern() {
        // An empty RewritePattern must produce a castore tree identical to
        // what plain ingest_path produces.
        let dir = tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("a"), b"plain bytes").unwrap();

        let blob_service_plain = MemoryBlobService::default();
        let directory_service_plain = MemoryDirectoryService::default();
        let plain = ingest_path::<_, _, _, &[u8]>(
            blob_service_plain.clone(),
            directory_service_plain.clone(),
            &root,
            None,
        )
        .await
        .expect("plain ingest");

        let pattern: RewritePattern<&str> = RewritePattern::new(Vec::new());
        let blob_service_rw = MemoryBlobService::default();
        let directory_service_rw = MemoryDirectoryService::default();
        let rewritten = ingest_path_with_rewrites(
            blob_service_rw.clone(),
            directory_service_rw.clone(),
            &root,
            &pattern,
        )
        .await
        .expect("rewriting ingest with empty pattern");

        assert_eq!(plain, rewritten);
    }
}
