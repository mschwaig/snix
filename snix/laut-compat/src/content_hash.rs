//! This module provides functions to calculate
//! NAR hashes and castore entries for store paths.

use nix_compat::nixbase32;
use nix_compat::nixhash::{HashAlgo, NixHash};
use nix_compat::store_path::{StorePath, StorePathName, build_ca_path};
use sha2::{Digest, Sha256};
use snix_castore::Node;
use snix_castore::blob_engine::ChunkingBlobEngine;
use snix_castore::blobstore::memory::MemoryBlobStore;
use snix_castore::chunkstore::memory::MemoryChunkStore;
use snix_castore::directoryservice::{RedbDirectoryService, RedbDirectoryServiceConfig};
use snix_castore::import::fs::{ingest_path, ingest_path_with_rewrites};
use snix_castore::refscan::{ReferenceScanner, RewriteEntry, RewritePattern, rewrite_in_place};
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::Path;
use std::sync::Arc;

/// Error type for hash calculation
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

/// Common functionality to create a runtime and ingest a path for hashing
type MemoryBlobEngine = Arc<ChunkingBlobEngine<MemoryBlobStore, MemoryChunkStore>>;

fn memory_blob_engine() -> MemoryBlobEngine {
    Arc::new(
        ChunkingBlobEngine::builder()
            .blob_store(MemoryBlobStore::default())
            .chunk_store(MemoryChunkStore::default())
            .build(),
    )
}

async fn memory_directory_service() -> Result<RedbDirectoryService, HashError> {
    RedbDirectoryService::new("laut-hash".into(), RedbDirectoryServiceConfig::default())
        .await
        .map_err(|e| io::Error::other(e.to_string()).into())
}

async fn prepare_for_hashing(
    path: &Path,
) -> Result<(MemoryBlobEngine, RedbDirectoryService, Node), HashError> {
    // Create memory services that don't persist anything
    let blob_service = memory_blob_engine();
    let directory_service = memory_directory_service().await?;

    // Ingest the path into the memory services
    let root_node =
        ingest_path::<_, _, _, &[u8]>(blob_service.clone(), directory_service.clone(), path, None)
            .await
            .map_err(|e| HashError::IoError(io::Error::other(e.to_string())))?;

    Ok((blob_service, directory_service, root_node))
}

/// Creates a Tokio runtime suitable for hash calculations
fn create_hash_runtime() -> Result<tokio::runtime::Runtime, HashError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(HashError::IoError)
}

/// Calculates the NAR hash of a path.
///
/// This function computes the cryptographic hash of a path's NAR serialization.
/// NAR (Nix ARchive) is a content-addressed archive format used by Nix.
///
/// # Arguments
///
/// * `path` - The path to hash
/// * `algo` - The hash algorithm to use (defaults to SHA256 if None)
///
/// # Returns
///
/// * On success, returns a tuple with the NAR hash and the size of the NAR in bytes
/// * On failure, returns a `HashError`
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use laut_compat::content_hash::{calculate_nar_hash, format_nar_hash};
/// use nix_compat::nixhash::HashAlgo;
///
/// let path = Path::new("/nix/store/9bwryidal9q3g91cjm6xschfn4ikd82q-hello-2.12.1");
/// let (hash, size) = calculate_nar_hash(path, Some(HashAlgo::Sha256)).unwrap();
/// println!("NAR hash: {}", format_nar_hash(&hash));
/// println!("NAR size: {}", size);
/// ```
pub fn calculate_nar_hash(
    path: &Path,
    algo: Option<HashAlgo>,
) -> Result<(NixHash, u64), HashError> {
    use snix_store::nar::{NarCalculationService, Renderer};

    let algo = algo.unwrap_or(HashAlgo::Sha256);
    match algo {
        HashAlgo::Sha256 => {
            // Run the calculation in a runtime
            with_hash_runtime(
                path,
                |blob_service, directory_service, root_node| async move {
                    let renderer = Renderer::new(blob_service, directory_service);

                    // Calculate the NAR hash
                    let (size, hash) = renderer
                        .calculate_nar(&root_node)
                        .await
                        .map_err(|e| HashError::IoError(io::Error::other(e.to_string())))?;

                    Ok::<(NixHash, u64), HashError>((NixHash::Sha256(hash), size))
                },
            )
        }
        // Support for other algorithms can be added here
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "only SHA256 is supported for NAR hashing",
        )
        .into()),
    }
}

/// Create a content-addressed store entry for a path and encode it to a BASE64URL_NOPAD string
///
/// This uses the actual Snix CA store logic to compute a castore Entry for a path,
/// encodes it to bytes, and then applies BASE64URL_NOPAD encoding to create a string.
/// The entry will have an empty name and will contain the node from the path.
///
/// # Arguments
///
/// * `path` - The path to create an entry for
///
/// # Returns
///
/// * On success, returns a BASE64URL_NOPAD encoded string of the entry
/// * On failure, returns a `HashError`
pub fn create_castore_entry(path: &Path) -> Result<String, HashError> {
    // Run the calculation in a runtime
    with_hash_runtime(path, |_, _directory_service, root_node| async move {
        // Create an Entry with an empty name
        let entry = snix_castore::proto::Entry::from_name_and_node("".into(), root_node);

        // Encode the entry to bytes
        let entry_bytes = prost::Message::encode_to_vec(&entry);

        // Encode to BASE64URL_NOPAD
        let encoded = data_encoding::BASE64URL_NOPAD.encode(&entry_bytes);

        Ok::<String, HashError>(encoded)
    })
}

/// Helper to run a computation that needs a runtime and hash inputs
fn with_hash_runtime<F, T, Fut>(path: &Path, f: F) -> Result<T, HashError>
where
    F: FnOnce(MemoryBlobEngine, RedbDirectoryService, Node) -> Fut,
    Fut: std::future::Future<Output = Result<T, HashError>>,
{
    // Create a runtime
    let runtime = create_hash_runtime()?;

    // Run the computation
    runtime.block_on(async {
        // Prepare inputs
        let (blob_service, directory_service, root_node) = prepare_for_hashing(path).await?;

        // Run the provided function
        f(blob_service, directory_service, root_node).await
    })
}

/// Convenience function to format the NAR hash in the Nix-compatible format
///
/// # Arguments
///
/// * `hash` - The NAR hash to format
///
/// # Returns
///
/// * Returns the formatted hash as a string in the format "sha256:<base32-hash>"
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use laut_compat::content_hash::{calculate_nar_hash, format_nar_hash};
///
/// let path = Path::new("/nix/store/9bwryidal9q3g91cjm6xschfn4ikd82q-hello-2.12.1");
/// let (hash, _) = calculate_nar_hash(path, None).unwrap();
/// let formatted_hash = format_nar_hash(&hash);
/// println!("{}", formatted_hash); // Prints: sha256:08za7nnjda8kpdsd73v3mhykjvp0rsmskwsr37winhmzgm6iw79w
/// ```
pub fn format_nar_hash(hash: &NixHash) -> String {
    match hash {
        NixHash::Sha256(digest) => {
            format!("sha256:{}", nixbase32::encode(digest))
        }
        NixHash::Sha1(digest) => {
            format!("sha1:{}", nixbase32::encode(digest))
        }
        NixHash::Sha512(digest) => {
            format!("sha512:{}", nixbase32::encode(digest.as_ref()))
        }
        NixHash::Md5(digest) => {
            format!("md5:{}", nixbase32::encode(digest))
        }
    }
}

/// Length of a nixbase32-encoded store-path hash (160 bits / 5 = 32 chars).
pub const STORE_PATH_HASH_LEN: usize = 32;

/// Build a [`RewritePattern`] over store-path-hash needles. Each entry's
/// needle and replacement must be exactly [`STORE_PATH_HASH_LEN`] ASCII
/// chars; mismatches are rejected as invalid input.
fn rewrite_pattern_from_map(
    deps: &HashMap<String, String>,
) -> Result<RewritePattern<String>, HashError> {
    let mut entries: Vec<RewriteEntry<String>> = Vec::with_capacity(deps.len());
    for (needle, replacement) in deps {
        validate_hash_str(needle)?;
        validate_hash_str(replacement)?;
        entries.push(RewriteEntry {
            needle: needle.clone(),
            replacement: replacement.as_bytes().to_vec(),
            record_positions: false,
        });
    }
    Ok(RewritePattern::new(entries))
}

fn validate_hash_str(s: &str) -> Result<(), HashError> {
    if s.len() != STORE_PATH_HASH_LEN
        || !s
            .bytes()
            .all(|b| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&b))
    {
        return Err(HashError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "store-path hash must be {} nixbase32 chars (got {})",
                STORE_PATH_HASH_LEN,
                s.len()
            ),
        )));
    }
    Ok(())
}

/// Run the snix `ReferenceScanner` over `path`'s blob contents and symlink
/// targets, looking for any of `candidates` (each a 32-char nixbase32
/// store-path hash). Returns the subset of `candidates` that were actually
/// observed in the content.
///
/// Used by the laut IA walker as a defense-in-depth equality check against
/// Nix's stored runtime references (`nix-store -q --references`): the two
/// sets are expected to agree exactly; any divergence is fatal at the
/// verifier.
pub fn scan_for_references(
    path: &Path,
    candidates: &BTreeSet<String>,
) -> Result<BTreeSet<String>, HashError> {
    for c in candidates {
        validate_hash_str(c)?;
    }
    let candidates_vec: Vec<String> = candidates.iter().cloned().collect();
    let path_buf = path.to_path_buf();
    let runtime = create_hash_runtime()?;
    runtime.block_on(async move {
        let blob_service = memory_blob_engine();
        let directory_service = memory_directory_service().await?;
        let scanner: ReferenceScanner<String> = ReferenceScanner::new(candidates_vec);
        ingest_path(blob_service, directory_service, &path_buf, Some(&scanner))
            .await
            .map_err(|e| HashError::IoError(io::Error::other(e.to_string())))?;
        Ok::<BTreeSet<String>, HashError>(scanner.finalise())
    })
}

/// Pass 1 of the IA→CA recursion: ingest `path` with the supplied
/// `deps_rewrites` (IA-hash → synthetic-CA-hash, both 32-char nixbase32 ASCII)
/// applied to file contents and symlink targets, render the resulting castore
/// tree to NAR bytes in memory, apply [Nix's `HashModuloSink`](
/// https://github.com/NixOS/nix/blob/master/src/libstore/references.cc)
/// equivalent over those bytes (zero out occurrences of `self_ia_hash`,
/// recording NAR byte positions), and derive a synthetic Nix CA store path via
/// [`build_ca_path`].
///
/// The result is the synthetic CA store path that downstream consumers would
/// see if this output had been a content-addressed derivation in the first
/// place. It feeds into both the consumer drv's resolved-input-hash
/// (constructive trace) and the pass-2 rewrite map for the same output.
pub fn rewrite_to_ca_pass1(
    path: &Path,
    name: &str,
    deps_rewrites: &HashMap<String, String>,
    self_ia_hash: &str,
    refs_as_ca: &[String],
) -> Result<StorePath, HashError> {
    let pattern = rewrite_pattern_from_map(deps_rewrites)?;
    validate_hash_str(self_ia_hash)?;

    let self_ia_hash_owned = self_ia_hash.to_string();
    let refs_owned: Vec<String> = refs_as_ca.to_vec();
    let name_owned = name.to_string();

    with_hash_runtime_rewriting(
        path,
        pattern,
        move |blob_service, directory_service, root_node| async move {
            let mut nar_bytes: Vec<u8> = Vec::new();
            snix_store::nar::write_nar(
                &mut nar_bytes,
                &root_node,
                &blob_service,
                &directory_service,
            )
            .await
            .map_err(|e| HashError::IoError(io::Error::other(e.to_string())))?;

            let self_mask_pattern = RewritePattern::new(vec![RewriteEntry {
                needle: self_ia_hash_owned,
                replacement: vec![0u8; STORE_PATH_HASH_LEN],
                record_positions: true,
            }]);
            let positions = rewrite_in_place(&self_mask_pattern, &mut nar_bytes, 0);

            // HashModuloSink: SHA256 over the masked NAR bytes, then `|<pos>` for
            // each recorded self-reference position. The trailing positions hash
            // prevents an attacker from constructing a NAR with already-zeroed
            // self-refs that would otherwise collide with the masked legit one.
            let mut hasher = Sha256::new();
            hasher.update(&nar_bytes);
            for pos in &positions {
                hasher.update(format!("|{}", pos).as_bytes());
            }
            let nar_modulo_hash: [u8; 32] = hasher.finalize().into();

            let name = StorePathName::from_str(&name_owned)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            let references = refs_owned
                .iter()
                .map(|r| StorePath::from_absolute_path(r.as_bytes()))
                .collect::<Result<BTreeSet<_>, _>>()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
            Ok(build_ca_path(
                name,
                true,
                &NixHash::Sha256(nar_modulo_hash),
                references.iter().map(StorePath::as_ref),
                !positions.is_empty(),
            )
            .to_owned())
        },
    )
}

/// Output of [`rewrite_to_ca_pass2`]: the BASE64URL_NOPAD castore Entry and
/// the SHA256 NAR hash of the rewritten content, plus its size in bytes.
///
/// The NAR hash is computed over the bytes that would be written to disk for
/// the "as if this output were content-addressed" form (self-ref already
/// substituted to the synthetic CA hash, deps' refs substituted to their
/// synthetic CA hashes). No HashModuloSink masking — that's pass 1's job to
/// derive the CA store-path hash itself; here we want the hash of the real
/// bytes a downstream consumer would see.
pub struct Pass2Result {
    pub castore_entry_base64: String,
    pub nar_hash: NixHash,
    pub nar_size: u64,
}

/// Pass 2 of the IA→CA recursion: ingest `path` with rewrites covering both
/// runtime deps and the output's self-reference (IA-hash → synthetic-CA-hash),
/// then return:
/// - the BASE64URL_NOPAD-encoded castore [`snix_castore::proto::Entry`] of the resulting root
///   node (signed as the per-output content fingerprint), and
/// - the SHA256 NAR hash + size of the rewritten content (stamped into
///   `payload.out.nix[name].hash` so the verifier can recompute it
///   symmetrically — see laut-sign's IA branch).
pub fn rewrite_to_ca_pass2(
    path: &Path,
    rewrites_including_self: &HashMap<String, String>,
) -> Result<Pass2Result, HashError> {
    let pattern = rewrite_pattern_from_map(rewrites_including_self)?;
    with_hash_runtime_rewriting(
        path,
        pattern,
        |blob_service, directory_service, root_node| async move {
            let entry =
                snix_castore::proto::Entry::from_name_and_node("".into(), root_node.clone());
            let entry_bytes = prost::Message::encode_to_vec(&entry);
            let castore_entry_base64 = data_encoding::BASE64URL_NOPAD.encode(&entry_bytes);

            use snix_store::nar::{NarCalculationService, Renderer};
            let (nar_size, nar_hash) = Renderer::new(blob_service, directory_service)
                .calculate_nar(&root_node)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            Ok(Pass2Result {
                castore_entry_base64,
                nar_hash: NixHash::Sha256(nar_hash),
                nar_size,
            })
        },
    )
}

/// Rewriting analog of [`with_hash_runtime`]: spins up an in-memory blob/dir
/// service pair, calls [`ingest_path_with_rewrites`] with the given pattern,
/// then runs the caller-supplied closure with the resulting services + root
/// node.
fn with_hash_runtime_rewriting<F, T, Fut>(
    path: &Path,
    pattern: RewritePattern<String>,
    f: F,
) -> Result<T, HashError>
where
    F: FnOnce(MemoryBlobEngine, RedbDirectoryService, Node) -> Fut,
    Fut: std::future::Future<Output = Result<T, HashError>>,
{
    let runtime = create_hash_runtime()?;
    runtime.block_on(async {
        let blob_service = memory_blob_engine();
        let directory_service = memory_directory_service().await?;
        let root_node = ingest_path_with_rewrites(
            blob_service.clone(),
            directory_service.clone(),
            path,
            &pattern,
        )
        .await
        .map_err(|e| HashError::IoError(io::Error::other(e.to_string())))?;
        f(blob_service, directory_service, root_node).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::Path, path::PathBuf};

    #[test]
    fn test_with_test_files() {
        // Get paths to test files
        let testdata_dir = PathBuf::from("testdata");
        let empty_path = testdata_dir.join("empty");
        let full_path = testdata_dir.join("full");
        let dir_path = testdata_dir.join("dir");

        // Test hash calculations on all test paths
        // Golden values from `nix hash path --type sha256 --base32`.
        for (path, expected) in [
            (
                empty_path,
                "0ip26j2h11n1kgkz36rl4akv694yz65hr72q4kv4b3lxcbi65b3p",
            ),
            (
                full_path,
                "1bisd3z6bxgrfhl5nfahcr7bf0y1y96932mh2agjpwvr6w141bjp",
            ),
            (
                dir_path,
                "1d9nmfkxfp95sngdqh3jf66fr5sqxzqd70yjr2m95fdi71cs475b",
            ),
        ] {
            // Calculate both NAR hash and castore entry to verify they run without error
            let (nar_hash, nar_size) = calculate_nar_hash(&path, None).unwrap();
            let encoded_entry = create_castore_entry(&path).unwrap();
            assert_eq!(format_nar_hash(&nar_hash), format!("sha256:{expected}"));

            // Just print the results for debugging
            println!("File: {:?}", path);
            println!(
                "  NAR hash: {} (size: {})",
                format_nar_hash(&nar_hash),
                nar_size
            );
            println!("  Encoded castore entry: {}", encoded_entry);

            // Verify that the encoded entry is a valid BASE64URL_NOPAD string
            assert!(
                !encoded_entry.contains('+'),
                "Encoded entry should not contain '+' character"
            );
            assert!(
                !encoded_entry.contains('/'),
                "Encoded entry should not contain '/' character"
            );
            assert!(
                !encoded_entry.contains('='),
                "Encoded entry should not contain padding '=' character"
            );

            // Basic validation - all encoded entries should be non-empty
            assert!(
                !encoded_entry.is_empty(),
                "Encoded entry should not be empty"
            );
        }
    }

    // 32-char ASCII strings standing in for nixbase32 store-path hashes.
    const HASH_SELF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_DEP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_CA_DEP: &str = "cccccccccccccccccccccccccccccccc";
    const HASH_CA_SELF: &str = "dddddddddddddddddddddddddddddddd";

    #[test]
    fn file_nar_matches_independent_writer_and_pass1_modulo_positions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out");
        let contents = format!("self={HASH_SELF} dep={HASH_DEP} again={HASH_SELF}");
        std::fs::write(&path, &contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut nar = Vec::new();
        nix_compat::nar::writer::open(&mut nar)
            .unwrap()
            .file(true, contents.len() as u64, &mut contents.as_bytes())
            .unwrap();
        let (hash, size) = calculate_nar_hash(&path, None).unwrap();
        assert_eq!(hash, NixHash::Sha256(Sha256::digest(&nar).into()));
        assert_eq!(size, nar.len() as u64);

        let rewritten_contents = contents.replace(HASH_DEP, HASH_CA_DEP);
        let mut rewritten_nar = Vec::new();
        nix_compat::nar::writer::open(&mut rewritten_nar)
            .unwrap()
            .file(
                true,
                rewritten_contents.len() as u64,
                &mut rewritten_contents.as_bytes(),
            )
            .unwrap();
        let positions: Vec<_> = rewritten_nar
            .windows(32)
            .enumerate()
            .filter_map(|(i, bytes)| (bytes == HASH_SELF.as_bytes()).then_some(i))
            .collect();
        assert_eq!(positions.len(), 2);
        for &i in &positions {
            rewritten_nar[i..i + 32].fill(0);
        }
        let mut digester = Sha256::new();
        digester.update(&rewritten_nar);
        for i in positions {
            digester.update(format!("|{i}"));
        }
        let modulo_hash = NixHash::Sha256(digester.finalize().into());
        let reference = format!("/nix/store/{HASH_CA_DEP}-dep");
        let reference_sp = StorePath::from_absolute_path(reference.as_bytes()).unwrap();
        let expected = build_ca_path(
            StorePathName::from_str("out").unwrap(),
            true,
            &modulo_hash,
            [reference_sp.as_ref()],
            true,
        )
        .to_owned();
        let rewrites = HashMap::from([(HASH_DEP.into(), HASH_CA_DEP.into())]);
        // References are a set: duplicates must not affect the path fingerprint.
        assert_eq!(
            rewrite_to_ca_pass1(
                &path,
                "out",
                &rewrites,
                HASH_SELF,
                &[reference.clone(), reference]
            )
            .unwrap(),
            expected
        );
    }

    #[test]
    fn pass2_matches_materialized_rewrites_including_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let original = write_fake_output(&format!("{HASH_SELF}:{HASH_DEP}"));
        let expected = write_fake_output(&format!("{HASH_CA_SELF}:{HASH_CA_DEP}"));
        for dir in [&original, &expected] {
            std::fs::set_permissions(
                root_of(dir).join("payload"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        symlink(
            format!("/nix/store/{HASH_DEP}-dep"),
            root_of(&original).join("link"),
        )
        .unwrap();
        symlink(
            format!("/nix/store/{HASH_CA_DEP}-dep"),
            root_of(&expected).join("link"),
        )
        .unwrap();
        let rewrites = HashMap::from([
            (HASH_SELF.into(), HASH_CA_SELF.into()),
            (HASH_DEP.into(), HASH_CA_DEP.into()),
        ]);
        let result = rewrite_to_ca_pass2(&root_of(&original), &rewrites).unwrap();
        assert_eq!(
            result.castore_entry_base64,
            create_castore_entry(&root_of(&expected)).unwrap()
        );
        let (hash, size) = calculate_nar_hash(&root_of(&expected), None).unwrap();
        assert_eq!(result.nar_hash, hash);
        assert_eq!(result.nar_size, size);
        let candidates = BTreeSet::from([HASH_DEP.into()]);
        assert_eq!(
            scan_for_references(&root_of(&original).join("link"), &candidates).unwrap(),
            candidates
        );
        // No content in the original filesystem was changed.
        assert_eq!(
            std::fs::read_to_string(root_of(&original).join("payload")).unwrap(),
            format!("{HASH_SELF}:{HASH_DEP}")
        );
    }

    #[test]
    fn castore_entry_uses_upstream_directory_sizes() {
        use prost::Message;
        let entry = create_castore_entry(Path::new("testdata/dir")).unwrap();
        let bytes = data_encoding::BASE64URL_NOPAD
            .decode(entry.as_bytes())
            .unwrap();
        let entry = snix_castore::proto::Entry::decode(bytes.as_slice()).unwrap();
        let Some(snix_castore::proto::entry::Entry::Directory(directory)) = entry.entry else {
            panic!("expected directory");
        };
        assert!(directory.name.is_empty());
        assert_eq!(directory.size, 2); // Old fork emitted 4 for the same two files.
    }

    #[test]
    fn rejects_unsupported_algorithm_and_invalid_hash_alphabet() {
        let dir = write_fake_output("data");
        assert!(calculate_nar_hash(&root_of(&dir), Some(HashAlgo::Sha1)).is_err());
        for hash in [
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "\u{00e9}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ] {
            assert!(scan_for_references(&root_of(&dir), &BTreeSet::from([hash.into()])).is_err());
        }
    }

    fn write_fake_output(contents: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("out");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("payload"), contents).unwrap();
        dir
    }

    fn root_of(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("out")
    }

    #[test]
    fn pass1_rewrites_deps_and_self_masks_self_reference() {
        // Contents reference both a dep hash and self. Pass 1 should:
        // - apply the dep rewrite during ingest (so the NAR sees the CA hash)
        // - mask the self-hash before computing the modulo SHA256
        // - tag self_reference=true into build_ca_path
        let contents =
            format!("first /nix/store/{HASH_SELF}-out, then /nix/store/{HASH_DEP}-dep, more.");
        let dir = write_fake_output(&contents);

        let mut deps = HashMap::new();
        deps.insert(HASH_DEP.to_string(), HASH_CA_DEP.to_string());
        let refs = vec![format!("/nix/store/{HASH_CA_DEP}-dep")];

        let sp = rewrite_to_ca_pass1(&root_of(&dir), "out", &deps, HASH_SELF, &refs).unwrap();
        // Sanity: name suffix preserved, hash slice differs from any input.
        assert!(sp.to_absolute_path().ends_with("-out"));
        let hash_str = nixbase32::encode(sp.digest());
        assert_ne!(hash_str, HASH_SELF);
        assert_ne!(hash_str, HASH_DEP);

        // Determinism: same inputs → same path.
        let sp2 = rewrite_to_ca_pass1(&root_of(&dir), "out", &deps, HASH_SELF, &refs).unwrap();
        assert_eq!(sp.to_absolute_path(), sp2.to_absolute_path());
    }

    #[test]
    fn pass1_path_changes_when_dep_rewrite_changes() {
        let contents = format!("ref /nix/store/{HASH_DEP}-dep here");
        let dir = write_fake_output(&contents);

        let refs = vec![format!("/nix/store/{HASH_CA_DEP}-dep")];

        let mut deps1 = HashMap::new();
        deps1.insert(HASH_DEP.to_string(), HASH_CA_DEP.to_string());

        let mut deps2 = HashMap::new();
        deps2.insert(
            HASH_DEP.to_string(),
            "ffffffffffffffffffffffffffffffff".to_string(),
        );

        let sp1 = rewrite_to_ca_pass1(&root_of(&dir), "out", &deps1, HASH_SELF, &refs).unwrap();
        let sp2 = rewrite_to_ca_pass1(&root_of(&dir), "out", &deps2, HASH_SELF, &refs).unwrap();
        assert_ne!(
            sp1.to_absolute_path(),
            sp2.to_absolute_path(),
            "different dep CA hash must change the synthetic CA path"
        );
    }

    #[test]
    fn pass2_returns_castore_entry_and_nar_hash_deterministically() {
        let contents = format!("self /nix/store/{HASH_SELF}-out and dep /nix/store/{HASH_DEP}-dep");
        let dir = write_fake_output(&contents);

        let mut rewrites = HashMap::new();
        rewrites.insert(HASH_DEP.to_string(), HASH_CA_DEP.to_string());
        rewrites.insert(HASH_SELF.to_string(), HASH_CA_SELF.to_string());

        let r1 = rewrite_to_ca_pass2(&root_of(&dir), &rewrites).unwrap();
        let r2 = rewrite_to_ca_pass2(&root_of(&dir), &rewrites).unwrap();
        // Determinism: castore entry, NAR hash, and NAR size all round-trip.
        assert_eq!(r1.castore_entry_base64, r2.castore_entry_base64);
        assert_eq!(format_nar_hash(&r1.nar_hash), format_nar_hash(&r2.nar_hash));
        assert_eq!(r1.nar_size, r2.nar_size);
        // BASE64URL_NOPAD: no padding, no '+' or '/'.
        assert!(!r1.castore_entry_base64.is_empty());
        assert!(!r1.castore_entry_base64.contains('+'));
        assert!(!r1.castore_entry_base64.contains('/'));
        assert!(!r1.castore_entry_base64.contains('='));
        // NAR size positive (we wrote a non-empty dir).
        assert!(r1.nar_size > 0);
    }

    #[test]
    fn pass2_changes_when_self_ref_replacement_changes() {
        let contents = format!("self /nix/store/{HASH_SELF}-out");
        let dir = write_fake_output(&contents);

        let mut rewrites_a = HashMap::new();
        rewrites_a.insert(HASH_SELF.to_string(), HASH_CA_SELF.to_string());
        let mut rewrites_b = HashMap::new();
        rewrites_b.insert(
            HASH_SELF.to_string(),
            "ffffffffffffffffffffffffffffffff".to_string(),
        );

        let ra = rewrite_to_ca_pass2(&root_of(&dir), &rewrites_a).unwrap();
        let rb = rewrite_to_ca_pass2(&root_of(&dir), &rewrites_b).unwrap();
        assert_ne!(ra.castore_entry_base64, rb.castore_entry_base64);
        // Different self-ref replacement bytes ⇒ different NAR content ⇒
        // different NAR hash. Same size though (length-preserving rewrite).
        assert_ne!(format_nar_hash(&ra.nar_hash), format_nar_hash(&rb.nar_hash));
        assert_eq!(ra.nar_size, rb.nar_size);
    }

    #[test]
    fn pass1_rejects_wrong_length_hash() {
        let dir = write_fake_output("nothing");
        let mut deps = HashMap::new();
        deps.insert("too-short".to_string(), HASH_CA_DEP.to_string());
        let err = rewrite_to_ca_pass1(&root_of(&dir), "out", &deps, HASH_SELF, &[]).unwrap_err();
        let HashError::IoError(ioe) = err;
        assert_eq!(ioe.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn scan_for_references_finds_present_and_skips_absent() {
        // Content references HASH_DEP but not HASH_SELF.
        let dir = write_fake_output(&format!("dep here: /nix/store/{HASH_DEP}-name"));
        let mut candidates = BTreeSet::new();
        candidates.insert(HASH_DEP.to_string());
        candidates.insert(HASH_SELF.to_string());

        let found = scan_for_references(&root_of(&dir), &candidates).unwrap();
        let expected: BTreeSet<String> = [HASH_DEP.to_string()].into_iter().collect();
        assert_eq!(found, expected);
    }

    #[test]
    fn scan_for_references_empty_candidates_returns_empty() {
        let dir = write_fake_output("anything goes");
        let found = scan_for_references(&root_of(&dir), &BTreeSet::new()).unwrap();
        assert!(found.is_empty());
    }

    #[test]
    fn scan_for_references_rejects_wrong_length() {
        let dir = write_fake_output("nothing");
        let mut candidates = BTreeSet::new();
        candidates.insert("too-short".to_string());
        let err = scan_for_references(&root_of(&dir), &candidates).unwrap_err();
        let HashError::IoError(ioe) = err;
        assert_eq!(ioe.kind(), io::ErrorKind::InvalidInput);
    }
}
