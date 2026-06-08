//! This module provides functions to calculate
//! NAR hashes and castore entries for store paths.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use nix_compat::nixhash::{CAHash, HashAlgo, NixHash};
use nix_compat::nixbase32;
use nix_compat::store_path::{StorePath, build_ca_path};
use sha2::{Digest, Sha256};
use snix_castore::Node;
use snix_castore::blobservice::memory::MemoryBlobService;
use snix_castore::directoryservice::memory::MemoryDirectoryService;
use snix_castore::import::fs::{ingest_path, ingest_path_with_rewrites};
use snix_castore::refscan::{RewriteEntry, RewritePattern, rewrite_in_place};

/// Error type for hash calculation
#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
}

/// Common functionality to create a runtime and ingest a path for hashing
async fn prepare_for_hashing(path: &Path) -> Result<(MemoryBlobService, MemoryDirectoryService, Node), HashError> {
    // Create memory services that don't persist anything
    let blob_service = MemoryBlobService::default();
    let directory_service = MemoryDirectoryService::default();

    // Ingest the path into the memory services
    let root_node = ingest_path::<_, _, _, &[u8]>(
        blob_service.clone(),
        directory_service.clone(),
        path,
        None,
    )
    .await
    .map_err(|e| HashError::IoError(
        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
    ))?;

    Ok((blob_service, directory_service, root_node))
}

/// Creates a Tokio runtime suitable for hash calculations
fn create_hash_runtime() -> Result<tokio::runtime::Runtime, HashError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| HashError::IoError(e))
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
    use snix_store::nar::{SimpleRenderer, NarCalculationService};

    let algo = algo.unwrap_or(HashAlgo::Sha256);
    match algo {
        HashAlgo::Sha256 => {
            // Run the calculation in a runtime
            with_hash_runtime(path, |blob_service, directory_service, root_node| async move {
                // Create a SimpleRenderer to calculate the NAR hash
                let renderer = SimpleRenderer::new(blob_service, directory_service);

                // Calculate the NAR hash
                let (size, hash) = renderer.calculate_nar(&root_node)
                    .await
                    .map_err(|e| HashError::IoError(
                        std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
                    ))?;

                Ok::<(NixHash, u64), HashError>((NixHash::Sha256(hash), size))
            })
        }
        // Support for other algorithms can be added here
        _ => unimplemented!("Only SHA256 is currently supported for NAR hashing"),
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

// Private helper function to calculate castore hash if needed internally
fn calculate_castore_hash(path: &Path) -> Result<String, HashError> {

    // Run the calculation in a runtime
    with_hash_runtime(path, |_, _directory_service, root_node| async move {
        // For directories, we get the digest directly
        let digest = match &root_node {
            Node::Directory { digest, .. } => digest.clone(),
            _ => {
                // For non-directory nodes, we need to create a wrapper directory
                let mut dir = snix_castore::Directory::default();
                let name = path.file_name()
                    .ok_or_else(|| HashError::IoError(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Path has no file name".to_string()
                    )))?
                    .to_string_lossy()
                    .into_owned();

                // Add the node to the directory
                dir.add(snix_castore::PathComponent::try_from(name.as_str())
                    .map_err(|e| HashError::IoError(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid path component: {}", e)
                    )))?,
                    root_node.clone()
                )
                .map_err(|e| HashError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error adding node to directory: {}", e)
                )))?;

                // Get the digest of the directory
                dir.digest()
            }
        };

        // Return the string representation directly
        Ok::<String, HashError>(digest.to_string())
    })
}

/// Helper to run a computation that needs a runtime and hash inputs
fn with_hash_runtime<F, T, Fut>(path: &Path, f: F) -> Result<T, HashError>
where
    F: FnOnce(MemoryBlobService, MemoryDirectoryService, Node) -> Fut,
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
    self_mask: Option<&str>,
) -> Result<RewritePattern<String>, HashError> {
    let mut entries: Vec<RewriteEntry<String>> = Vec::with_capacity(deps.len() + 1);
    for (needle, replacement) in deps {
        validate_hash_str(needle)?;
        validate_hash_str(replacement)?;
        entries.push(RewriteEntry {
            needle: needle.clone(),
            replacement: replacement.as_bytes().to_vec(),
            record_positions: false,
        });
    }
    if let Some(self_hash) = self_mask {
        validate_hash_str(self_hash)?;
        entries.push(RewriteEntry {
            needle: self_hash.to_string(),
            replacement: vec![0u8; STORE_PATH_HASH_LEN],
            record_positions: true,
        });
    }
    Ok(RewritePattern::new(entries))
}

fn validate_hash_str(s: &str) -> Result<(), HashError> {
    if s.len() != STORE_PATH_HASH_LEN {
        return Err(HashError::IoError(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "store-path hash must be {} chars (got {})",
                STORE_PATH_HASH_LEN,
                s.len()
            ),
        )));
    }
    Ok(())
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
) -> Result<StorePath<String>, HashError> {
    let pattern = rewrite_pattern_from_map(deps_rewrites, None)?;
    validate_hash_str(self_ia_hash)?;

    let self_ia_hash_owned = self_ia_hash.to_string();
    let refs_owned: Vec<String> = refs_as_ca.to_vec();
    let name_owned = name.to_string();

    with_hash_runtime_rewriting(path, pattern, move |blob_service, directory_service, root_node| async move {
        let mut nar_bytes: Vec<u8> = Vec::new();
        snix_store::nar::write_nar(&mut nar_bytes, &root_node, blob_service, directory_service)
            .await
            .map_err(|e| HashError::IoError(io::Error::new(io::ErrorKind::Other, e.to_string())))?;

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

        build_ca_path(
            &name_owned,
            &CAHash::Nar(NixHash::Sha256(nar_modulo_hash)),
            refs_owned.iter().map(String::as_str).collect::<Vec<_>>(),
            !positions.is_empty(),
        )
        .map_err(|e| {
            HashError::IoError(io::Error::new(io::ErrorKind::Other, e.to_string()))
        })
    })
}

/// Pass 2 of the IA→CA recursion: ingest `path` with rewrites covering both
/// runtime deps and the output's self-reference (IA-hash → synthetic-CA-hash),
/// then return the BASE64URL_NOPAD-encoded castore [`proto::Entry`] of the
/// resulting root node.
///
/// This is the artifact that gets signed as the per-output content fingerprint
/// — it captures the "as if this output were content-addressed" form of the
/// path including the substituted self-reference.
pub fn rewrite_to_ca_pass2(
    path: &Path,
    rewrites_including_self: &HashMap<String, String>,
) -> Result<String, HashError> {
    let pattern = rewrite_pattern_from_map(rewrites_including_self, None)?;
    with_hash_runtime_rewriting(path, pattern, |_, _, root_node| async move {
        let entry = snix_castore::proto::Entry::from_name_and_node("".into(), root_node);
        let entry_bytes = prost::Message::encode_to_vec(&entry);
        Ok(data_encoding::BASE64URL_NOPAD.encode(&entry_bytes))
    })
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
    F: FnOnce(MemoryBlobService, MemoryDirectoryService, Node) -> Fut,
    Fut: std::future::Future<Output = Result<T, HashError>>,
{
    let runtime = create_hash_runtime()?;
    runtime.block_on(async {
        let blob_service = MemoryBlobService::default();
        let directory_service = MemoryDirectoryService::default();
        let root_node = ingest_path_with_rewrites(
            blob_service.clone(),
            directory_service.clone(),
            path,
            &pattern,
        )
        .await
        .map_err(|e| {
            HashError::IoError(io::Error::new(io::ErrorKind::Other, e.to_string()))
        })?;
        f(blob_service, directory_service, root_node).await
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::Path, path::PathBuf};

    #[test]
    fn test_hash_known_path() {
        // This test will be skipped if the path doesn't exist
        let path = Path::new("/nix/store/9bwryidal9q3g91cjm6xschfn4ikd82q-hello-2.12.1");
        if !path.exists() {
            return;
        }

        let (hash, _) = calculate_nar_hash(path, Some(HashAlgo::Sha256)).unwrap();
        let formatted = format_nar_hash(&hash);

        // The expected hash for this path
        let expected = "sha256:08za7nnjda8kpdsd73v3mhykjvp0rsmskwsr37winhmzgm6iw79w";

        assert_eq!(formatted, expected, "NAR hash doesn't match expected value");
    }

    #[test]
    fn test_with_test_files() {
        // Get paths to test files
        let testdata_dir = PathBuf::from("testdata");
        let empty_path = testdata_dir.join("empty");
        let full_path = testdata_dir.join("full");
        let dir_path = testdata_dir.join("dir");

        // Test hash calculations on all test paths
        for path in [empty_path, full_path, dir_path] {
            if !path.exists() {
                eprintln!("Skipping missing test file: {:?}", path);
                continue;
            }

            // Calculate both NAR hash and castore entry to verify they run without error
            let (nar_hash, nar_size) = calculate_nar_hash(&path, None).unwrap();
            let encoded_entry = create_castore_entry(&path).unwrap();

            // Just print the results for debugging
            println!("File: {:?}", path);
            println!("  NAR hash: {} (size: {})", format_nar_hash(&nar_hash), nar_size);
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
            assert!(!encoded_entry.is_empty(), "Encoded entry should not be empty");
        }
    }

    // 32-char ASCII strings standing in for nixbase32 store-path hashes.
    const HASH_SELF: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_DEP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_CA_DEP: &str = "cccccccccccccccccccccccccccccccc";
    const HASH_CA_SELF: &str = "dddddddddddddddddddddddddddddddd";

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
        let contents = format!(
            "first /nix/store/{HASH_SELF}-out, then /nix/store/{HASH_DEP}-dep, more."
        );
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
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
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
    fn pass2_returns_base64_castore_entry_and_is_deterministic() {
        let contents =
            format!("self /nix/store/{HASH_SELF}-out and dep /nix/store/{HASH_DEP}-dep");
        let dir = write_fake_output(&contents);

        let mut rewrites = HashMap::new();
        rewrites.insert(HASH_DEP.to_string(), HASH_CA_DEP.to_string());
        rewrites.insert(HASH_SELF.to_string(), HASH_CA_SELF.to_string());

        let b1 = rewrite_to_ca_pass2(&root_of(&dir), &rewrites).unwrap();
        let b2 = rewrite_to_ca_pass2(&root_of(&dir), &rewrites).unwrap();
        assert_eq!(b1, b2);
        // BASE64URL_NOPAD: no padding, no '+' or '/'.
        assert!(!b1.is_empty());
        assert!(!b1.contains('+'));
        assert!(!b1.contains('/'));
        assert!(!b1.contains('='));
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

        let ba = rewrite_to_ca_pass2(&root_of(&dir), &rewrites_a).unwrap();
        let bb = rewrite_to_ca_pass2(&root_of(&dir), &rewrites_b).unwrap();
        assert_ne!(ba, bb);
    }

    #[test]
    fn pass1_rejects_wrong_length_hash() {
        let dir = write_fake_output("nothing");
        let mut deps = HashMap::new();
        deps.insert("too-short".to_string(), HASH_CA_DEP.to_string());
        let err =
            rewrite_to_ca_pass1(&root_of(&dir), "out", &deps, HASH_SELF, &[]).unwrap_err();
        let HashError::IoError(ioe) = err;
        assert_eq!(ioe.kind(), io::ErrorKind::InvalidInput);
    }
}