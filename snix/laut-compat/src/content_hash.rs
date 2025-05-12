//! This module provides functions to calculate NAR hashes and CA store
//! hashes for store paths.

use std::io;
use std::path::Path;
use nix_compat::nixhash::{HashAlgo, NixHash};
use nix_compat::nixbase32;
use snix_castore::Node;
use snix_castore::blobservice::memory::MemoryBlobService;
use snix_castore::directoryservice::memory::MemoryDirectoryService;
use snix_castore::import::fs::ingest_path;

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
/// use laut_compat::nar::{calculate_nar_hash, format_nar_hash};
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

/// Calculate the content-addressed store hash of a path
/// 
/// This uses the actual Snix CA store logic to compute the hash of a path.
/// For directories, it returns the directory digest directly.
/// For other node types, it creates a single-entry directory with the node
/// and returns the digest of that directory.
///
/// # Arguments
///
/// * `path` - The path to hash
///
/// # Returns
///
/// * On success, returns the CA store hash as a string (blake3 hash)
/// * On failure, returns a `HashError`
pub fn calculate_castore_hash(path: &Path) -> Result<String, HashError> {
    
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
/// use laut_compat::nar::{calculate_nar_hash, format_nar_hash};
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
        
        // Test both hash calculations on all test paths
        for path in [empty_path, full_path, dir_path] {
            if !path.exists() {
                eprintln!("Skipping missing test file: {:?}", path);
                continue;
            }
            
            // Calculate both hash types to verify they run without error
            let (nar_hash, nar_size) = calculate_nar_hash(&path, None).unwrap();
            let castore_hash = calculate_castore_hash(&path).unwrap();
            
            // Just print the results for debugging
            println!("File: {:?}", path);
            println!("  NAR hash: {} (size: {})", format_nar_hash(&nar_hash), nar_size);
            println!("  CA hash: {}", castore_hash);
        }
    }
}