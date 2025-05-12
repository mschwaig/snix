use count_write::CountWrite;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::writer;
use crate::nixbase32;
use crate::nixhash::{HashAlgo, NixHash};

/// Error type for NAR hash calculation
#[derive(Debug, thiserror::Error)]
pub enum NarHashError {
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),

    #[error("Unsupported file type for path: {0}")]
    UnsupportedFileType(String),
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
/// * On failure, returns a `NarHashError`
///
/// # Example
///
/// ```no_run
/// use std::path::Path;
/// use nix_compat::nar::hash::calculate_nar_hash;
/// use nix_compat::nixhash::HashAlgo;
///
/// let path = Path::new("/nix/store/9bwryidal9q3g91cjm6xschfn4ikd82q-hello-2.12.1");
/// let (hash, size) = calculate_nar_hash(path, Some(HashAlgo::Sha256)).unwrap();
/// println!("NAR hash: {}", hash);
/// println!("NAR size: {}", size);
/// ```
pub fn calculate_nar_hash(
    path: &Path,
    algo: Option<HashAlgo>,
) -> Result<(NixHash, u64), NarHashError> {
    let algo = algo.unwrap_or(HashAlgo::Sha256);

    match algo {
        HashAlgo::Sha256 => {
            // First, calculate the NAR without hashing to get the size
            let mut size_counter = Vec::new();
            write_path_to_nar_root(path, &mut size_counter)?;
            let nar_size = size_counter.len() as u64;

            // Now generate the NAR again to calculate the hash
            let mut hasher = Sha256::new();
            {
                let mut count_write = CountWrite::from(&mut hasher);
                let mut writer = BufWriter::new(&mut count_write);
                write_path_to_nar_root(path, &mut writer)?;
                writer.flush()?;
            }

            // Get the final hash
            let digest: [u8; 32] = hasher.finalize().into();

            Ok((NixHash::Sha256(digest), nar_size))
        }
        // Support for other algorithms can be added here
        _ => unimplemented!("Only SHA256 is currently supported for NAR hashing"),
    }
}

/// Function to create a NAR writer and write a path to it
fn write_path_to_nar_root<W: io::Write>(path: &Path, writer: &mut W) -> Result<(), NarHashError> {
    // Create a NAR writer
    let nar = writer::open(writer)?;

    // Process the path based on its type
    let metadata = fs::symlink_metadata(path)?;

    if metadata.file_type().is_symlink() {
        // It's a symlink, get the target and write it
        let target = fs::read_link(path)?;
        let target_str = target.to_string_lossy().into_owned();
        nar.symlink(target_str.as_bytes())?;
    } else if metadata.file_type().is_file() {
        // It's a regular file, write its contents
        let file = File::open(path)?;
        let size = metadata.len();
        let executable = metadata.permissions().mode() & 0o111 != 0;

        nar.file(executable, size, &mut BufReader::new(file))?;
    } else if metadata.file_type().is_dir() {
        // It's a directory, create a directory node
        let mut dir_writer = nar.directory()?;

        // Read directory entries
        let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(Result::ok).collect();

        // Sort entries by name (required for NAR format)
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        // Process each entry recursively
        for entry in entries {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip . and .. entries
            if name_str == "." || name_str == ".." {
                continue;
            }

            let entry_path = entry.path();
            let node = dir_writer.entry(name_str.as_bytes())?;
            write_path_to_nar_node(node, &entry_path)?;
        }

        dir_writer.close()?;
    } else {
        // Unsupported file type
        return Err(NarHashError::UnsupportedFileType(
            path.display().to_string(),
        ));
    }

    Ok(())
}

/// Helper function to recursively write a path to a NAR node
fn write_path_to_nar_node<W: io::Write>(
    nar: writer::Node<W>,
    path: &Path,
) -> Result<(), NarHashError> {
    // Get metadata for the path
    let metadata = fs::symlink_metadata(path)?;

    if metadata.file_type().is_symlink() {
        // It's a symlink, get the target and write it
        let target = fs::read_link(path)?;
        let target_str = target.to_string_lossy().into_owned();
        nar.symlink(target_str.as_bytes())?;
        Ok(())
    } else if metadata.file_type().is_file() {
        // It's a regular file, write its contents
        let file = File::open(path)?;
        let size = metadata.len();
        let executable = metadata.permissions().mode() & 0o111 != 0;

        nar.file(executable, size, &mut BufReader::new(file))?;
        Ok(())
    } else if metadata.file_type().is_dir() {
        // It's a directory, create a directory node
        let mut dir_writer = nar.directory()?;

        // Read directory entries
        let mut entries: Vec<_> = fs::read_dir(path)?.filter_map(Result::ok).collect();

        // Sort entries by name (required for NAR format)
        entries.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

        // Process each entry recursively
        for entry in entries {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            // Skip . and .. entries
            if name_str == "." || name_str == ".." {
                continue;
            }

            let entry_path = entry.path();
            let node = dir_writer.entry(name_str.as_bytes())?;
            write_path_to_nar_node(node, &entry_path)?;
        }

        dir_writer.close()?;
        Ok(())
    } else {
        // Unsupported file type
        Err(NarHashError::UnsupportedFileType(
            path.display().to_string(),
        ))
    }
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
/// use nix_compat::nar::hash::{calculate_nar_hash, format_nar_hash};
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

// this test actually gets skipped apparently
// so we need to look into that
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

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
}
