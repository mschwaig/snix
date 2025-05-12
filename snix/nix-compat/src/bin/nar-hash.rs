use clap::{Parser, ValueEnum};
use std::path::Path;
use nix_compat::nar::hash::{calculate_nar_hash, format_nar_hash};

#[derive(Debug, Clone, ValueEnum)]
enum HashType {
    /// Standard NAR hash (compatible with Nix)
    Nar,
    /// Content-addressed store hash (blake3 hash of directory structure)
    Castore,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Calculate content hash of a path")]
struct Args {
    /// Path to hash
    path: String,

    /// Type of hash to calculate
    #[arg(short = 't', long, value_enum, default_value_t = HashType::Nar)]
    hash_type: HashType,

    /// Output just the hash, without any labels
    #[arg(short, long)]
    quiet: bool,
}

fn main() {
    let args = Args::parse();
    
    let path = Path::new(&args.path);
    if !path.exists() {
        eprintln!("Error: Path '{}' does not exist", path.display());
        std::process::exit(1);
    }
    
    match args.hash_type {
        HashType::Nar => {
            // Calculate the NAR hash
            match calculate_nar_hash(path, None) {
                Ok((hash, size)) => {
                    let formatted = format_nar_hash(&hash);
                    if args.quiet {
                        println!("{}", formatted);
                    } else {
                        println!("NAR hash: {}", formatted);
                        println!("NAR size: {} bytes", size);
                    }
                },
                Err(err) => {
                    eprintln!("Error calculating NAR hash: {}", err);
                    std::process::exit(1);
                }
            }
        },
        HashType::Castore => {
            // Calculate the CA store hash
            match calculate_castore_hash(path) {
                Ok(hash) => {
                    if args.quiet {
                        println!("{}", hash);
                    } else {
                        println!("CA store hash: {}", hash);
                    }
                },
                Err(err) => {
                    eprintln!("Error calculating CA store hash: {}", err);
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Calculate the content-addressed store hash of a path
/// This uses the actual Snix CA store logic to compute the hash
fn calculate_castore_hash(path: &Path) -> Result<String, std::io::Error> {
    use snix_castore::B3Digest;
    use snix_castore::blobservice::memory::MemoryBlobService;
    use snix_castore::directoryservice::memory::MemoryDirectoryService;
    use snix_castore::import::fs::ingest_path;
    
    // We need to use tokio for compatibility with the async functions
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    
    // Run the async computation in the runtime
    let result = runtime.block_on(async {
        // Create memory services that don't persist anything
        let blob_service = MemoryBlobService::default();
        let directory_service = MemoryDirectoryService::default();
        
        // Ingest the path into the memory services
        let root_node = ingest_path::<_, _, _, &[u8]>(
            blob_service,
            directory_service.clone(),
            path,
            None,
        )
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        
        // For directories, we get the digest directly
        let digest = match &root_node {
            snix_castore::Node::Directory { digest, .. } => digest.clone(),
            _ => {
                // For non-directory nodes, we need to create a wrapper directory
                let mut dir = snix_castore::Directory::default();
                let name = path.file_name()
                    .ok_or_else(|| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Path has no file name".to_string()
                    ))?
                    .to_string_lossy()
                    .into_owned();
                
                // Add the node to the directory
                dir.add(snix_castore::PathComponent::try_from(name.as_str())
                    .map_err(|e| std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid path component: {}", e)
                    ))?, 
                    root_node.clone()
                )
                .map_err(|e| std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Error adding node to directory: {}", e)
                ))?;
                
                // Get the digest of the directory
                dir.digest()
            }
        };
        
        Ok::<B3Digest, std::io::Error>(digest)
    })?;
    
    // Convert the B3Digest to its string representation (blake3-BASE64)
    Ok(result.to_string())
}