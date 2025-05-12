use clap::{Parser, ValueEnum};
use std::path::Path;
use laut_compat::nar::{calculate_nar_hash, format_nar_hash, calculate_castore_hash};

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