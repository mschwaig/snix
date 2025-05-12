use std::env;
use std::path::Path;
use nix_compat::nar::hash::{calculate_nar_hash, format_nar_hash};

fn main() {
    // Get command-line arguments
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path>", args[0]);
        std::process::exit(1);
    }
    
    let path = Path::new(&args[1]);
    if !path.exists() {
        eprintln!("Error: Path '{}' does not exist", path.display());
        std::process::exit(1);
    }
    
    // Calculate the NAR hash
    match calculate_nar_hash(path, None) {
        Ok((hash, size)) => {
            let formatted = format_nar_hash(&hash);
            println!("NAR hash: {}", formatted);
            println!("NAR size: {} bytes", size);
        },
        Err(err) => {
            eprintln!("Error calculating NAR hash: {}", err);
            std::process::exit(1);
        }
    }
}