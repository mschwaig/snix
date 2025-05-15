use clap::{Parser, ValueEnum};
use std::path::Path;
use laut_compat::content_hash::{calculate_nar_hash, format_nar_hash, create_castore_entry};

#[derive(Debug, Clone, ValueEnum)]
enum OutputType {
    /// NAR hash as defined by nix
    Nar,
    /// castore entry as defined by snix-castore
    Castore,
}

#[derive(Parser, Debug)]
#[command(author, version, about = "Calculate content hash or entry for a path")]
struct Args {
    path: String,

    #[arg(short = 't', long, value_enum, default_value_t = OutputType::Nar)]
    output_type: OutputType,

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

    match args.output_type {
        OutputType::Nar => {
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
        OutputType::Castore => {
            match create_castore_entry(path) {
                Ok(entry) => {
                    let entry_bytes = prost::Message::encode_to_vec(&entry);
                    if args.quiet {
                        let encoded = data_encoding::BASE64URL_NOPAD.encode(&entry_bytes);
                        println!("{}", encoded);
                    } else {
                        println!("CA store entry: {:?}", entry);
                        println!("Entry size: {} bytes", entry_bytes.len());
                    }
                },
                Err(err) => {
                    eprintln!("Error creating CA store entry: {}", err);
                    std::process::exit(1);
                }
            }
        }
    }
}