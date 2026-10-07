use clap::Parser;
use mimalloc::MiMalloc;
use nix_compat::nix_daemon::handler::NixDaemon;
use nix_daemon::SnixDaemon;
use snix_build::buildservice;
use snix_castore::blob_engine::BlobServiceEngine;
use snix_cli::make_listener;
use snix_store::utils::{ServiceUrlsGrpc, construct_services};
use std::{error::Error, sync::Arc};
use tracing::error;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// Run Nix-compatible store daemon backed by snix.
#[derive(Parser)]
struct Cli {
    #[clap(flatten)]
    service_addrs: ServiceUrlsGrpc,

    /// The address to listen on. Must be a unix domain socket.
    #[clap(flatten)]
    listen_args: tokio_listener::ListenerAddressLFlag,

    #[clap(flatten)]
    tracing_args: snix_tracing::TracingArgs,

    /// Build service URI.
    ///
    /// The following schemes are supported by the following services:
    ///
    /// * dummy: for a dummy build service
    ///
    /// * oci:/path/to/bundle for a OCI build service
    ///
    /// * bwrap:/path/to/bundle for a bubblewrap service
    ///
    /// * grpc+http://[::1]:8000, grpc+https://[::1]:8000 or grpc+unix:/path/to/socket
    ///   for a GRPC remote builder.
    #[arg(long, env, default_value = "dummy:")]
    build_service_addr: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Cli::parse();

    let mut tracing_handle = snix_tracing::TracingBuilder::default()
        .handle_tracing_args(&args.tracing_args)
        .build()?;

    tokio::select! {
        _ = snix_cli::shutdown_signal() => {
            if let Err(e) = tracing_handle.shutdown().await {
                eprintln!("failed to shutdown tracing: {e}");
            }
            Ok(())
        },
        res = run(args) => {
            if let Err(e) = tracing_handle.shutdown().await {
                eprintln!("failed to shutdown tracing: {e}");
            }
            res
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (blob_service, directory_service, path_info_service, nar_calculation_service) =
        construct_services(cli.service_addrs).await?;

    let blob_engine = Arc::new(BlobServiceEngine(blob_service));

    let build_service = buildservice::from_addr(
        &cli.build_service_addr,
        blob_engine.clone(),
        directory_service.clone(),
    )
    .await?;

    let io = Arc::new(SnixDaemon::new(
        blob_engine,
        directory_service,
        path_info_service,
        nar_calculation_service,
        build_service,
        Vec::new(),
    ));

    let listen_address = cli.listen_args.listen_address.unwrap_or_else(|| {
        "/tmp/snix-daemon.sock"
            .parse()
            .expect("invalid fallback listen address")
    });

    let mut listener = make_listener(&listen_address, &cli.listen_args.listener_options).await?;

    while let Ok((connection, _)) = listener.accept().await {
        let io = io.clone();
        tokio::spawn(async move {
            match NixDaemon::initialize(io.clone(), connection).await {
                Ok(mut daemon) => {
                    if let Err(error) = daemon.handle_client().await {
                        match error.kind() {
                            std::io::ErrorKind::UnexpectedEof => {
                                // client disconnected, nothing to do
                            }
                            _ => {
                                // otherwise log the error and disconnect
                                error!(error=?error, "client error");
                            }
                        }
                    }
                }
                Err(err) => {
                    error!(%err, "nix-daemon handshake failed");
                }
            }
        });
    }
    Ok(())
}
