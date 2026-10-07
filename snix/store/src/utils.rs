use std::{collections::HashMap, sync::Arc};

use snix_castore::blob_engine::{self, BlobEngine};
use snix_castore::blobstore::BlobStore;
use snix_castore::chunkstore::ChunkStore;
use snix_castore::directoryservice::DirectoryService;
use snix_castore::utils as castore_utils;
use url::Url;

use crate::composition::REG;
use crate::nar::NarCalculationService;
use crate::pathinfoservice::PathInfoService;
use snix_castore::composition::{
    Composition, DeserializeWithRegistry, ServiceBuilder, with_registry,
};

#[derive(serde::Deserialize, Default)]
pub struct CompositionConfigs {
    pub blob_stores:
        HashMap<String, DeserializeWithRegistry<Box<dyn ServiceBuilder<Output = dyn BlobStore>>>>,
    pub chunk_stores:
        HashMap<String, DeserializeWithRegistry<Box<dyn ServiceBuilder<Output = dyn ChunkStore>>>>,
    pub directoryservices: HashMap<
        String,
        DeserializeWithRegistry<Box<dyn ServiceBuilder<Output = dyn DirectoryService>>>,
    >,
    pub pathinfoservices: HashMap<
        String,
        DeserializeWithRegistry<Box<dyn ServiceBuilder<Output = dyn PathInfoService>>>,
    >,
}

/// Provides a set of clap arguments to configure snix-\[ca\]store services.
///
/// This particular variant has defaults tailored for usecases accessing data
/// directly locally, like the `snix store daemon` command.
#[derive(clap::Parser, Clone)]
#[group(id = "StoreServiceUrls")]
pub struct ServiceUrls {
    #[clap(flatten)]
    pub castore_service_addrs: castore_utils::ServiceUrls,

    #[arg(long, env, default_value = "redb:/var/lib/snix-store/pathinfo.redb")]
    pub path_info_service_addr: String,
}

/// Provides a set of clap arguments to configure snix-\[ca\]store services.
///
/// This particular variant has defaults tailored for usecases accessing data
/// from another running snix daemon, via gRPC.
#[derive(clap::Parser, Clone)]
#[group(id = "StoreServiceUrlsGrpc")]
pub struct ServiceUrlsGrpc {
    #[clap(flatten)]
    castore_service_addrs: castore_utils::ServiceUrlsGrpc,

    #[arg(long, env, default_value = "grpc+http://[::1]:8000")]
    path_info_service_addr: String,
}

/// Provides a set of clap arguments to configure snix-\[ca\]store services.
///
/// This particular variant has defaults tailored for usecases keeping all data
/// in memory.
/// It's currently used in snix-cli-eval, as we don't really care about persistency
/// there yet, and using something else here might make some perf output harder
/// to interpret.
#[derive(clap::Parser, Clone)]
#[group(id = "StoreServiceUrlsMemory")]
pub struct ServiceUrlsMemory {
    #[clap(flatten)]
    castore_service_addrs: castore_utils::ServiceUrlsMemory,

    #[arg(long, env, default_value = "redb+memory:")]
    path_info_service_addr: String,
}

impl From<ServiceUrlsGrpc> for ServiceUrls {
    fn from(urls: ServiceUrlsGrpc) -> ServiceUrls {
        ServiceUrls {
            castore_service_addrs: urls.castore_service_addrs.into(),
            path_info_service_addr: urls.path_info_service_addr,
        }
    }
}

impl From<ServiceUrlsMemory> for ServiceUrls {
    fn from(urls: ServiceUrlsMemory) -> ServiceUrls {
        ServiceUrls {
            castore_service_addrs: urls.castore_service_addrs.into(),
            path_info_service_addr: urls.path_info_service_addr,
        }
    }
}

/// Deserializes service addresses into composition config, configuring each
/// service as the single "root".
/// If the `xp-composition-cli` feature is enabled, and a file specified in the
/// `--experimental-store-composition` parameter, this is used instead.
pub async fn addrs_to_configs(
    urls: impl Into<ServiceUrls>,
) -> Result<CompositionConfigs, Box<dyn std::error::Error + Send + Sync>> {
    let ServiceUrls {
        castore_service_addrs,
        path_info_service_addr,
    } = urls.into();

    #[cfg(feature = "xp-composition-cli")]
    if let Some(conf_path) = castore_service_addrs.experimental_store_composition {
        let conf_text = tokio::fs::read_to_string(conf_path).await?;
        return Ok(with_registry(&REG, || toml::from_str(&conf_text))?);
    }

    let mut configs: CompositionConfigs = Default::default();

    let blob_store_url = Url::parse(&castore_service_addrs.blob_store_addr)?;
    let chunk_store_url = Url::parse(&castore_service_addrs.chunk_store_addr)?;
    let directory_service_url = Url::parse(&castore_service_addrs.directory_service_addr)?;
    let path_info_service_url = Url::parse(&path_info_service_addr)?;

    configs.blob_stores.insert(
        "root".into(),
        with_registry(&REG, || blob_store_url.try_into())?,
    );
    configs.chunk_stores.insert(
        "root".into(),
        with_registry(&REG, || chunk_store_url.try_into())?,
    );
    configs.directoryservices.insert(
        "root".into(),
        with_registry(&REG, || directory_service_url.try_into())?,
    );
    configs.pathinfoservices.insert(
        "root".into(),
        with_registry(&REG, || path_info_service_url.try_into())?,
    );

    Ok(configs)
}

/// Construct the store handles from their addrs.
pub async fn construct_services(
    urls: impl Into<ServiceUrls>,
) -> Result<
    (
        Arc<dyn BlobStore>,
        Arc<dyn ChunkStore>,
        Arc<dyn BlobEngine>,
        Arc<dyn DirectoryService>,
        Arc<dyn PathInfoService>,
        Arc<dyn NarCalculationService>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let configs = addrs_to_configs(urls).await?;
    construct_services_from_configs(configs).await
}

/// Construct the store handles from their addrs.
pub async fn construct_services_from_configs(
    configs: CompositionConfigs,
) -> Result<
    (
        Arc<dyn BlobStore>,
        Arc<dyn ChunkStore>,
        Arc<dyn BlobEngine>,
        Arc<dyn DirectoryService>,
        Arc<dyn PathInfoService>,
        Arc<dyn NarCalculationService>,
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let mut comp = Composition::new(&REG);

    comp.extend(configs.blob_stores);
    comp.extend(configs.chunk_stores);
    comp.extend(configs.directoryservices);
    comp.extend(configs.pathinfoservices);

    let blob_store: Arc<dyn BlobStore> = comp.build("root").await?;
    let chunk_store: Arc<dyn ChunkStore> = comp.build("root").await?;
    let blob_engine: Arc<dyn BlobEngine> = Arc::new(
        blob_engine::ChunkingBlobEngine::builder()
            .blob_store(blob_store.clone())
            .chunk_store(chunk_store.clone())
            .build(),
    );

    let directory_service: Arc<dyn DirectoryService> = comp.build("root").await?;
    let path_info_service: Arc<dyn PathInfoService> = comp.build("root").await?;

    // HACK: The grpc client also implements NarCalculationService, and we
    // really want to use it (otherwise we'd need to fetch everything again for hashing).
    // Until we revamped store composition and config, detect this special case here.
    let nar_calculation_service: Arc<dyn NarCalculationService> = path_info_service
        .nar_calculation_service()
        .unwrap_or_else(|| {
            Arc::new(crate::nar::Renderer::new(
                blob_engine.clone(),
                directory_service.clone(),
            ))
        });

    Ok((
        blob_store,
        chunk_store,
        blob_engine,
        directory_service,
        path_info_service,
        nar_calculation_service,
    ))
}

/// Returns a new [PathInfoService]. Should only be used for tests.
pub fn gen_test_pathinfo_service() -> impl PathInfoService + Clone {
    crate::pathinfoservice::RedbPathInfoService::new_temporary(
        "test".to_string(),
        crate::pathinfoservice::RedbPathInfoServiceConfig::default(),
    )
    .expect("creating pathinfoservice to succeed")
}
