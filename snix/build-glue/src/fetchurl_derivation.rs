//! Code translating from a `builtin:derivation` [Derivation] to a [Fetch].
use crate::fetchers::Fetch;
use nix_compat::{
    derivation::{Derivation, OutputHash, OutputHashMode},
    store_path::StorePathName,
};
use tracing::instrument;

/// Parses a [Derivation] to a [Fetch] if using the `builtin:fetchurl` command and otherwise valid
///
/// If it doesn't use `builtin:fetchurl` as `command`, `Ok(None)` is returned.
/// If it uses `builtin:fetchurl`, but is otherwise invalid, an [Error] is returned.
/// Otherwise returns the synthesized [Fetch], as well as the name.
#[instrument]
pub fn fetchurl_derivation_to_fetch(
    drv: &Derivation,
) -> Result<Option<(&StorePathName, Fetch)>, Error> {
    if drv.command() != "builtin:fetchurl" {
        return Ok(None);
    }
    if !drv.arguments().is_empty() {
        return Err(Error::ArgumentsInvalid);
    }
    if drv.system() != "builtin" {
        return Err(Error::SystemInvalid);
    }

    // ensure this is a fixed-output derivation
    let Some(output_hash) = drv.outputs().as_fixed_output_hash() else {
        return Err(Error::NoFOD);
    };

    // parse `url` from the environment
    let url = std::str::from_utf8(drv.environment().get("url").ok_or(Error::URLMissing)?)
        .or(Err(Error::URLInvalid))?
        .parse()
        .or(Err(Error::URLInvalid))?;

    Ok(Some((
        drv.name(),
        match output_hash {
            OutputHash {
                mode: OutputHashMode::Flat,
                hash,
            } => Fetch::URL {
                url,
                exp_hash: Some(hash.to_owned()),
            },
            OutputHash {
                mode: OutputHashMode::Recursive,
                hash,
            } if drv.environment().get("executable").map(|b| b.as_slice()) == Some(b"1") => {
                Fetch::Executable {
                    url,
                    hash: hash.to_owned(),
                }
            }
            OutputHash {
                mode: OutputHashMode::Recursive,
                hash,
            } => Fetch::NAR {
                url,
                hash: hash.to_owned(),
            },
        },
    )))
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid arguments")]
    ArgumentsInvalid,
    #[error("Invalid system")]
    SystemInvalid,
    #[error("Derivation is not fixed-output")]
    NoFOD,
    #[error("Missing URL")]
    URLMissing,
    #[error("Invalid URL")]
    URLInvalid,
}
