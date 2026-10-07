//! Contains builtins that fetch paths from the Internet, or local filesystem.

use super::utils::select_string;
use crate::snix_store_io::SnixStoreIO;
use nix_compat::nixhash::{HashAlgo, NixHash};
use snix_eval::builtin_macros::builtins;
use snix_eval::generators::Gen;
use snix_eval::generators::GenCo;
use snix_eval::{CatchableErrorKind, ErrorKind, Value, try_cek};
use std::{rc::Rc, sync::Arc};
use url::Url;

// Used as a return type for extract_fetch_args, which is sharing some
// parsing code between the fetchurl and fetchTarball builtins.
struct NixFetchArgs {
    url: Url,
    name: Option<String>,
    sha256: Option<[u8; 32]>,
}

// `fetchurl` and `fetchTarball` accept a single argument, which can either be the URL (as string),
// or an attrset, where `url`, `sha256` and `name` keys are allowed.
async fn extract_fetch_args(
    co: &GenCo,
    args: Value,
) -> Result<Result<NixFetchArgs, CatchableErrorKind>, ErrorKind> {
    if let Ok(url_str) = args.to_str() {
        // Get the raw bytes, not the ToString repr.
        let url_str =
            String::from_utf8(url_str.as_bytes().to_vec()).map_err(|_| ErrorKind::Utf8)?;

        // Parse the URL.
        let url = Url::parse(&url_str).map_err(|e| ErrorKind::SnixError(Arc::from(e)))?;

        return Ok(Ok(NixFetchArgs {
            url,
            name: None,
            sha256: None,
        }));
    }

    let attrs = args.to_attrs().map_err(|_| ErrorKind::TypeError {
        expected: "attribute set or contextless string",
        actual: args.type_of(),
    })?;

    // Reject disallowed attrset keys, to match Nix' behaviour.
    // We complain about the first unexpected key we find in the list.
    const VALID_KEYS: [&[u8]; 3] = [b"url", b"name", b"sha256"];
    if let Some(first_invalid_key) = attrs.keys().find(|k| !&VALID_KEYS.contains(&k.as_bytes())) {
        return Err(ErrorKind::UnexpectedArgumentBuiltin(
            first_invalid_key.clone(),
        ));
    }

    let url_str = try_cek!(select_string(co, &attrs, "url").await?)
        .ok_or_else(|| ErrorKind::AttributeNotFound { name: "url".into() })?;
    let name = try_cek!(select_string(co, &attrs, "name").await?);
    let sha256_str = try_cek!(select_string(co, &attrs, "sha256").await?);

    Ok(Ok(NixFetchArgs {
        url: Url::parse(&url_str).map_err(|e| ErrorKind::SnixError(Arc::from(e)))?,
        name,
        // parse the sha256 string into a digest, and bail out if it's not sha256.
        sha256: sha256_str
            .map(
                |sha256_str| match NixHash::from_str(&sha256_str, Some(HashAlgo::Sha256)) {
                    Ok(NixHash::Sha256(digest)) => Ok(digest),
                    _ => Err(ErrorKind::InvalidHash(sha256_str)),
                },
            )
            .transpose()?,
    }))
}

#[allow(unused_variables)] // for the `state` arg, for now
#[builtins(state = "Rc<SnixStoreIO>")]
pub(crate) mod fetcher_builtins {
    use bstr::ByteSlice;
    use nix_compat::{flakeref, nixhash::NixHash};
    use snix_build_glue::fetchers::Fetch;
    use snix_eval::{NixContext, NixString, try_cek_to_value};
    use std::collections::BTreeMap;

    use super::*;

    /// Attempts to mimic `nix::libutil::baseNameOf`
    fn url_basename(url: &Url) -> &str {
        let s = url.path().trim_end_matches('/');

        match s.rsplit_once('/') {
            None => url.host_str().unwrap_or_default(),
            Some((_, basename)) => basename,
        }
    }

    /// Consumes a fetch.
    /// If there is enough info to calculate the store path without fetching,
    /// queue the fetch to be fetched lazily, and return the store path.
    /// If there's not enough info to calculate it, do the fetch now, and then
    /// return the store path.
    /// Note the builtins.typeof of fetchurl and fetchTarball are *not* "path", but "string",
    /// to stay bug-compatible with Nix.
    fn fetch_lazy(state: Rc<SnixStoreIO>, name: String, fetch: Fetch) -> Result<Value, ErrorKind> {
        let store_path = match fetch
            .store_path(&name)
            .map_err(|e| ErrorKind::SnixError(Arc::from(e)))?
        {
            Some(store_path) => {
                // Move the fetch to KnownPaths, so it can be actually fetched later.
                let sp = state
                    .build_state
                    .known_paths
                    .write()
                    .add_fetch(fetch, &name)
                    .expect("Snix bug: should only fail if the store path cannot be calculated");

                debug_assert_eq!(
                    sp, store_path,
                    "calculated store path by KnownPaths should match"
                );
                sp
            }
            None => {
                // If we don't have enough info, do the fetch now.
                let (store_path, _path_info) = state
                    .tokio_handle
                    .block_on(async {
                        state
                            .build_state
                            .fetcher
                            .ingest_and_persist(&name, fetch)
                            .await
                    })
                    .map_err(|e| ErrorKind::SnixError(Arc::from(e)))?;

                store_path
            }
        };

        let s = store_path.to_absolute_path();

        // Emit the calculated Store Path, which needs to have context.
        let context = NixContext::new().append(snix_eval::NixContextElement::Plain(s.clone()));
        Ok(Value::String(NixString::new_context_from(context, s)))
    }

    #[builtin("fetchurl")]
    async fn builtin_fetchurl(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        args: Value,
    ) -> Result<Value, ErrorKind> {
        let args = try_cek_to_value!(extract_fetch_args(&co, args).await?);

        // Derive the name from the URL basename if not set explicitly.
        let name = args
            .name
            .unwrap_or_else(|| url_basename(&args.url).to_owned());

        fetch_lazy(
            state,
            name,
            Fetch::URL {
                url: args.url,
                exp_hash: args.sha256.map(NixHash::Sha256),
            },
        )
    }

    #[builtin("fetchTarball")]
    async fn builtin_fetch_tarball(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        args: Value,
    ) -> Result<Value, ErrorKind> {
        let args = try_cek_to_value!(extract_fetch_args(&co, args).await?);

        // Name defaults to "source" if not set explicitly.
        const DEFAULT_NAME_FETCH_TARBALL: &str = "source";
        let name = args
            .name
            .unwrap_or_else(|| DEFAULT_NAME_FETCH_TARBALL.to_owned());

        fetch_lazy(
            state,
            name,
            Fetch::Tarball {
                url: args.url,
                exp_nar_sha256: args.sha256,
            },
        )
    }

    #[builtin("fetchGit")]
    async fn builtin_fetch_git(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        args: Value,
    ) -> Result<Value, ErrorKind> {
        Err(ErrorKind::NotImplemented("fetchGit"))
    }

    // FUTUREWORK: make it a feature flag once #64 is implemented
    #[builtin("parseFlakeRef")]
    async fn builtin_parse_flake_ref(
        state: Rc<SnixStoreIO>,
        co: GenCo,
        value: Value,
    ) -> Result<Value, ErrorKind> {
        let flake_ref = value.to_str()?;
        let flake_ref_str = flake_ref.to_str()?;

        let fetch_args = flake_ref_str
            .parse()
            .map_err(|err| ErrorKind::SnixError(Arc::new(err)))?;

        // Convert the FlakeRef to our Value format
        let mut attrs = BTreeMap::new();

        // Extract type and url based on the variant
        match fetch_args {
            flakeref::FlakeRef::Git { url, .. } => {
                attrs.insert("type".into(), Value::from("git"));
                attrs.insert("url".into(), Value::from(url.to_string()));
            }
            flakeref::FlakeRef::GitHub {
                owner, repo, r#ref, ..
            } => {
                attrs.insert("type".into(), Value::from("github"));
                attrs.insert("owner".into(), Value::from(owner));
                attrs.insert("repo".into(), Value::from(repo));
                if let Some(ref_name) = r#ref {
                    attrs.insert("ref".into(), Value::from(ref_name));
                }
            }
            flakeref::FlakeRef::GitLab { owner, repo, .. } => {
                attrs.insert("type".into(), Value::from("gitlab"));
                attrs.insert("owner".into(), Value::from(owner));
                attrs.insert("repo".into(), Value::from(repo));
            }
            flakeref::FlakeRef::File { url, .. } => {
                attrs.insert("type".into(), Value::from("file"));
                attrs.insert("url".into(), Value::from(url.to_string()));
            }
            flakeref::FlakeRef::Tarball { url, .. } => {
                attrs.insert("type".into(), Value::from("tarball"));
                attrs.insert("url".into(), Value::from(url.to_string()));
            }
            flakeref::FlakeRef::Path { path, .. } => {
                attrs.insert("type".into(), Value::from("path"));
                attrs.insert(
                    "path".into(),
                    Value::from(path.to_string_lossy().into_owned()),
                );
            }
            _ => {
                // For all other ref types, return a simple type/url attributes
                attrs.insert("type".into(), Value::from("indirect"));
                attrs.insert("url".into(), Value::from(flake_ref_str));
            }
        }

        Ok(Value::Attrs(attrs.into()))
    }

    #[cfg(test)]
    mod tests {
        mod url_basename {
            use super::super::*;
            use rstest::rstest;

            #[rstest]
            #[case::empty_path("", "localhost")]
            #[case::path_on_root("/dir", "dir")]
            #[case::relative_path("dir/foo", "foo")]
            #[case::root_with_trailing_slash("/", "localhost")]
            #[case::root_with_many_trailing_slashes("///", "localhost")]
            #[case::trailing_slash("/dir/", "dir")]
            #[case::many_trailing_slashes("/dir//", "dir")]
            fn test_url_basename(#[case] url_path: &str, #[case] exp_basename: &str) {
                let mut url = Url::parse("http://localhost").expect("invalid url");
                url.set_path(url_path);
                assert_eq!(url_basename(&url), exp_basename);
            }
        }
    }
}
