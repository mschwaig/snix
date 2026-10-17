//! Editable ATerm preimages, deliberately outside the checked derivation model.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Deref, DerefMut};

use nom::{
    Parser, bytes::streaming::tag, character::streaming::char, combinator::all_consuming,
    multi::separated_list1, sequence::delimited,
};

use super::parse_error::{ErrorKind, NomError, NomResult};
use super::write::{self, AtermWriteable};
use super::{DerivationBuilder, DerivationError, OutputName, ParserError};
use crate::{
    nixhash::{HashAlgo, NixHash},
    store_path::{self, StorePath, StorePathName},
};

/// An output tuple in an unvalidated trace preimage.
///
/// Unlike checked [`super::Outputs`], this can represent floating CA outputs
/// and blank output paths used during derivation hashing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnvalidatedOutput {
    /// Concrete output path, or an unresolved/blank path.
    pub path: Option<StorePath>,
    /// Hash algorithm, including an optional `r:` prefix, or empty for IA.
    pub hash_algo: String,
    /// Hexadecimal fixed-output digest, or empty for IA/floating CA.
    pub hash: String,
}

/// A mutable derivation preimage, without semantic or output-path validation.
///
/// This is intended for constructive traces, not for executing builds. Parsing
/// still checks ATerm syntax, store paths, output names and hash encodings.
/// The builder's `outputs` field is unused; `outputs` here preserves the tuples.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnvalidatedDerivation {
    /// Non-output fields, using upstream's builder representation.
    pub builder: DerivationBuilder,
    /// Output tuples, including unresolved floating-CA outputs.
    pub outputs: BTreeMap<OutputName, UnvalidatedOutput>,
}

impl Deref for UnvalidatedDerivation {
    type Target = DerivationBuilder;
    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl DerefMut for UnvalidatedDerivation {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
    }
}

impl UnvalidatedDerivation {
    /// Parse a complete ATerm without validating build semantics or rewriting env.
    pub fn from_aterm_bytes(bytes: &[u8]) -> Result<Self, ParserError<&[u8]>> {
        match all_consuming(|i| super::parser::parse_with_outputs(i, parse_outputs)).parse(bytes) {
            Ok((_, (builder, outputs))) => Ok(Self { builder, outputs }),
            Err(nom::Err::Incomplete(_)) => Err(ParserError::Incomplete),
            Err(nom::Err::Error(e) | nom::Err::Failure(e)) => Err(e.into()),
        }
    }

    /// Serialize this preimage in canonical ATerm field order.
    pub fn to_aterm_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.builder
            .serialize_with_replacements(
                &mut bytes,
                &self.environment,
                self,
                self.input_derivations.iter(),
            )
            .expect("writing to Vec cannot fail");
        bytes
    }
}

impl AtermWriteable for UnvalidatedDerivation {
    fn aterm_write(&self, writer: &mut impl std::io::Write) -> std::io::Result<()> {
        write::write_char(writer, '[')?;
        for (i, (name, output)) in self.outputs.iter().enumerate() {
            if i != 0 {
                write::write_char(writer, ',')?;
            }
            let path = output
                .path
                .as_ref()
                .map(StorePath::to_absolute_path)
                .unwrap_or_default();
            write::write_char(writer, '(')?;
            write::write_array_elements(
                writer,
                [name.as_str(), &path, &output.hash_algo, &output.hash],
            )?;
            write::write_char(writer, ')')?;
        }
        write::write_char(writer, ']')
    }
}

fn parse_outputs(i: &[u8]) -> NomResult<&[u8], BTreeMap<OutputName, UnvalidatedOutput>> {
    let (rest, tuples) = delimited(
        char('['),
        separated_list1(tag(","), super::parser::parse_output_fields),
        char(']'),
    )
    .parse(i)?;
    let mut outputs = BTreeMap::new();
    for (name, path, hash_algo, hash) in tuples {
        let fail = |code| nom::Err::Failure(NomError { input: i, code });
        let name = name
            .parse::<OutputName>()
            .map_err(|e| fail(ErrorKind::InvalidOutputName(e)))?;
        let path = if path.is_empty() {
            None
        } else {
            Some(StorePath::from_absolute_path(path.as_bytes()).map_err(|e| fail(e.into()))?)
        };
        let hash =
            String::from_utf8(hash.into()).map_err(|_| fail(ErrorKind::InvalidOutputHash))?;
        if !hash_algo.is_empty() {
            let algo = hash_algo
                .strip_prefix("r:")
                .unwrap_or(&hash_algo)
                .parse::<HashAlgo>()
                .map_err(|e| fail(ErrorKind::NixHashError(e)))?;
            if !hash.is_empty() {
                let digest = data_encoding::HEXLOWER
                    .decode(hash.as_bytes())
                    .map_err(|e| {
                        fail(ErrorKind::NixHashError(
                            crate::nixhash::Error::InvalidBase16Encoding(e),
                        ))
                    })?;
                NixHash::from_algo_and_digest(algo, &digest)
                    .map_err(|e| fail(ErrorKind::NixHashError(e)))?;
            }
        } else if !hash.is_empty() {
            return Err(fail(ErrorKind::InvalidOutputHash));
        }
        if outputs
            .insert(
                name.clone(),
                UnvalidatedOutput {
                    path,
                    hash_algo,
                    hash,
                },
            )
            .is_some()
        {
            return Err(fail(ErrorKind::DuplicateMapKey(name.to_string())));
        }
    }
    Ok((rest, outputs))
}

/// Hash the original ATerm bytes, using the union of input drv/source references.
///
/// This accepts floating CA and noncanonical preimages without normalizing them.
pub fn calculate_derivation_path_from_aterm(
    name: &str,
    bytes: &[u8],
) -> Result<String, DerivationError> {
    let drv = UnvalidatedDerivation::from_aterm_bytes(bytes)
        .map_err(|e| DerivationError::InvalidATermError(format!("{e:?}")))?;
    let name = format!("{name}.drv");
    let name = StorePathName::from_str(&name)
        .map_err(|e| DerivationError::InvalidDerivationName(name.as_bytes().to_vec(), e.into()))?;
    let refs = drv
        .input_derivations
        .keys()
        .chain(drv.input_sources.iter())
        .map(StorePath::as_ref)
        .collect::<BTreeSet<_>>();
    Ok(store_path::build_text_path(name, bytes, refs).to_absolute_path())
}

#[cfg(test)]
mod tests {
    use super::super::UnverifiedDerivation;
    use super::*;

    const DEP: &str = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-dep.drv";
    const SRC: &str = "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-source";

    fn preimage(outputs: &str) -> String {
        format!(
            r#"Derive([{outputs}],[("{DEP}",["bin","out"])],["{SRC}"],"","",[],[("out","not-an-output-path")])"#
        )
    }

    #[test]
    fn floating_ca_and_noncanonical_env_roundtrip_without_validation() {
        for algo in ["sha256", "r:sha256", "r:sha1", "sha512", "md5"] {
            let bytes = preimage(&format!(r#"("bin","","{algo}",""),("out","","{algo}","")"#));
            let mut drv = UnvalidatedDerivation::from_aterm_bytes(bytes.as_bytes()).unwrap();
            assert_eq!(drv.to_aterm_bytes(), bytes.as_bytes());
            assert_eq!(drv.environment["out"].as_slice(), b"not-an-output-path");
            assert!(UnverifiedDerivation::from_aterm_bytes(bytes.as_bytes()).is_err());
            drv.input_derivations.clear();
            drv.input_sources
                .insert(StorePath::from_absolute_path(DEP.as_bytes()).unwrap());
            let rewritten = drv.to_aterm_bytes();
            let parsed = UnvalidatedDerivation::from_aterm_bytes(&rewritten).unwrap();
            assert!(parsed.input_derivations.is_empty());
            assert_eq!(parsed.input_sources.len(), 2);
        }
    }

    #[test]
    fn raw_hash_uses_all_references_not_nested_output_lists() {
        let bytes = preimage(r#"("out","","r:sha256","")"#);
        let refs = [DEP, SRC].map(|s| StorePath::from_absolute_path(s.as_bytes()).unwrap());
        let expected = store_path::build_text_path(
            StorePathName::from_str("test.drv").unwrap(),
            bytes.as_bytes(),
            refs.iter().map(StorePath::as_ref),
        )
        .to_absolute_path();
        assert_eq!(
            calculate_derivation_path_from_aterm("test", bytes.as_bytes()).unwrap(),
            expected
        );
    }

    #[test]
    fn references_with_same_digest_and_different_names_are_not_collapsed() {
        let bytes = preimage(r#"("out","","r:sha256","")"#)
            .replace(SRC, "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-source");
        let drv = UnvalidatedDerivation::from_aterm_bytes(bytes.as_bytes()).unwrap();
        let mut refs = drv.input_sources.clone();
        refs.extend(drv.input_derivations.keys().cloned());
        assert_eq!(refs.len(), 2);
        let paths: Vec<_> = refs.iter().map(StorePath::to_absolute_path).collect();
        assert!(paths[0] < paths[1]);
        let expected = store_path::build_text_path(
            StorePathName::from_str("test.drv").unwrap(),
            bytes.as_bytes(),
            refs.iter().map(StorePath::as_ref),
        )
        .to_absolute_path();
        assert_eq!(
            calculate_derivation_path_from_aterm("test", bytes.as_bytes()).unwrap(),
            expected
        );
    }

    #[test]
    fn preserves_non_utf8_and_escaped_aterm_fields() {
        let mut bytes =
            br#"Derive([("out","","r:sha256","")],[],[],"x","sh",["[\"],"],[("raw",""#.to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice(br#"\n\"\\")])"#);
        let drv = UnvalidatedDerivation::from_aterm_bytes(&bytes).unwrap();
        assert_eq!(drv.to_aterm_bytes(), bytes);
        assert!(
            calculate_derivation_path_from_aterm("raw", &bytes)
                .unwrap()
                .ends_with("-raw.drv")
        );
    }

    #[test]
    fn rejects_malformed_or_ambiguous_preimages() {
        for output in [
            r#"("out","","r:nohash","")"#,
            r#"("out","","sha256","00")"#,
            r#"("out","","","ff")"#,
            r#"("out","/not/store","","")"#,
            r#"("out","","",""),("out","","","")"#,
        ] {
            assert!(
                UnvalidatedDerivation::from_aterm_bytes(preimage(output).as_bytes()).is_err(),
                "{output}"
            );
        }
        let bytes = preimage(r#"("out","","r:sha256","")"#);
        assert!(calculate_derivation_path_from_aterm("../bad", bytes.as_bytes()).is_err());
        assert!(
            calculate_derivation_path_from_aterm("x", format!("{bytes}garbage").as_bytes())
                .is_err()
        );
        assert!(calculate_derivation_path_from_aterm("x", b"Derive(").is_err());
    }

    #[test]
    fn canonical_fixture_paths_match_upstream() {
        for entry in std::fs::read_dir("src/derivation/tests/derivation_tests/ok").unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) != Some("drv") {
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            let sp: StorePath = path.file_name().unwrap().to_str().unwrap().parse().unwrap();
            let name = sp.name().strip_drv_ext().unwrap();
            let raw = UnvalidatedDerivation::from_aterm_bytes(&bytes).unwrap();
            assert_eq!(raw.to_aterm_bytes(), bytes, "{}", path.display());
            assert_eq!(
                calculate_derivation_path_from_aterm(name.as_str(), &bytes).unwrap(),
                sp.to_absolute_path()
            );
        }
    }
}
