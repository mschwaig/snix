use crate::store_path::{
    self, build_ca_path, build_output_path, build_text_path, StorePath, StorePathRef,
};
use bstr::BString;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io;

mod errors;
mod output;
mod parse_error;
mod parser;
mod validate;
mod write;

#[cfg(test)]
mod tests;

// Public API of the crate.
pub use crate::nixhash::{CAHash, NixHash};
pub use errors::{DerivationError, OutputError};
pub use output::{CAFloatingAlgo, Output};
pub use parser::Error as ParserError;

use self::write::AtermWriteable;

/// Calculates a derivation path from an ATerm representation without fully parsing it.
///
/// This function extracts only the necessary reference information from the ATerm 
/// representation to calculate the store path, without constructing a complete
/// Derivation object. It's designed to be resilient to changes in the ATerm format
/// and efficiently calculate paths for derivations.
///
/// # Arguments
///
/// * `name` - The name of the derivation (used in the resulting path)
/// * `aterm_str` - The ATerm string representation of the derivation
///
/// # Returns
///
/// * `Result<String, DerivationError>` - The calculated store path or an error
pub fn calculate_derivation_path_from_aterm(
    name: &str,
    aterm_str: &[u8],
) -> Result<String, DerivationError> {
    // Append .drv to the name
    let name = format!("{}.drv", name);
    
    // Extract the references from the derivation ATerm
    let references = extract_references_from_aterm(aterm_str)?;
    
    // Use the same path building function as the method does, 
    // directly with the provided ATerm string
    let store_path: crate::store_path::StorePath<String> = crate::store_path::build_text_path(&name, aterm_str, references)
        .map_err(|_e| DerivationError::InvalidOutputName(name))?;

    Ok(store_path.to_absolute_path())
}

/// Extracts only the references from a derivation ATerm.
/// 
/// This is a minimal parser that only looks for input derivations and input sources
/// within the ATerm, without validating the other fields. It directly extracts the
/// referenced store paths without requiring the ATerm to be fully parseable.
fn extract_references_from_aterm(aterm_str: &[u8]) -> Result<std::collections::BTreeSet<String>, DerivationError> {
    // Derivation ATerm format:
    // Derive([outputs...],[input_derivations...],[input_sources...],system,builder,args,env)
    
    let aterm_str = std::str::from_utf8(aterm_str)
        .map_err(|e| DerivationError::InvalidATermError(format!("Invalid UTF-8 in ATerm: {}", e)))?;
    
    // Create an empty set to collect references
    let mut references = std::collections::BTreeSet::new();
    
    // Look for input sources list - this is the third parameter to Derive
    // It appears as a list like: ["/nix/store/path1","/nix/store/path2",...]
    
    // Find where the third bracket starts
    if let Some(input_sources_start) = find_nth_list_start(aterm_str, 3) {
        // Find where the list ends
        if let Some(input_sources_end) = find_matching_bracket(aterm_str, input_sources_start) {
            // Extract input sources list content
            let input_sources_list = &aterm_str[input_sources_start + 1..input_sources_end];
            
            // Parse the list items
            for path in parse_string_list(input_sources_list) {
                // Only add store paths
                if path.starts_with("/nix/store/") {
                    references.insert(path);
                }
            }
        }
    }
    
    // Look for input derivations, which is the second parameter
    // ATerm format for input derivations is more complex and involves key-value pairs
    // But for our purpose, we just need to extract any store paths
    
    // Find where the second bracket starts
    if let Some(input_derivs_start) = find_nth_list_start(aterm_str, 2) {
        // Find where the list ends
        if let Some(input_derivs_end) = find_matching_bracket(aterm_str, input_derivs_start) {
            // Extract input derivations list content
            let input_derivs_list = &aterm_str[input_derivs_start + 1..input_derivs_end];
            
            // Parse the list items, looking for store paths
            for path in input_derivs_list.split(',') {
                if let Some(store_path) = extract_store_path(path) {
                    references.insert(store_path.to_string());
                }
            }
        }
    }
    
    // Debug output
    #[cfg(test)]
    println!("Extracted references: {:#?}", references);
    
    Ok(references)
}

/// Find the start position of the nth list in an ATerm string
fn find_nth_list_start(s: &str, n: usize) -> Option<usize> {
    let mut count = 0;
    let mut in_string = false;
    let mut escape = false;
    
    for (i, c) in s.char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
        } else {
            if c == '"' {
                in_string = true;
            } else if c == '[' {
                count += 1;
                if count == n {
                    return Some(i);
                }
            }
        }
    }
    
    None
}

/// Find the matching closing bracket for the opening bracket at the given position
fn find_matching_bracket(s: &str, opening_pos: usize) -> Option<usize> {
    let mut depth = 0;
    let mut in_string = false;
    let mut escape = false;
    
    for (i, c) in s[opening_pos..].char_indices() {
        if in_string {
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
        } else {
            if c == '"' {
                in_string = true;
            } else if c == '[' {
                depth += 1;
            } else if c == ']' {
                depth -= 1;
                if depth == 0 {
                    return Some(opening_pos + i);
                }
            }
        }
    }
    
    None
}

/// Parse a list of quoted strings
fn parse_string_list(s: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_string = false;
    let mut escape = false;
    
    for c in s.chars() {
        if in_string {
            if escape {
                // Handle escaped characters
                match c {
                    'n' => current.push('\n'),
                    'r' => current.push('\r'),
                    't' => current.push('\t'),
                    _ => current.push(c),
                }
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
                // We've completed a string, add it to the result
                result.push(current.clone());
                current.clear();
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_string = true;
        }
    }
    
    result
}

/// Extract a store path from a substring, if present
fn extract_store_path(s: &str) -> Option<&str> {
    // Find a store path pattern in the string
    let store_path_start = s.find("/nix/store/")?;
    
    // Extract everything from the start of the store path to the next quote or comma
    let mut end = s.len();
    for (i, c) in s[store_path_start..].char_indices() {
        if c == '"' || c == ',' || c == ')' {
            end = store_path_start + i;
            break;
        }
    }
    
    Some(&s[store_path_start..end])
}

/// Error type for derivation ATerm parsing issues
#[derive(Debug, thiserror::Error)]
pub enum ATermParsingError {
    #[error("Invalid derivation ATerm format: {0}")]
    InvalidFormat(String),
}


#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Derivation {
    #[serde(rename = "args")]
    pub arguments: Vec<String>,

    pub builder: String,

    #[serde(rename = "env")]
    pub environment: BTreeMap<String, BString>,

    /// Map from drv path to output names used from this derivation.
    #[serde(rename = "inputDrvs")]
    pub input_derivations: BTreeMap<StorePath<String>, BTreeSet<String>>,

    /// Plain store paths of additional inputs.
    #[serde(rename = "inputSrcs")]
    pub input_sources: BTreeSet<StorePath<String>>,

    /// Maps output names to Output.
    pub outputs: BTreeMap<String, Output>,

    pub system: String,
}

impl Derivation {
    /// write the Derivation to the given [std::io::Write], in ATerm format.
    ///
    /// The only errors returns are these when writing to the passed writer.
    pub fn serialize(&self, writer: &mut impl std::io::Write) -> Result<(), io::Error> {
        self.serialize_with_replacements(writer, &self.input_derivations)
    }

    /// Like `serialize` but allow replacing the input_derivations for hash calculations.
    fn serialize_with_replacements(
        &self,
        writer: &mut impl std::io::Write,
        input_derivations: &BTreeMap<impl AtermWriteable, BTreeSet<String>>,
    ) -> Result<(), io::Error> {
        use write::*;

        writer.write_all(write::DERIVATION_PREFIX.as_bytes())?;
        write_char(writer, write::PAREN_OPEN)?;

        write_outputs(writer, &self.outputs)?;
        write_char(writer, COMMA)?;

        write_input_derivations(writer, input_derivations)?;
        write_char(writer, COMMA)?;

        write_input_sources(writer, &self.input_sources)?;
        write_char(writer, COMMA)?;

        write_system(writer, &self.system)?;
        write_char(writer, COMMA)?;

        write_builder(writer, &self.builder)?;
        write_char(writer, COMMA)?;

        write_arguments(writer, &self.arguments)?;
        write_char(writer, COMMA)?;

        write_environment(writer, &self.environment)?;

        write_char(writer, PAREN_CLOSE)?;

        Ok(())
    }

    /// return the ATerm serialization.
    pub fn to_aterm_bytes(&self) -> Vec<u8> {
        self.to_aterm_bytes_with_replacements(&self.input_derivations)
    }

    /// Like `to_aterm_bytes`, but accept a different BTreeMap for input_derivations.
    /// This is used to render the ATerm representation of a Derivation "modulo
    /// fixed-output derivations".
    fn to_aterm_bytes_with_replacements(
        &self,
        input_derivations: &BTreeMap<impl AtermWriteable, BTreeSet<String>>,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();

        // invoke serialize and write to the buffer.
        // Note we only propagate errors writing to the writer in serialize,
        // which won't panic for the string we write to.
        self.serialize_with_replacements(&mut buffer, input_derivations)
            .unwrap();

        buffer
    }

    /// Parse an Derivation in ATerm serialization, and validate it passes our
    /// set of validations.
    pub fn from_aterm_bytes(b: &[u8]) -> Result<Derivation, parser::Error<&[u8]>> {
        parser::parse(b)
    }

    /// Parse a Derivation in ATerm serialization *without* invoking
    /// [`Derivation::validate`].
    ///
    /// This is intended for callers that operate on partially-resolved or
    /// otherwise non-canonical derivations (e.g. computing the resolved-input
    /// hash of an unresolved derivation by editing the parsed struct and
    /// re-serializing). The bytes still need to be syntactically valid ATerm.
    pub fn from_aterm_bytes_unchecked(
        b: &[u8],
    ) -> Result<Derivation, parser::Error<&[u8]>> {
        parser::parse_unchecked(b)
    }

    /// Returns the drv path of a [Derivation] struct.
    ///
    /// The drv path is calculated by invoking [build_text_path], using
    /// the `name` with a `.drv` suffix as name, all [Derivation::input_sources] and
    /// keys of [Derivation::input_derivations] as references, and the ATerm string of
    /// the [Derivation] as content.
    pub fn calculate_derivation_path(
        &self,
        name: &str,
    ) -> Result<StorePath<String>, DerivationError> {
        // append .drv to the name
        let name = format!("{}.drv", name);

        // collect the list of paths from input_sources and input_derivations
        // into a (sorted, guaranteed by BTreeSet) list of references
        let references: BTreeSet<String> = self
            .input_sources
            .iter()
            .chain(self.input_derivations.keys())
            .map(StorePath::to_absolute_path)
            .collect();

        build_text_path(&name, self.to_aterm_bytes(), references)
            .map_err(|_e| DerivationError::InvalidOutputName(name))
    }

    /// Returns the FOD digest, if the derivation is fixed-output, or None if
    /// it's not.
    /// TODO: this is kinda the string from [build_ca_path] with a
    /// [CAHash::Flat], what's fed to `build_store_path_from_fingerprint_parts`
    /// (except the out_output.path being an empty string)
    pub fn fod_digest(&self) -> Option<[u8; 32]> {
        if self.outputs.len() != 1 {
            return None;
        }

        let out_output = self.outputs.get("out")?;
        let ca_hash = out_output.ca_hash.as_ref()?;

        Some(
            Sha256::new_with_prefix(format!(
                "fixed:out:{}{}:{}",
                ca_kind_prefix(ca_hash),
                ca_hash.hash().to_nix_hex_string(),
                out_output
                    .path
                    .as_ref()
                    .map(StorePath::to_absolute_path)
                    .unwrap_or_default(),
            ))
            .finalize()
            .into(),
        )
    }

    /// Calculates the hash of a derivation modulo fixed-output subderivations.
    ///
    /// This is called `hashDerivationModulo` in nixcpp.
    ///
    /// It returns the sha256 digest of the derivation ATerm representation,
    /// except that:
    ///  -  any input derivation paths have beed replaced "by the result of a
    ///     recursive call to this function" and that
    ///  - for fixed-output derivations the special
    ///    `fixed:out:${algo}:${digest}:${fodPath}` string is hashed instead of
    ///    the A-Term.
    ///
    /// It's up to the caller of this function to provide a (infallible) lookup
    /// function to query the [Derivation::hash_derivation_modulo] of direct
    /// input derivations, by their [StorePathRef].
    /// It will only be called in case the derivation is not a fixed-output
    /// derivation.
    pub fn hash_derivation_modulo<F>(&self, fn_lookup_hash_derivation_modulo: F) -> [u8; 32]
    where
        F: Fn(&StorePathRef) -> [u8; 32],
    {
        // Fixed-output derivations return a fixed hash.
        // Non-Fixed-output derivations return the sha256 digest of the ATerm
        // notation, but with all input_derivation paths replaced by a recursive
        // call to this function.
        // We call [fn_lookup_hash_derivation_modulo] rather than recursing
        // ourselves, so callers can precompute this.
        self.fod_digest().unwrap_or({
            // For each input_derivation, look up the hash derivation modulo,
            // and replace the derivation path in the aterm with it's HEXLOWER digest.
            let aterm_bytes = self.to_aterm_bytes_with_replacements(&BTreeMap::from_iter(
                self.input_derivations
                    .iter()
                    .map(|(drv_path, output_names)| {
                        let hash = fn_lookup_hash_derivation_modulo(&drv_path.as_ref());

                        (hash, output_names.to_owned())
                    }),
            ));

            // write the ATerm of that to the hash function and return its digest.
            Sha256::new_with_prefix(aterm_bytes).finalize().into()
        })
    }

    /// This calculates all output paths of a Derivation and updates the struct.
    /// It requires the struct to be initially without output paths.
    /// This means, self.outputs[$outputName].path needs to be an empty string,
    /// and self.environment[$outputName] needs to be an empty string.
    ///
    /// Output path calculation requires knowledge of the
    /// [Derivation::hash_derivation_modulo], which (in case of non-fixed-output
    /// derivations) also requires knowledge of the
    /// [Derivation::hash_derivation_modulo] of input derivations (recursively).
    ///
    /// To avoid recursing and doing unnecessary calculation, we simply
    /// ask the caller of this function to provide the result of the
    /// [Derivation::hash_derivation_modulo] call of the current [Derivation],
    /// and leave it up to them to calculate it when needed.
    ///
    /// On completion, `self.environment[$outputName]` and
    /// `self.outputs[$outputName].path` are set to the calculated output path for all
    /// outputs.
    pub fn calculate_output_paths(
        &mut self,
        name: &str,
        hash_derivation_modulo: &[u8; 32],
    ) -> Result<(), DerivationError> {
        // The fingerprint and hash differs per output
        for (output_name, output) in self.outputs.iter_mut() {
            // Assert that outputs are not yet populated, to avoid using this function wrongly.
            // We don't also go over self.environment, but it's a sufficient
            // footgun prevention mechanism.
            assert!(output.path.is_none());

            let path_name = output_path_name(name, output_name);

            // For fixed output derivation we use [build_ca_path], otherwise we
            // use [build_output_path] with [hash_derivation_modulo].
            let store_path = if let Some(ref hwm) = output.ca_hash {
                build_ca_path(&path_name, hwm, Vec::<&str>::new(), false).map_err(|e| {
                    DerivationError::InvalidOutputDerivationPath(output_name.to_string(), e)
                })?
            } else {
                build_output_path(hash_derivation_modulo, output_name, &path_name).map_err(|e| {
                    DerivationError::InvalidOutputDerivationPath(
                        output_name.to_string(),
                        store_path::BuildStorePathError::InvalidStorePath(e),
                    )
                })?
            };

            self.environment.insert(
                output_name.to_string(),
                store_path.to_absolute_path().into(),
            );
            output.path = Some(store_path);
        }

        Ok(())
    }
}

#[cfg(feature = "async")]
#[allow(dead_code)]
trait DerivationAsyncExt {
    /// Parse an Derivation in ATerm serialization, and validate it passes
    /// our set of validations, from a asynchronous buffered reader.
    /// This is a streaming variant of [Derivation::from_aterm_bytes].
    async fn from_streaming_aterm_bytes<R>(reader: R) -> Result<Derivation, parser::Error<Vec<u8>>>
    where
        R: tokio::io::AsyncBufRead + Unpin + Send;
}

#[cfg(feature = "async")]
impl DerivationAsyncExt for Derivation {
    async fn from_streaming_aterm_bytes<R>(
        mut reader: R,
    ) -> Result<Derivation, parser::Error<Vec<u8>>>
    where
        R: tokio::io::AsyncBufRead + Unpin + Send,
    {
        use tokio::io::AsyncBufReadExt;
        let mut buffer = Vec::new();
        loop {
            let rest = reader.fill_buf().await.unwrap();
            let length = rest.len();

            // We reached EOF, we can stop and return incompleteness.
            if length == 0 {
                return Err(ParserError::Incomplete);
            }

            buffer.extend_from_slice(rest);

            // Parse the so-far internal buffer of reader.
            match parser::parse_streaming(&buffer) {
                (Err(parser::Error::Incomplete), _) => {
                    reader.consume(length);
                    continue;
                }
                (Ok(derivation), leftover) => {
                    // We cannot inline it in the next call because `reader` is mutably borrowed
                    // and has a relationship with the lifetime of `leftover`.
                    let leftover_length = leftover.len();

                    // Well, if we already had consumed the leftovers of the past fetch
                    // while believing we were just parsing incomplete ATerm, there's nothing
                    // we can do about it. The protocol is made this way.
                    if length >= leftover_length {
                        // We still have leftover, let's not consume it.
                        // It's not for us.
                        reader.consume(length - leftover_length);
                    }
                    return Ok(derivation);
                }
                (Err(e), _) => {
                    return Err(e.into());
                }
            }
        }
    }
}

/// Calculate the name part of the store path of a derivation [Output].
///
/// It's the name, and (if it's the non-out output), the output name
/// after a `-`.
fn output_path_name(derivation_name: &str, output_name: &str) -> String {
    let mut output_path_name = derivation_name.to_string();
    if output_name != "out" {
        output_path_name.push('-');
        output_path_name.push_str(output_name);
    }
    output_path_name
}

/// For a [CAHash], return the "prefix" used for NAR purposes.
/// For [CAHash::Flat], this is an empty string, for [CAHash::Nar], it's "r:".
/// Panics for other [CAHash] kinds, as they're not valid in a derivation
/// context.
fn ca_kind_prefix(ca_hash: &CAHash) -> &'static str {
    match ca_hash {
        CAHash::Flat(_) => "",
        CAHash::Nar(_) => "r:",
        _ => panic!("invalid ca hash in derivation context: {:?}", ca_hash),
    }
}
