# Laut Fork on Current Snix

This fork is based on upstream `b9dba2b9735798c13d73c08a1b08ae3c7bed7136`
(2026-10-13). It replaces the additions in the 20-commit fork ending at
`95cd1ba7515d409edaf0dfb249f6cdf327f4c209`; it does not roll upstream APIs back.

## Retained Functionality

- `laut_compat::content_hash`: NAR SHA256/hash size, empty-name castore Entry
  encoding, reference scanning, and both IA-to-synthetic-CA rewrite passes.
- `nix_compat::derivation::calculate_derivation_path_from_aterm`: hashes the
  original bytes with the sorted, deduplicated union of input drv/source paths.
  It shares upstream's ATerm parser, including byte-valued environment fields.
- `nix_compat::derivation::UnvalidatedDerivation`: mutable ATerm preimages,
  including floating CA and blank output paths, without build validation or
  normalization of environment values. This is not an executable derivation.
- `nix_compat::store_path::hash_upstream_placeholder`: Nix upstream-output
  placeholders, using upstream's validated store-path and output-name types.
- Borrowed `SigningKey::signing_key` and `VerifyingKey::verifying_key` accessors
  for signing/verifying arbitrary messages such as JWS payloads.
- Castore's `RewritePattern`, `rewrite_in_place`, `RewritingReferenceReader`,
  and filesystem ingestion with length-preserving file/symlink rewrites.

The old floating-output fields are not patched into checked upstream outputs.
Upstream `Derivation` and `UnverifiedDerivation` retain their invariants and
builder APIs. The old CA self-reference inversion patch is unnecessary:
upstream `build_ca_path` already handles `has_self_ref` correctly. Memory
blob/directory service exports and `SimpleRenderer` patches are replaced by
`ChunkingBlobEngine`, memory blob/chunk stores, in-memory `RedbDirectoryService`,
and upstream `Renderer`.

The streaming rewriter performs simultaneous substitutions: replacement bytes
are never scanned again at a buffer boundary. This also supports identity
rewrites with accurate recorded positions. Reference lists passed to pass 1 are
parsed, sorted, and deduplicated before path construction.
Store-path ordering also compares names when digests are equal, preserving
distinct references in ordered maps/sets and keeping `Ord` consistent with `Eq`.

## Laut API Migration

Laut has deliberately not been edited. Its current checkout does **not** compile
against this revision without the following source changes.

1. Replace every `StorePath<String>` and `StorePath::<String>` with `StorePath`.
   Parsing absolute paths still takes bytes. The parsing error is now
   `nix_compat::store_path::ParseStorePathError`, not `store_path::Error`.
   `StorePath::name()` returns `&StorePathName`; use `.name().as_str()` for a
   borrowed string or `.name().to_string()` for an owned string.
2. In `laut-sign/src/constructive_trace.rs`, import
   `UnvalidatedDerivation as Derivation` instead of the checked `Derivation`.
   Replace `from_aterm_bytes_unchecked` with `from_aterm_bytes`. The
   `input_derivations` and `input_sources` fields remain editable through the
   upstream builder. Output names are `OutputName`, not `String`: use
   `output_name.as_str()` for lookups in string-keyed maps and for the
   `hash_upstream_placeholder` argument.
3. Replace IA-to-floating output field assignments with:

   ```rust
   for output in drv.outputs.values_mut() {
       output.path = None;
       output.hash_algo = "r:sha256".into();
       output.hash.clear();
   }
   ```

   `CAFloatingAlgo`, `ca_hash`, and `ca_floating` are no longer needed. Output
   tuples are `UnvalidatedOutput { path, hash_algo, hash }`. The raw preimage
   type's `builder.outputs` is unused; edit its own `outputs` map instead.
4. Keep `calculate_derivation_path_from_aterm`, `hash_placeholder`, key parsing,
   key accessors, and content-hashing function names/signatures. Pass 1 now
   returns the nongeneric `StorePath`. `Pass2Result` is unchanged.
5. Update laut's snix Git revision/lockfile and Nix source hash together, keeping
   `PROTO_ROOT` pointed at the **repository root**, not its `snix/` subdirectory.
   The workspace requires Rust >= 1.95. When reproducing upstream's dependency
   graph in another Cargo workspace, carry over upstream's root
   `[patch.crates-io]` overrides for hyper and the tonic family. Dependency
   workspace patches are not inherited by Git consumers.

For ordinary validated IA/FOD derivations, prefer upstream
`UnverifiedDerivation::from_aterm_bytes` and `into_parts()` to obtain a
`DerivationBuilder` and checked `Outputs`. Do not use that route for trace
preimages: `into_parts()` removes output environment bindings and
`build_unverified()` fills them with concrete paths. That would change the
bytes laut intends to hash. Floating-CA execution by upstream's checked build
pipeline is not added by this fork.

## Compatibility Constraints

- This is a source migration, not a drop-in update of the old fork.
- NAR serialization, SHA256 formatting, and the empty-name BASE64URL_NOPAD
  protobuf Entry envelope are retained. Blob chunking is not part of these
  content fingerprints.
- **Directory castore fingerprints can change.** Upstream corrected directory
  sizes from twice the child count to the child count (plus child-directory
  sizes). A two-file directory now has size 2, not 4. Nested directory digests
  can change as well. The upstream `compat-accept-bigger-sizes` feature accepts
  old data on input; it does not reproduce old output fingerprints. Coordinate
  signer/verifier upgrades and re-sign directory traces or version/separate
  their cache namespace. Do not assume old signatures compare equal.
- Raw ATerm hashing now parses the full ATerm and rejects malformed/trailing
  input. It correctly includes input sources even when nested input-output
  lists exist, unlike the old ad-hoc bracket counter. It hashes the supplied
  bytes, not their reserialization, and supports non-UTF8 environment bytes.
- Store-hash inputs must be exactly 32 nixbase32 characters. Invalid alphabet,
  invalid reference paths/names, and unsupported NAR hash algorithms return
  errors rather than proceeding or panicking. SHA256 is the only supported
  NAR algorithm. Rewrite needles must be at least two bytes and replacements
  must have equal length (internal `RewritePattern` invariants).
- Hashing helpers remain synchronous and create their own Tokio runtime.
  Call them outside an async runtime or from a blocking worker. Blob contents
  are held in memory; pass 1 additionally buffers the rewritten NAR for
  self-reference masking. Cyclic closure policy remains the caller's concern.

## Verification

Run from the `snix/` Cargo workspace, with protobuf and a suitable Rust toolchain:

```sh
export PROTO_ROOT=/path/to/snix-repository-root
cargo check -p laut-compat -p nix-compat --all-targets --locked
cargo test -p laut-compat -p nix-compat --locked -- --quiet
cargo test -p nix-compat --no-default-features --locked -- --quiet
cargo test -p nix-compat --all-features --locked -- --quiet
cargo test -p snix-castore --locked --lib refscan:: -- --quiet
cargo test -p snix-castore --locked --lib import::fs::tests -- --quiet
```

`Cargo.lock` preserves all upstream package versions and Git revisions; only
the new `laut-compat` package entry is added. `Cargo.nix` is regenerated using
upstream's crate2nix 0.15.0 and nixfmt, without running `cargo update`.

Results on 2026-10-17, using `nix develop /home/mschwaig/git/laut -c ...`,
Rust 1.98.1, and `PROTO_ROOT=/tmp/opencode/snix-update-independent`:

| Check | Result |
| --- | --- |
| Cargo check, laut-compat + nix-compat, all targets, locked | Passed |
| laut-compat unit tests / doctests | 13 / 2 passed |
| nix-compat alongside laut-compat | 1765 passed, 3 ignored; 30 doctests passed |
| nix-compat, no default features | 353 passed; 29 doctests passed |
| nix-compat, all features | 1793 passed, 3 ignored; 33 doctests passed |
| castore reference scanner/rewriter tests | 22 passed |
| castore rewriting filesystem ingestion tests | 2 passed |
| Clippy, all targets of all three crates, `--no-deps -- -D warnings` | Passed |
| Nix instantiate, `snix.laut-compat` | Passed |

The no-default-features run emits six pre-existing unused-import warnings in
upstream tests. No tests failed. The full upstream workspace, Nix build, and
laut's application/VM tests were not run; laut was not modified.
