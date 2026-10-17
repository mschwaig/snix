//! Compatibility layer between nix-compat and snix-store for laut
//!
//! This crate provides utilities for working with the Nix store, including
//! functions to calculate NAR hashes and CA store hashes for store paths.

/// Module for NAR hash calculation
pub mod content_hash;
