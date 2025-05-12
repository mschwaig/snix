//! Compatibility layer between nix-compat and snix-store for laut
//!
//! This crate provides utilities for working with the Nix store, including
//! functions to calculate NAR hashes and CA store hashes for store paths.

/// Module for NAR hash calculation
pub mod nar;

// Re-export key types from the nar module
pub use nar::{NarHashError, calculate_nar_hash, format_nar_hash, calculate_castore_hash};