pub mod build_state;
pub mod builder;
pub mod fetchers;
pub mod fetchurl_derivation;
pub mod known_paths;

// Used as user agent in various HTTP Clients
const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));
