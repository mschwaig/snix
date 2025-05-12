{ depot ? null, lib ? (import ../nix/readTree/default.nix) { depot = depot; }
, buildRustCrate, clap, fixtures ? (import ../laut-compat/default.nix).fixtures }:

buildRustCrate {
  pname = "laut-compat";
  version = "0.1.0";
  src = lib.cleanSource ./.;
  dependencies = [
    "anyhow"
    "thiserror"
    "tokio"
    "tracing"
    "clap"
    "nix-compat"
    "snix-castore"
    "snix-store"
  ];
}