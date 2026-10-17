{ depot, ... }:

depot.snix.crates.workspaceMembers.laut-compat.build.override {
  runTests = true;
}
