{
  description = "FIPS — a distributed, decentralized network routing protocol for mesh nodes connecting over arbitrary transports";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      fenix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Honor the toolchain the repo pins in rust-toolchain.toml
        # (channel 1.94.1 + rustfmt, clippy) so Nix builds match CI and the
        # AUR/Debian packaging exactly, including the edition-2024 frontend.
        rustToolchain = fenix.packages.${system}.fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = "sha256-zC8E38iDVJ1oPIzCqTk/Ujo9+9kx9dXq7wAwPMpkpg0=";
        };

        rustPlatform = pkgs.makeRustPlatform {
          cargo = rustToolchain;
          rustc = rustToolchain;
        };

        cargoToml = pkgs.lib.importTOML ./Cargo.toml;

        # libdbus-sys (pulled in transitively by `bluer`, Linux/glibc only)
        # runs `bindgen` against the system D-Bus headers at build time.
        nativeBuildInputs = [
          pkgs.pkg-config
          rustPlatform.bindgenHook # sets LIBCLANG_PATH + clang for bindgen
        ];

        buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [
          pkgs.dbus # libdbus-1.so.3, linked via bluer→libdbus-sys
          pkgs.stdenv.cc.cc.lib # libgcc_s.so.1, needed by every Rust binary
        ];

        fips = rustPlatform.buildRustPackage {
          pname = "fips";
          version = cargoToml.package.version;

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            # Drop the build dir and the usual editor/VCS noise so the source
            # hash is stable and unrelated edits don't trigger rebuilds.
            filter =
              path: type:
              (pkgs.lib.cleanSourceFilter path type) && (baseNameOf path != "target");
          };

          cargoLock.lockFile = ./Cargo.lock;

          inherit buildInputs;

          # autoPatchelfHook rewrites the RPATH of the built binaries so the
          # daemon finds libdbus-1.so.3 (linked via bluer→libdbus-sys) in the
          # Nix store at runtime — without it the `fips` binary fails to load
          # on NixOS where there is no global /usr/lib.
          nativeBuildInputs =
            nativeBuildInputs ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook ];

          # The test suite exercises TUN devices, raw sockets and mDNS, none of
          # which exist in the build sandbox. The AUR/Debian packaging likewise
          # ships the release binaries without running the integration tests
          # here, so keep the package build hermetic and skip them.
          doCheck = false;

          meta = {
            description = cargoToml.package.description;
            homepage = cargoToml.package.homepage;
            license = pkgs.lib.licenses.mit;
            mainProgram = "fips";
            platforms = pkgs.lib.platforms.linux ++ pkgs.lib.platforms.darwin;
          };
        };

        mkApp = name: {
          type = "app";
          program = "${fips}/bin/${name}";
          meta.description = "Run the ${name} binary from the FIPS package";
        };
      in
      {
        packages = {
          default = fips;
          fips = fips;
        };

        apps = {
          default = mkApp "fips";
          fips = mkApp "fips";
          fipsctl = mkApp "fipsctl";
          fips-gateway = mkApp "fips-gateway";
          fipstop = mkApp "fipstop";
        };

        # `nix flake check` builds the package (and thus validates the flake on
        # the current system).
        checks.fips = fips;

        devShells.default = pkgs.mkShell {
          inherit buildInputs;
          nativeBuildInputs = nativeBuildInputs ++ [
            rustToolchain
            pkgs.cargo-edit
          ];
          # Point rust-analyzer at the matching std sources.
          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
        };

        formatter = pkgs.nixfmt;
      }
    );
}
