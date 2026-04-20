{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = { url = "github:oxalica/rust-overlay"; };
    libspdm-src = {
      url = "git+file:third-party/libspdm";
      flake = false;
    };
  };

  outputs = inputs:
    with inputs;
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import inputs.rust-overlay) ];
        pkgs = import inputs.nixpkgs { inherit overlays system; };

        libspdm-src = inputs.libspdm-src;

        libspdm = pkgs.stdenv.mkDerivation {
          pname = "libspdm";
          version = "3.0.0";

          src = libspdm-src;

          nativeBuildInputs = [ pkgs.cmake ];
          buildInputs = [ pkgs.openssl ];

          hardeningDisable = [ "all" ];
          NIX_CFLAGS_COMPILE = "-fno-lto";

          CFLAGS =
            "-DLIBSPDM_ENABLE_CAPABILITY_EVENT_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_MEL_CAP=0 -DLIBSPDM_HAL_PASS_SPDM_CONTEXT=1 -DLIBSPDM_ENABLE_CAPABILITY_GET_KEY_PAIR_INFO_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_SET_KEY_PAIR_INFO_CAP=0 -DLIBSPDM_ENABLE_CAPABILITY_ENDPOINT_INFO_CAP=0";

          cmakeFlags = [
            "-DARCH=x64"
            "-DTOOLCHAIN=GCC"
            "-DTARGET=Release"
            "-DCRYPTO=openssl"
            "-DENABLE_BINARY_BUILD=1"
            "-DCOMPILED_LIBCRYPTO_PATH=${pkgs.openssl.out}/lib"
            "-DCOMPILED_LIBSSL_PATH=${pkgs.openssl.out}/lib"
            "-DDISABLE_TESTS=1"
          ];

          installPhase = ''
            mkdir -p $out/lib $out/include
            cp -r lib/*.a $out/lib/
            cp -r ../include/* $out/include/
          '';
        };

        spdm-utils = pkgs.rustPlatform.buildRustPackage {
          pname = "spdm-utils";
          version = "1.0.0";

          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let
                baseName = baseNameOf path;
                relPath = pkgs.lib.removePrefix (toString ./. + "/") path;
                # Include Rust source files
              in (pkgs.lib.hasSuffix ".rs" baseName)
              || (pkgs.lib.hasSuffix ".toml" baseName)
              || (baseName == "Cargo.lock") || (baseName == "build.rs")
              || (baseName == "wrapper.h") ||
              # Include certs directory
              (pkgs.lib.hasPrefix "certs" relPath) ||
              # Include manifest directory
              (pkgs.lib.hasPrefix "manifest" relPath) ||
              # Exclude third-party (we get libspdm from input)
              !(pkgs.lib.hasPrefix "third-party" relPath) &&
              # Allow directories to be traversed
              (type == "directory");
          };

          cargoLock = { lockFile = ./Cargo.lock; };

          nativeBuildInputs = [ pkgs.pkg-config pkgs.libclang pkgs.openssl ];

          buildInputs = [ pkgs.udev pkgs.pciutils pkgs.openssl libspdm ];

          hardeningDisable = [ "all" ];

          preBuild = ''
            # Create the expected libspdm directory structure
            mkdir -p third-party/libspdm/build/lib
            mkdir -p third-party/libspdm/include
            ln -sf ${libspdm}/lib/*.a third-party/libspdm/build/lib/
            cp -r ${libspdm-src}/include/* third-party/libspdm/include/
            cp -r ${libspdm-src}/os_stub third-party/libspdm/

            # Generate certificates if they don't exist
            if [ ! -f certs/alias/slot0/bundle_responder.certchain.der ]; then
              pushd certs
              bash ./setup_certs.sh || true
              popd
            fi
          '';

          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS =
            "-I${pkgs.pciutils}/include -I${pkgs.glibc.dev}/include -I${libspdm-src}/include";
          NIX_CFLAGS_COMPILE = "-fno-lto";
          NIX_CFLAGS_LINK = "-fno-lto";
        };

      in {
        packages.default = spdm-utils;
        packages.libspdm = libspdm;

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.rust-bin.stable.latest.complete
            pkgs.pkg-config
            pkgs.udev
            pkgs.libclang
            pkgs.pciutils
            pkgs.bash
            pkgs.coreutils
            pkgs.openssl
            pkgs.cmake
            pkgs.gnumake
            pkgs.gcc
          ];
          LIBCLANG_PATH = "${pkgs.libclang.lib}/lib";
          BINDGEN_EXTRA_CLANG_ARGS =
            "-I${pkgs.pciutils}/include -I${pkgs.glibc.dev}/include";
          hardeningDisable = [ "all" ];
          NIX_CFLAGS_COMPILE = "-fno-lto";
          NIX_CFLAGS_LINK = "-fno-lto";
        };
      });
}
