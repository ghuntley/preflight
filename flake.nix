{
  description = "Preflight structured secret-inspection proxy";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devenv.url = "github:cachix/devenv";
    devenv.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, devenv, ... }@inputs:
  let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    each = nixpkgs.lib.genAttrs systems;
  in {
    packages = each (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        tools = [ pkgs.poppler-utils pkgs.tesseract pkgs.qpdf pkgs.exiftool pkgs.zbar pkgs.bubblewrap ];
      in rec {
        preflight = pkgs.rustPlatform.buildRustPackage {
          pname = "preflight";
          version = "0.1.0";
          src = nixpkgs.lib.fileset.toSource {
            root = ./.;
            fileset = nixpkgs.lib.fileset.unions [ ./Cargo.toml ./Cargo.lock ./src ./tests ./vendor ./rules ./benches ./LICENSE ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          # Hegel's engine bootstrap needs network; mandatory in devenv CI.
          doCheck = false;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postInstall = ''
            install -Dm644 LICENSE $out/share/licenses/preflight/LICENSE
            install -Dm644 vendor/gitleaks/LICENSE $out/share/licenses/preflight/gitleaks-LICENSE
            install -Dm644 vendor/gitleaks/upstream.json $out/share/preflight/upstream.json
            wrapProgram $out/bin/preflight-worker \
              --set PATH ${nixpkgs.lib.makeBinPath tools}
            wrapProgram $out/bin/preflight \
              --set PREFLIGHT_WORKER $out/bin/preflight-worker \
              --set PREFLIGHT_WORKER_PATH ${nixpkgs.lib.makeBinPath tools} \
              --set PREFLIGHT_TOOLCHAIN_ID "$out:${nixpkgs.lib.makeBinPath tools}" \
              --prefix PATH : ${nixpkgs.lib.makeBinPath [ pkgs.bubblewrap ]}
          '';
          meta = { mainProgram = "preflight"; license = nixpkgs.lib.licenses.mit; platforms = systems; };
        };
        default = preflight;
      });
    apps = each (system: { default = { type = "app"; program = "${self.packages.${system}.preflight}/bin/preflight"; }; });
    devShells = each (system: { default = devenv.lib.mkShell { inherit inputs; pkgs = nixpkgs.legacyPackages.${system}; modules = [ ./devenv.nix ]; }; });
    overlays.default = final: _: { preflight = self.packages.${final.stdenv.hostPlatform.system}.preflight; };
    nixosModules.default = import ./nixos/module.nix self;
    checks = each (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in {
        preflight-vm = import ./nixos/tests/preflight.nix {
          inherit pkgs;
          module = self.nixosModules.default;
          package = self.packages.${system}.preflight.overrideAttrs (_: { cargoBuildFlags = [ "--features=test-fixtures" ]; });
        };
        preflight-package = self.packages.${system}.preflight;
      });
  };
}
