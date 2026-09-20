{ pkgs, ... }:
let tools = [ pkgs.poppler-utils pkgs.tesseract pkgs.qpdf pkgs.exiftool pkgs.zbar pkgs.bubblewrap ];
in {
  languages.rust.enable = true;
  packages = [ pkgs.git pkgs.pkg-config pkgs.nodejs pkgs.bubblewrap pkgs.gitleaks ] ++ tools;
  env.PREFLIGHT_WORKER_PATH = pkgs.lib.makeBinPath tools;
  env.PREFLIGHT_TEST_FONT = "${pkgs.dejavu_fonts}/share/fonts/truetype/DejaVuSansMono.ttf";
  # Development builds disable persistent approvals because the worker is mutable.
  enterTest = ''
    cargo fmt --check
    cargo clippy --locked --all-targets --all-features -- -D warnings
    cargo test --locked --all-features
    npx --yes @spolu/cc-check format
  '';
}
