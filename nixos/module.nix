self: { config, lib, pkgs, ... }:
let
  cfg = config.services.preflight;
  format = pkgs.formats.toml {};
  configFile = format.generate "preflight.toml" (cfg.settings // {
    bind = "${cfg.listenAddress}:${toString cfg.port}";
    upstream = cfg.upstream;
    mode = cfg.mode;
    cache_dir = "/var/cache/preflight";
    control_socket = "/run/preflight/control.sock";
    sandbox = true;
  });
in {
  options.services.preflight = {
    enable = lib.mkEnableOption "preflight outbound request inspection";
    package = lib.mkOption { type = lib.types.package; default = self.packages.${pkgs.stdenv.hostPlatform.system}.preflight; };
    listenAddress = lib.mkOption { type = lib.types.str; default = "127.0.0.1"; };
    port = lib.mkOption { type = lib.types.port; default = 8081; };
    upstream = lib.mkOption { type = lib.types.str; default = "http://127.0.0.1:8080"; };
    mode = lib.mkOption { type = lib.types.enum [ "redact" "no-go" "advisory" ]; default = "redact"; };
    settings = lib.mkOption { type = format.type; default = {}; description = "Nonsecret additional TOML settings."; };
    environmentFile = lib.mkOption { type = lib.types.nullOr lib.types.str; default = null; description = "Runtime path containing PREFLIGHT_CLIENT_KEY and PREFLIGHT_UPSTREAM_KEY."; };
    openFirewall = lib.mkOption { type = lib.types.bool; default = false; };
  };
  config = lib.mkIf cfg.enable {
    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
    systemd.services.preflight = {
      description = "Preflight secret inspection proxy";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/preflight serve --config ${configFile}";
        ExecReload = "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
        DynamicUser = true;
        CacheDirectory = "preflight";
        CacheDirectoryMode = "0700";
        RuntimeDirectory = "preflight";
        RuntimeDirectoryMode = "0700";
        UMask = "0077";
        Restart = "on-failure";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        MemoryMax = "3G";
        TasksMax = 128;
      };
    };
  };
}
