# NixOS module for the FIPS mesh network daemon.
#
# Exposed as nixosModules.default in flake.nix.
# Consumers enable it with:
#
#   { inputs, ... }: {
#     imports = [ inputs.fips.nixosModules.default ];
#     services.fips.enable = true;
#   }
#
# The package is provided via the flake's overlay (overlays.default), so it
# lands in pkgs.fips without the consumer needing to know the input name.
#
# --- Hybrid config pattern ---
#
# fips.yaml and identity keys live in /var/lib/fips/ (writable, survives
# reboots and rebuilds). The shipped default is seeded there on first run
# only; operator edits are never clobbered.
#
# The hosts file and ACL files (peers.allow, peers.deny) MUST stay at
# /etc/fips/ because fips hardcodes those paths on Linux
# (DEFAULT_HOSTS_PATH, DEFAULT_PEERS_ALLOW_PATH, DEFAULT_PEERS_DENY_PATH).
# They are seeded as real writable files (not Nix store symlinks) so the
# operator can edit them directly.
#
# fips is launched with --config /var/lib/fips/fips.yaml, which bypasses
# the config search path entirely — fips will never accidentally load
# /etc/fips/fips.yaml instead of the user-managed version.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.fips;
  stateDir = "/var/lib/fips";
in
{
  options.services.fips = {
    enable = lib.mkEnableOption "FIPS mesh network daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.fips;
      defaultText = lib.literalExpression "pkgs.fips";
      description = ''
        The fips package to use. Defaults to the one provided by the
        fips flake overlay (overlays.default).
      '';
    };

    configFile = lib.mkOption {
      type = lib.types.path;
      default = "${cfg.package}/share/fips/fips.yaml";
      defaultText = lib.literalExpression "''${cfg.package}/share/fips/fips.yaml";
      description = ''
        Default fips.yaml used to seed the writable config at
        /var/lib/fips/fips.yaml on first run. The operator can then edit
        /var/lib/fips/fips.yaml directly; this file is never overwritten
        after the initial seed.
      '';
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Open firewall ports for fips transports
        (UDP 2121, TCP 8443).
      '';
    };

    dns = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Route .fips queries to the fips DNS responder on [::1]:5354
          via systemd-resolved. Without this, .fips hostnames don't
          resolve on the host.
        '';
      };
    };

    gateway = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Enable the outbound LAN gateway. Lets non-fips hosts on the
          LAN reach mesh destinations via DNS-allocated virtual IPs
          and kernel NAT. Requires the fips daemon running with DNS.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    # 'fips' group so non-root users can run fipsctl/fipstop without sudo
    # and edit config/hosts files group-writable.
    users.groups.fips = { };

    # Writable directories for hosts file, ACL files, and nftables drop-ins.
    # fips hardcodes /etc/fips/hosts, /etc/fips/peers.allow,
    # /etc/fips/peers.deny on Linux, so these MUST live here. Created as
    # real directories (not environment.etc symlinks) so the operator can
    # edit files in place.
    systemd.tmpfiles.rules = [
      "d /etc/fips 0775 root fips -"
      "d /etc/fips/fips.d 0775 root fips -"
    ];

    systemd.services.fips = {
      description = "FIPS Mesh Network Daemon";
      wantedBy = [ "multi-user.target" ];
      after = [
        "network-online.target"
        "systemd-tmpfiles-setup.service"
      ];
      wants = [ "network-online.target" ];

      # Seed config and hosts on first run only. Existing files are never
      # overwritten, so operator edits survive service restarts and system
      # rebuilds.
      preStart = ''
        # Seed writable config from the shipped default (only if absent).
        # fips derives key paths (fips.key/fips.pub) from the config file's
        # parent directory, so keys also land in /var/lib/fips/.
        if [ ! -f ${stateDir}/fips.yaml ]; then
          cp "${cfg.configFile}" ${stateDir}/fips.yaml
          chown root:fips ${stateDir}/fips.yaml
          chmod 0664 ${stateDir}/fips.yaml
        fi

        # Seed hosts file (fips hardcodes /etc/fips/hosts on Linux).
        if [ ! -f /etc/fips/hosts ]; then
          cp "${cfg.package}/share/fips/hosts" /etc/fips/hosts
          chown root:fips /etc/fips/hosts
          chmod 0664 /etc/fips/hosts
        fi
      '';

      serviceConfig = {
        Type = "simple";
        # Run as root:fips so the daemon has root for TUN/raw sockets while
        # group members can access the control socket and state files.
        Group = "fips";
        # --config bypasses the search path: fips loads ONLY this file,
        # never /etc/fips/fips.yaml.
        ExecStart = "${cfg.package}/bin/fips --config ${stateDir}/fips.yaml";
        Restart = "on-failure";
        RestartSec = 5;

        # Writable state directory (/var/lib/fips/) for config + keys.
        # root:fips 0775 so group members can edit the config.
        StateDirectory = "fips";
        StateDirectoryMode = "0775";

        # Control socket directory (/run/fips/) — group-accessible.
        RuntimeDirectory = "fips";
        RuntimeDirectoryMode = "0770";

        # Log directory (/var/log/fips/) for the built-in profiler.
        LogsDirectory = "fips";

        # Security hardening (daemon runs as root for TUN and raw sockets).
        # Mirrors packaging/systemd/fips.service.
        ProtectHome = "yes";
        PrivateTmp = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = false;
      };
    };

    services.resolved = lib.mkIf cfg.dns.enable {
      enable = true;
      settings.Resolve = {
        DNS = [ "[::1]:5354" ];
        Domains = [ "~fips" ];
      };
    };

    systemd.services.fips-gateway = lib.mkIf cfg.gateway.enable {
      description = "FIPS Outbound LAN Gateway";
      wantedBy = [ "multi-user.target" ];
      after = [ "fips.service" ];
      requires = [ "fips.service" ];

      preStart = ''
        for i in $(seq 1 30); do
          ${pkgs.iproute2}/bin/ip link show fips0 >/dev/null 2>&1 && exit 0
          sleep 1
        done
        echo "fips0 did not appear within 30s" >&2
        exit 1
      '';

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/fips-gateway --config ${stateDir}/fips.yaml";
        Restart = "on-failure";
        RestartSec = 5;
        TimeoutStopSec = 15;
        ProtectHome = "yes";
        PrivateTmp = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = false;
      };
    };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ 8443 ];
      allowedUDPPorts = [ 2121 ];
    };
  };
}
