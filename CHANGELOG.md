# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [2.0.0] — 2026-07-19

First stable release of the full rewrite ("ServerTools v2").

### Added — hardening & pro-features round

- User-based capacity model: `--users N` (or the `expected_users` config
  key, asked in Custom Optimize) sizes conntrack from the real user count
  instead of RAM, bounds `tcp_mem` explicitly, and prints an honest
  RAM-feasibility warning with numbers (docs/PROFILES.md).
- Persian documentation: full step-by-step usage guide `docs/GUIDE.md`
  (RTL layout with LTR command blocks); README reworked to proper RTL.

- `--dry-run`: renders the exact sysctl file for the resolved profile/tier
  and diffs every key against the live kernel — applies nothing.
- `--report` / Tools menu: plain-text support report (system, workload,
  live tuning keys, swap, manifest tail, log tail), printed and saved.
- Reserved service ports: listening ports inside the ephemeral range are
  auto-added to `net.ipv4.ip_local_reserved_ports` so outgoing connections
  can never collide with panel/node listeners.
- zram swap backend (`swap_backend = auto|file|zram`): swap file remains the
  default; auto falls back to compressed-RAM zram when the disk is too
  small. Boot persistence via oneshot unit; rollback swapoffs and resets.
- Service-restart offer after limits changes (running services keep the old
  nofile until restarted); batch mode prints the affected containers.
- XanMod kernel installer (BBRv3) as an ADVANCED consent-based tool:
  apt-only, CPU psABI level detection, double warning, container-virt guard.
- DNS: Electro and Begzar presets (public-IP Iranian resolvers); latency
  test now measures real DNS queries via dig (ping fallback);
  `DNSOverTLS=opportunistic` on systemd-resolved; resolv.conf gains
  `options timeout:2 attempts:2 rotate`; stub-bypass detection warns when
  apps would not see the new DNS.
- sysctl base: `tcp_rfc1337=1`, `optmem_max`, L/XL high-churn caps
  (`tcp_max_tw_buckets`, `tcp_max_orphans`) — doc and code now in sync;
  live qdisc switch via `tc qdisc replace` (no reboot needed).
- Detection: Hiddify, sing-box, Hysteria, OpenVPN, and podman containers.

### Fixed

- Rollback now disables systemd units it created (manifest `unit` action) —
  no more dangling `.wants` symlinks after removing MSS/zram units.
- `ss | head` under pipefail produced spurious warnings on long listings.
- Self-update downloaded the release twice; now a single verified download.
- Public-IP lookup trimmed (2 endpoints, 2s timeout) so the first dashboard
  render never feels stuck on broken-connectivity servers.

### Added — Phase 4 (automation & distribution)

- `--auto` non-interactive mode for fleet provisioning: applies the base
  layer plus the detected (or `--profile`-forced) workload profile without
  any prompt. Companions: `--tier S|M|L|XL`, `--dns <provider|ip1,ip2>`
  (DNS untouched when omitted), `--no-swap`, `--no-limits`, `--no-extras`.
  Example: `st --auto --profile vpn-node --tier L --dns cloudflare`.
- `--install`: installs the running script as `/usr/local/bin/st` (tracked
  in the manifest); works from a file or from a `bash <(curl ...)` pipe.
- `--update`: self-update preferring the latest GitHub Release with SHA-256
  verification, falling back to the raw main build until the first release
  exists; every download must pass `bash -n` and a fingerprint check before
  anything is replaced. Both also available in the Settings menu.

### Added — Phase 3 (security, VPN-aware tuning, network tools)

- `security` module (all consent-based): UFW setup with SSH-port auto-detect
  and lockout protection (allow rule lands before any deny), extra-port
  validation, and a Docker-bypass warning; fail2ban sshd jail (systemd
  backend, resident cost stated up front); SSH hardening via a
  `sshd_config.d` drop-in validated with `sshd -t` before restart —
  key-only login is offered only when an authorized_keys file exists.
- `vpn` module: MSS clamping (IPv4+IPv6) with boot persistence through a
  systemd **oneshot** unit (runs once, exits — zero-footprint compliant);
  Docker+UFW bypass audit listing the currently published ports.
- `tools` module: ping matrix against Iran + global targets (latency/loss),
  DNS provider latency test, live TCP/conntrack status (BBR, forwarding,
  table usage %), listening-ports snapshot.
- `pkg_install` helper (apt/dnf/yum/pacman, single index refresh, log-routed
  output) — packages are only ever installed after explicit consent.
- Main menu gained Security and Network & VPN tools sections.
- `ROADMAP.md`: phases, backlog, and v2.0.0 release criteria moved out of
  CLAUDE.md.

### Added — Phase 2 (optimization modules)

- Layered profiles (`general`, `vpn-node`, `wireguard`, `panel`, `full`) with
  auto-detection and manual override; capacity tiers S/M/L/XL sized by RAM,
  with the estimated kernel RAM cost of the conntrack table shown up front.
- `sysctl` module implementing `docs/SYSCTL.md`: BBR/fq detection with
  persistence, tier-scaled backlogs/buffers, UDP memory for QUIC/Hysteria2,
  and for VPN profiles: IPv4+IPv6 forwarding, conntrack sizing with hash
  buckets (modprobe.d persisted), 1-hour established timeout, rp_filter=2 and
  ICMP-redirect hardening. Applied keys are verified and reported honestly.
- `dns` module: provider presets (Cloudflare/Google/Quad9/OpenDNS/Shecan),
  custom IPv4/IPv6 entries, per-provider latency test, systemd-resolved
  drop-in or tracked resolv.conf. "Keep current" now really keeps it
  (legacy bug: it silently applied the default provider).
- `swap` module: fstab entry written only after `swapon` verifiably succeeds;
  explicit btrfs CoW handling; disk headroom check.
- `limits` module: nofile 1048576 via PAM + a systemd drop-in (no more
  sed-editing `system.conf`).
- `extras` module: journald disk cap (100M) and NTP enablement.
- Quick Optimize (plan → confirm → per-step OK/SKIP/WARN/FAIL → summary) and
  Custom Optimize (profile, tier override, per-module toggles).
- Rollback now swapoffs an active swap file before removal and reloads
  sysctl when tuning files were restored.

### Added — Phase 1 (skeleton and core runtime)

- Modular `src/` tree compiled into a single `dist/server-tools.sh` by `build.sh`.
- Core runtime: strict mode with a global `ERR` trap, leveled logging with
  rotation, terminal capability detection (color / UTF-8 / NO_COLOR),
  reusable UI kit (boxes, key/value rows, menus, confirm/pause).
- Persistent state: config file at `/etc/server-tools/config`, change manifest
  at `/var/lib/server-tools/manifest.tsv`.
- Backup engine: pristine `original/` copy on first touch (never overwritten),
  per-run backups, manifest-driven rollback (`--rollback` and menu).
- Workload detection: Marzban panel/node, Pasarguard node (pg-node), x-ui,
  WireGuard, wg-dashboard.
- System status report (`--status` and menu) with cached public IP lookups.
- CLI entrypoint: `--status`, `--rollback`, `--version`, `--help`,
  `--no-color`, `--debug`.
- CI: ShellCheck + shfmt lint, build, smoke tests across Ubuntu 20.04/22.04/24.04
  and Debian 11/12 containers. Release workflow publishing the built script with
  SHA-256 checksums on tags.
- Documentation: `docs/ARCHITECTURE.md`, `docs/PROFILES.md`, `docs/SYSCTL.md`
  (tuning spec), `docs/ROLLBACK.md`, `docs/FAQ.md`, `CLAUDE.md`.

### Changed

- Legacy scripts (`opt.sh` V15.2.0, `opt-gcore.sh` V11) moved to `legacy/` and
  frozen. Their old raw-URL install paths changed accordingly.

### Planned

Future ideas and release criteria live in `ROADMAP.md`.
