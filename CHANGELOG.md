# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [2.1.0] — 2026-07-23

### Fixed — critical

- **IPv6 died after a reboot on RA/SLAAC providers.** Enabling
  `ipv6.conf.all.forwarding` makes the kernel ignore router advertisements,
  which removes the IPv6 default route on the next boot. `accept_ra = 2` is
  now written for `all`, `default` and — because the setting is per-device —
  the live default interface by name.
- **SSH hardening could silently not apply.** sshd honours the FIRST value
  it reads and processes `sshd_config.d` in lexical order, so the old
  `99-server-tools.conf` lost against `50-cloud-init.conf`. The drop-in is
  now `00-server-tools.conf`, the superseded file is removed, and every
  setting is verified against `sshd -T` instead of being assumed.

### Fixed — high

- `--auto` always exited 0. There is now a documented exit-code contract
  (0 success, 1 failure, 2 usage error, 3 warnings/drift) that propagates
  from every step, which makes the tool usable in Ansible and CI.
- UDP conntrack timeouts are tuned for QUIC/Hysteria2 nodes
  (`udp_timeout`, `udp_timeout_stream`, plus TCP time-wait/close-wait and
  generic timeouts); WireGuard keeps longer-lived mappings on purpose.
- Reserved service ports are no longer capped at 32 individual entries:
  consecutive ports collapse into ranges, the cap is 64 entries, extra
  ports can be pinned with the `reserved_ports` config key, and `--verify`
  reports listeners that appeared later.
- `vm.swappiness` follows the swap backend: 100 on zram (compressed RAM
  should be used), 10 on a disk swap file. The swap step therefore runs
  before the sysctl step.
- `--profile/--tier/--users/--dns` without `--auto`/`--dry-run` used to be
  ignored silently; they now exit 2 with an explanation.
- `tcp_fastopen` drops to client-only (1) on VPN profiles: server-side TFO
  adds a fingerprint and some middleboxes drop SYNs carrying data.

### Fixed — medium

- `FallbackDNS` is reset to empty instead of carrying a dead value — this
  also removes the distribution's Google/Cloudflare fallbacks, which could
  silently answer queries the chosen resolver refused.
- Per-link DNS overrides now cover every up link, not just the default
  route; the boot unit resolves interfaces at runtime and pulls in
  `network-online.target` with `Wants=`.
- MSS clamping survives `ufw reload` (persisted in `before.rules`, reverted
  automatically if UFW rejects the change).
- Old run backups are pruned (newest 10 kept); `original/` is never touched.
- `--install`/`--update` no longer record `/usr/local/bin/st` in the
  manifest, so a later rollback cannot delete the command itself.
- A missing `SHA256SUMS` during self-update is reported instead of silently
  skipping verification.
- `--dry-run` no longer runs `modprobe`; qdisc support is inspected with
  `modinfo` in that mode.
- IPv6 addresses are validated properly (groups, single `::`) instead of
  accepting anything containing a colon.
- Docker containers inherit limits from the engine: the tool now offers to
  write `default-ulimits` when `/etc/docker/daemon.json` does not exist and
  prints the exact snippet when it does.

### Added

- **`--verify` / Doctor menu** — drift detection across every module
  (`<module>_verify()` is now a formal contract), unreserved-port check,
  and measured effect since the baseline. `--json` makes it fleet-friendly.
- **Before/after snapshot** — TCP retransmits, interface drops and conntrack
  are captured before the first change so the effect can be measured later.
- **`--rollback-original`** — restore the state from before ServerTools ever
  ran, in one step (menu: Rollback → Restore original state).
- **Anti-abuse egress profile** — blocks outbound SMTP/worm ports and
  RFC1918/CGNAT ranges while keeping the provider's own subnet reachable,
  and switches SSH to a rate-limited rule.
- **Node API restriction** — 62050/62051 limited to the panel IP.
- **Node & Docker menu** — configuration backup (certificates included),
  official upstream installers shown in full before running, Docker ulimits.
- **Network tools** — bandwidth test (speedtest client or dependency-free
  HTTP download), quick CPU/disk benchmark, live view of
  conntrack/sockets/traffic, and APT mirror switching for Iran-hosted
  servers with automatic rollback when `apt-get update` fails.
- **Real qdisc probing** — support is tested by attaching the qdisc to
  loopback instead of being assumed; `cake` and any other qdisc can be
  selected with the `qdisc` config key.

## [2.0.1] — 2026-07-23

### Fixed

- **DNS was reported as applied while the old servers stayed in effect.**
  Two root causes, both fixed: systemd *appends* to list settings in
  drop-ins, so the previously configured servers stayed ahead of ours (the
  drop-in now resets `DNS=`/`FallbackDNS=` before assigning them), and
  per-link DNS from netplan/DHCP takes precedence over the global
  configuration, so it is now overridden at runtime and persisted — by
  clearing the link's DNS in a systemd-networkd drop-in where the link is
  networkd-managed, otherwise through a oneshot unit.
- DNS application is verified against the servers that will really answer
  queries (link scope, then global, then resolv.conf) instead of only
  checking that the resolved stub is in place; a mismatch now reports WARN.
- `/etc/resolv.conf` that bypasses systemd-resolved is detected and gets the
  servers written into it directly as well.
- Tracking the same file twice in one run overwrote its run backup with the
  already-modified content, which would have made rollback restore our own
  file instead of the original.
- The post-limits restart offer missed containers whose name does not carry
  the product (a pg-node container is often just `node`); it now matches on
  name and image, covers podman, and warns that a restart disconnects users.
- The same restart offer asked nothing at all even when it found containers:
  the loop fed the container list on stdin, so the `read` inside the
  confirmation consumed it instead of the user's answer — and bash suppresses
  a prompt entirely when stdin is not a terminal. The list is now read
  through a dedicated file descriptor.

### Added

- System Status is now a full report: hostname/arch/timezone and NTP sync,
  swap backend (zram vs file), interface MTU and active qdisc, TCP socket
  counts, a dedicated DNS section (resolver stack, servers in effect, DoT
  state, resolv.conf mode), accept-queue and buffer values, conntrack usage
  with percentage, nofile limits (shell, systemd, docker advisory),
  firewall/fail2ban/SSH state, and the applied profile/tier/user count.
- `Electro` and `Begzar` are now selectable with `--dns` too.
- Support reports (`--report`) include the DNS section and nofile limits.
- The DNS menu shows the servers currently in effect, and after applying,
  the optimizer prints the servers that actually answer queries.

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
