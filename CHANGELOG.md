# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [2.3.3] — 2026-07-24

### Changed

- **Real bandwidth test with a proper UI.** The old option relied on the
  deprecated speedtest.net Python client (`speedtest-cli`) — and even offered
  to install it — which breaks against Ookla's API and is frequently filtered
  from Iran, so it "worked once, then stopped." The test is now a genuine
  **download + upload + latency** measurement against Cloudflare's speed
  endpoints (`speed.cloudflare.com`): four parallel streams for realistic
  throughput, best-of-three TCP-connect latency, results shown live and
  formatted (Mbit/s and MB/s). Download falls back across mirrors (Cloudflare →
  Hetzner → …) when a network throttles large inbound CDN transfers while
  leaving upload fine. It needs only `curl`, works from Iran, and never
  installs the fragile client. A genuine Ookla binary is still used when it is
  already present.

### Fixed

- **DNS now sticks on netplan/DHCP hosts.** On a systemd-networkd link the
  DHCP-provided servers OUTRANK the global resolved config, and a runtime
  `resolvectl dns` override was clobbered by networkd re-pushing the DHCP DNS
  after the resolved restart — so a chosen provider silently never took effect
  (the WARN some users saw). The link is now fixed first: a networkd drop-in
  pins our servers and sets `UseDNS=false`, applied with a blip-free
  `networkctl reload` *before* resolved restarts, then re-asserted at runtime
  afterwards. Persist → restart → re-assert, in that order.
- **Capacity sysctls no longer regress a modern kernel.** `vm.max_map_count`,
  `fs.file-max`, `fs.nr_open` and `net.core.optmem_max` were fixed values that
  on kernel 6.x are *lower* than the running defaults (e.g. `max_map_count` is
  1048576 since 6.7, `file-max` is effectively unlimited) — so the tool was
  quietly lowering them. They are now **ceilings**: applied only when higher
  than the live value, never below it.
- **`net.ipv4.udp_mem` is no longer set.** The fixed RAM formula produced values
  *below* the kernel's own RAM-scaled default, capping UDP memory on busy
  QUIC/Hysteria nodes. The kernel already sizes this well; we leave it alone.
- **No more false `accept_ra` drift on static-IPv6 links.** Per-interface
  `accept_ra=2` is now pinned only where the link actually accepts RAs; on a
  statically-addressed link networkd holds it at 0 and reverted us on every
  reload, showing as a permanent one-key drift in `--verify` / `--dry-run`.

## [2.3.1] — 2026-07-24

### Changed

- **Calmer, cleaner UI.** The 2.3.0 redesign was too busy — a full-width
  separator bar under every menu group and a horizontal rule between every
  status section made the screens feel boxed-in. Rewrote the layout to lean on
  whitespace instead of lines:
  - Menu groups are now lightweight coloured labels (no separator bars), with
    blank-line spacing; the main menu is four calm groups (Optimize · Inspect ·
    Manage · System).
  - Menu rows are aligned and quieter: `1  Quick Optimize   hint` — no
    brackets, arrows, or em-dashes.
  - The **dashboard** is four compact lines (Host · Machine · Network ·
    Workload) instead of two boxed sections.
  - **System Status** drops the eight inter-section rules; sections are set off
    by a `▍` accent bar and whitespace, so the whole report reads in one calm
    pass.
  - The long **Network & VPN Tools** menu is grouped (Diagnose · Measure ·
    Network · System), and all submenus share one quiet input caret.

## [2.3.0] — 2026-07-24

Inspired by a comparison with `jestivald/node-accelerator`: adopted its best
data-path ideas within our zero-footprint rules, made Quick Optimize more
complete, and reworked the UI.

### Added

- **CPU/NIC performance step (`perf.sh`), on by default in Quick Optimize.**
  Three `/sys`-level wins that sysctl cannot express, all applied live and
  persisted through a single zero-footprint oneshot unit:
  - **RPS/RFS/XPS** — spreads NIC softirq processing across every core.
    Decisive on the single-queue virtio NICs most VPS ship, where one core
    otherwise caps the whole node's packet rate. **Enabled only when the NIC
    has fewer hardware queues than cores** (a multi-queue NIC already spreads
    via RSS); override with the `rps_mode` config key (`auto`/`on`/`off`).
  - **CPU governor = performance** — removes clock ramp-up latency on bursty
    proxy traffic; silently skipped where `cpufreq` is absent (typical VPS).
  - **Transparent Huge Pages = madvise** — stops khugepaged compaction stalls
    from adding tail-latency spikes, without denying THP to code that asks.
  Every write is non-disruptive (takes effect without resetting the link), so
  it is safe on a node already carrying users. `perf_verify` joins Doctor;
  `--no-perf` skips it in `--auto`.
- **New high-value base sysctls** (all Layer 1, universally safe): `fs.nr_open`
  (raising nofile is silently capped without it), `vm.max_map_count = 262144`
  (Xray/sing-box map many buffers per connection), `net.core.netdev_budget`
  with `netdev_budget_usecs` (single-core PPS ceiling), `tcp_min_snd_mss = 512`
  (CVE-2019-11479 floor), and ICMP broadcast/bogus-error hardening.

### Changed

- **UI redesign.** Grouped main menu (Optimize / Inspect / Recover / Secure /
  Tools / Maintain), an at-a-glance optimized/not-optimized status badge on the
  dashboard, sleeker `▸` section headings and `❯ [n] Label — hint` menu rows,
  a beginner hint line, and a new `ui_badge`/`ui_menu_group`/`ui_hint` toolkit.
  All glyphs degrade to ASCII on non-UTF-8/`NO_COLOR`/dumb terminals.
- New `log_note` helper for informational, step-buffered asides.

### Fixed

- **The ERR trap fired on the deliberate final `return`.** `main` returns
  `ST_EXIT_CODE`, which is 1 (a step failed) or 3 (warning/drift) by design —
  but the ERR trap was never cleared, so *every* run that ended in a warning
  printed a spurious `unhandled failure (exit=3) … return "$ST_EXIT_CODE"` to
  stderr and logged it as ERROR. The trap is now cleared right before the
  report-and-return tail. (Present since the exit-code contract was added.)
- **The perf step could abort Quick Optimize on a read-only `/sys`.**
  `_perf_plan` ended on a `for`/guard whose false result leaked into the bare
  `plan="$(_perf_plan …)"` capture — the same class the 2.2.0 notes described.
  On unprivileged-LXC VPS (read-only `/sys`) every writability test is false,
  so the helper returned non-zero and, with perf now default in Quick
  Optimize, took the whole run down. It now returns success explicitly and the
  empty plan simply skips the step.
- **The perf step reported OK when `systemctl daemon-reload` failed.** A failed
  reload now escalates the step to WARN instead of hiding behind a note
  (golden rule 4).
- **NOTRACK could break Docker/DNAT-forwarded ports.** A NOTRACK'd port skips
  the `nat` table, so exempting a Docker-published (`-p`) port silently broke
  its forwarding — fatally with `userland-proxy: false`. DNAT/REDIRECT target
  ports are now read from the live `nat` table, excluded from the suggestion,
  and hard-dropped even if entered manually.
- **Port set math used `comm` on numerically-sorted input.** `comm` needs
  *byte*-sorted input, but ports are sorted numerically, so lists mixing
  different digit-lengths (e.g. `8443` vs `51820`) produced wrong results and
  "not in sorted order" noise. Replaced with collation-safe `_ports_intersect`
  / `_ports_subtract` awk helpers — fixes NOTRACK candidate selection and the
  reserved-ports UDP intersection introduced in 2.1.2.
- **`marznode` was not detected.** Gozargah renamed marzban-node to `marznode`;
  detection and the post-optimize restart prompt now match both.

### Comparison notes (deliberately NOT adopted)

- `ethtool -G` ring/coalesce tuning — can reset the link and harms latency on
  many hypervisors (already excluded in `docs/SYSCTL.md`); kept out so the perf
  step stays safe to run on a live node.
- CrowdSec, fleet auto-sync, blocklist auto-refresh — all require a resident
  agent or timer, which violates the zero-footprint rule. The NOTRACK feature
  (2.2.0) and per-IP anti-abuse already cover the node-side conntrack/abuse
  surface without a daemon.

## [2.2.0] — 2026-07-24

### Added

- **NOTRACK — exempt proxy data ports from connection tracking.** New
  Network-tools action (option `n`) for userspace-proxy nodes (Xray/Reality,
  VLESS/VMess/Trojan, Hysteria). Such a proxy terminates every inbound
  connection in userspace and opens its own outbound sockets, so the conntrack
  entry the kernel creates for each of the millions of short-lived client
  connections is pure overhead. Exempting the proxy ports (raw table, both
  directions, IPv4+IPv6) keeps the conntrack table near-empty — it can no
  longer hit `nf_conntrack_max` under load — and removes the per-packet
  tracking cost on the hottest path on the box. SSH and detected WireGuard
  ports are excluded automatically because they genuinely need conntrack; the
  target form is probed per kernel (`-j CT --notrack`, else legacy
  `-j NOTRACK`). Persistence is a zero-footprint oneshot systemd unit that
  re-adds the rules at boot and removes them on rollback; `notrack_verify`
  joins the Doctor drift checks.

### Fixed

- **`--dry-run` crashed on a host with no default route.** `_sysctl_render`
  ended on `[[ -n $iface ]] && printf …`; with no default interface that
  guard is false, so the function returned non-zero, and the bare
  `rendered="$(_sysctl_render)"` propagated it into the ERR trap under
  `errexit`. Value-producing helpers now return success explicitly.
- **The ERR trap fired on incidental non-zero returns.** Same root cause as
  above generalised: a helper whose stdout is captured must not leak the exit
  status of a trailing conditional. Documented the contract and hardened the
  one helper that violated it.
- **"Effect since baseline" was broken on every host.** The global
  `IFS=$'\n\t'` has no space, so the space-separated `awk` output of the TCP
  counters landed entirely in the first variable, and the delta arithmetic in
  `snapshot_report` then operated on `"a b c"`. The counter read now forces a
  space `IFS`.
- **The default interface could be silently blanked.** `net_default_iface`
  and `net_default_gw` piped `ip route` into an early-exiting `awk`; the
  SIGPIPE'd `ip` made the pipeline return 141 under `pipefail`, and the
  callers' `|| x=''` guards then discarded a correct answer. Both capture the
  route first and parse it from a here-string (same fix as the 2.1.1 batch),
  which also removes the crash path above on hosts that *do* have a route.

## [2.1.2] — 2026-07-23

### Fixed

- **Reserved service ports were mostly wrong.** `sub()` turns an awk field
  into a string, so `$5 >= 10240` compared text — `"22"` ranks above
  `"10240"` — and ports such as 22, 53, 443 and 1080 ended up in
  `ip_local_reserved_ports` while genuine high ports (a node API on 62050)
  were pushed out by the 64-entry cap. The comparison is numeric now.
- **Transient proxy sockets are no longer reserved.** A node's short-lived
  outbound UDP sockets show up in `ss -uln` exactly like real servers, so
  the list churned every second and Doctor reported drift constantly. TCP
  listeners are taken as-is; UDP is sampled twice a second apart and only
  the intersection (WireGuard, Hysteria, …) is kept. Apply and Doctor share
  the same source, so their expectations always match.
- `--dry-run` printed a stray `->` line when nothing had drifted (iterating
  `"${arr[@]-}"` over an empty array yields one empty element); the summary
  counter had the same pattern.

## [2.1.1] — 2026-07-23

### Fixed

- **Values read through a pipe could be silently discarded.** With
  `pipefail`, an `awk`/`sed` that exits on the first match kills the
  producer with SIGPIPE, the pipeline returns 141, and the caller's error
  branch then throws away a value that was read perfectly well. This showed
  up as `DNS over TLS: n/a` in the status report, and was latent in
  `detect_ssh_port` — where losing a custom SSH port would have opened the
  wrong port in UFW. Everything affected now captures the command output
  first and parses it from a here-string
  (`dns_over_tls_state`, `_dns_global_servers`, `_dns_probe_ms`,
  `detect_ssh_port`, `_dns_persist_link`, `_abuse_local_subnet`, UFW and
  qdisc status in the report).
- **False "1 key did not take the expected value" warning.** The verify pass
  re-rendered the configuration instead of checking the text that was
  written, so live inputs (listening ports, swap backend) could differ
  between the two renders; and the kernel normalises
  `ip_local_reserved_ports` into merged ranges, which never matched the
  written string. The rendered text is now produced once and reused, and
  that key is compared as a port set.
- The interface-specific `accept_ra` line is written with systemd's `-`
  prefix so an early-boot apply cannot log an error when the NIC is not up
  yet.
- Warnings raised inside a step no longer break the status line: they are
  buffered and printed underneath the step's verdict.
- Failing sysctl keys are now named in the warning itself instead of only
  in the log.

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
