# Roadmap

Single source of truth for phase status, scope, and the idea backlog.
Keep `CHANGELOG.md` for *what shipped*; keep this file for *what's next*.

## Phases

### Phase 1 — skeleton & core runtime ✅

Modular `src/` + single-file build, strict mode + ERR trap, logging, UI kit,
persistent config, change manifest, original/per-run backups with rollback,
workload detection, status report, CLI entrypoint, CI (ShellCheck/shfmt +
5-distro smoke), release automation.

### Phase 2 — optimization modules ✅

Layered profiles (`general`/`vpn-node`/`wireguard`/`panel`/`full`) with
auto-detection; capacity tiers S/M/L/XL with kernel-RAM cost preview;
`sysctl` (implements `docs/SYSCTL.md`, verified after apply), `dns`
(providers + latency test, decoupled select/apply), `swap` (verified swapon,
btrfs-safe), `limits` (PAM + systemd drop-in), `extras` (journald cap, NTP);
Quick/Custom Optimize flows with honest per-step outcomes.

### Phase 3 — security, VPN-aware tuning, network tools ✅

- `security` module (all consent-based, Layer 3): UFW with SSH-port
  auto-detect and lockout protection; fail2ban (resident cost stated);
  SSH hardening via validated `sshd_config.d` drop-in.
- `vpn` module: MSS clamping (IPv4+IPv6, boot-persisted via a oneshot
  unit — no resident process), Docker+UFW bypass audit.
- `tools` module: ping matrix (Iran + global targets), DNS latency,
  conntrack/BBR live status, listening-ports overview.

### Phase 4 — automation & distribution ✅ (code) / release ⬜

- Done: `--auto` non-interactive mode (`--profile`, `--tier`, `--dns`,
  `--no-swap/--no-limits/--no-extras`); `--install` to
  `/usr/local/bin/st`; `--update` self-update (release-first with SHA-256
  verification, raw-main fallback, `bash -n` + fingerprint gate).
- Remaining: tag `v2.0.0` after the release criteria below pass on a real
  server; then switch README install links from `main` to
  `releases/latest`.

## Backlog (unscheduled ideas)

- `st doctor` — drift detection: compare live kernel values against the
  last applied profile; offer re-apply (`--dry-run` already shows the diff;
  doctor adds re-apply + scheduling-free health verdicts).
- Before/after snapshot — capture retransmit/drop counters pre-apply so
  `--status` can show the measured effect, not a claim.
- ufw-docker integration (actually fix the bypass, not just warn).
- Panel/node port auto-suggestion for UFW from detected containers.
- Optional full-IPv6-disable toggle (leak prevention setups).
- Restore-to-factory: rollback from `original/` across all runs.
- irqbalance module (consent-based, multi-core hosts only).
- iperf3 helper (guided server/client test between two nodes).

Recently landed from this list: `--dry-run`, `--report`, reserved service
ports, zram backend, XanMod/BBRv3 installer, DoT + Iranian DNS presets,
service-restart offer, user-based capacity model (`--users`).

## Release criteria for v2.0.0

1. CI green on all 5 distro containers.
2. Real-server validation: one Marzban/Pasarguard node + one panel host —
   Quick Optimize, reboot, `--status` verification, `--rollback` restores.
3. `docs/SYSCTL.md` and the sysctl module in sync (spot-check).
4. README install commands point at the tagged release asset.
