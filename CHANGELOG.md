# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] — 2.0.0-dev

Full rewrite ("ServerTools v2"). Phase 1: project skeleton and core runtime.

### Added
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

### Planned (next phases)
- Phase 2: optimization modules (sysctl, DNS, swap, limits) with layered
  profiles and capacity tiers (spec in `docs/SYSCTL.md` / `docs/PROFILES.md`).
- Phase 3: security module (UFW/fail2ban/SSH), VPN-aware tuning
  (IPv6 forwarding, MSS clamping, Docker+UFW), network test tools.
- Phase 4: `--auto` non-interactive mode, `st` installer command, self-update,
  first stable release.
