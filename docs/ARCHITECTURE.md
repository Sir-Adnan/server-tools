# Architecture

## Goals

1. **Zero footprint** — a one-shot tool. It writes kernel-level configuration
   and exits; nothing of ours stays resident. Servers running this carry up to
   100k+ concurrent VPN users, so the tool's runtime cost must be zero.
2. **Trustworthy changes** — every touched file is tracked (manifest +
   pristine original + per-run backup) before it is changed.
3. **Single-file delivery, modular development** — users fetch one file;
   developers work in a structured tree.

## Build pipeline

```text
src/ (modular, ShellCheck-directive headers)
  └── build.sh  — concatenates SOURCES in order, strips per-file shebangs,
                  injects VERSION (@VERSION@)
        └── dist/server-tools.sh  — the only artifact users run
```

- Build order lives in the `SOURCES` array in `build.sh`; the header must be
  first (strict mode + constants + ERR trap) and `99-main.sh` last
  (`main "$@"` is the final statement of the built file).
- `bash -n` runs as part of every build; CI additionally runs ShellCheck on
  the *built* file, which lints the program as a whole.

## Source map

| Path | Responsibility |
|---|---|
| `src/00-header.sh` | strict mode, constants (`ST_*`), ERR trap |
| `src/core/colors.sh` | terminal capability detection, palette (`C_*`) |
| `src/core/log.sh` | leveled logging, rotation, `die` |
| `src/core/ui.sh` | rules/titles/kv/menu/confirm/pause, logo |
| `src/core/utils.sh` | OS/network facts, `has_cmd`, cached public IP |
| `src/core/state.sh` | persistent config, change manifest |
| `src/core/backup.sh` | `st_track_file`, manifest-driven rollback |
| `src/modules/detect.sh` | workload detection (panel/node/wireguard/…) |
| `src/modules/sysinfo.sh` | System Status report |
| `src/menu.sh` | interactive menu |
| `src/99-main.sh` | CLI parsing, entrypoint |

Phase 2 adds `src/modules/{sysctl,dns,swap,limits}.sh` plus
`src/profiles.sh` implementing `docs/PROFILES.md` and `docs/SYSCTL.md`.

## Runtime filesystem layout (FHS)

| Path | Purpose |
|---|---|
| `/etc/server-tools/config` | user preferences (key=value) |
| `/var/lib/server-tools/manifest.tsv` | change manifest (rollback source of truth) |
| `/var/lib/server-tools/backups/original/<abs-path>` | pristine first-touch copies, never overwritten |
| `/var/lib/server-tools/backups/runs/<run-id>/<abs-path>` | per-run copies |
| `/var/log/server-tools.log` | log (fallback: `/var/lib/server-tools/`) |

Nothing is written to `/tmp` — predictable filenames in world-writable
directories are a symlink-attack risk for a root tool.

## Error handling policy

- `set -Eeuo pipefail` plus a global ERR trap that reports the failing line
  and command; nothing dies silently.
- Failures that are genuinely tolerable are guarded explicitly with a comment
  explaining why (bare `|| true` is banned by CLAUDE.md).
- Optional tooling (`curl`, `sysctl`, `docker`, `tput`, …) is feature-detected
  with `has_cmd` and degrades to `unknown`/`?` values instead of failing.

## UI policy

- Color only labels/titles via the `C_*` palette — never values, so output
  stays readable on light and dark terminals.
- `NO_COLOR`, non-tty stdout, `TERM=dumb`, and `--no-color` all disable color.
- Unicode box drawing only when the locale is UTF-8; ASCII fallback otherwise.
- The dashboard renders instantly: network lookups (public IP) are cached for
  the process lifetime; nothing in the menu loop blocks on the network.
