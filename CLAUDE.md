# CLAUDE.md — ServerTools

## What this is

ServerTools is a Linux server optimization toolkit written in pure bash, aimed
primarily at VPN infrastructure servers: Xray/Reality nodes (marzban-node,
pg-node/Pasarguard), central panels (Marzban, Pasarguard), WireGuard, x-ui.
Users run one built file as root — interactive TUI menu or non-interactive CLI.

Servers using this tool routinely carry 10k–100k+ concurrent VPN users, so the
tool itself must add **zero** runtime load.

## Golden rules (never break these)

1. **Zero footprint.** The tool is one-shot: it configures the kernel and
   exits. Never install daemons, cron jobs, agents, or telemetry by default.
   Optional services (irqbalance, fail2ban) only with explicit user consent,
   with their cost stated in the UI.
2. **Idempotent.** Running any action twice must be safe and converge to the
   same state — no backup-of-backup, no duplicated config lines.
3. **Track before touch.** Every file the script creates or modifies MUST go
   through `st_track_file <path>` *before* the change. That records the change
   in the manifest, snapshots a pristine `original/` copy on first touch, and
   a per-run backup. Rollback depends on this.
4. **Honest failures.** No bare `|| true`. If a failure is genuinely
   tolerable, add a comment stating *why*, and reflect the outcome in what the
   user sees. Never print "OK" for something that failed.
5. **No new runtime dependencies.** Allowed baseline: bash >= 4.4, coreutils,
   awk/sed/grep, iproute2. Everything else (curl, sysctl, docker, systemctl,
   tput…) must be feature-detected via `has_cmd` and degrade gracefully.
6. **`dist/` is generated.** Never edit `dist/server-tools.sh` directly.
   Edit `src/` and run `./build.sh`. Build order lives in the `SOURCES` array
   in `build.sh` — new src files must be added there.
7. **`legacy/` is frozen.** Never modify the legacy scripts.
8. **Never `git commit` or `git push`.** The user commits manually in
   VS Code. Prepare the working tree only (edit, build, test); at most,
   suggest a commit message in the summary.

## Working efficiently (token budget)

- This file is the only doc loaded every session — keep it lean. Details
  live elsewhere and are read on demand only: `ROADMAP.md` (phases, backlog,
  release criteria), `docs/*` (specs), `CHANGELOG.md`.
- Never read `dist/server-tools.sh` (generated, ~1600 lines) or anything in
  `legacy/` — work from `src/` files, which are small and single-purpose.
- Prefer a targeted Read/Grep of one `src/` file over re-scanning the tree;
  the Source map in `docs/ARCHITECTURE.md` says which file owns what.

## Commands

- Build: `./build.sh` (or `make build`)
- Lint: `make lint` — ShellCheck on the built file + `shfmt -i 2 -ci -d` on src
- Test: `./tests/smoke.sh` (build + parse + `--version`/`--help` without root)

CI (`.github/workflows/ci.yml`) mirrors these and also boots `--status` as
root inside Ubuntu 20.04/22.04/24.04 and Debian 11/12 containers. Keep it green.

## Style

- shfmt: 2-space indent, `-ci` (indented case branches).
- Functions: `snake_case` with a module prefix (`ui_`, `log_`, `net_`,
  `config_`, `manifest_`, `st_`, `detect_`).
- Globals: `ST_*`, `readonly` where possible. Locals always declared `local`.
- Colors only via the palette (`C_*`). Color labels/titles only — never
  values (readability on light and dark terminals). `ui_detect_terminal`
  already honours NO_COLOR, non-tty, and TERM=dumb; don't bypass it.
- Unicode box drawing only behind `ST_UTF8` checks, with an ASCII fallback.
- **The global `IFS=$'\n\t'` has no space.** So `for x in ${list//,/ }` does not
  split, `"${arr[*]}"` joins with a *newline*, and a bare `read -ra`/`read a b c`
  never splits a space-separated line. Use `ports_split` / `join_sp`, or prefix
  the read (`IFS=' ' read -ra …`). This class has caused silent, shipped bugs.
- User-facing docs: Persian first (`README.md`, `docs/FAQ.md`) with an English
  mirror. Code, comments, and commit messages: English.

## Versioning & releases

- Single source of truth: the `VERSION` file, injected as `@VERSION@` at build.
- SemVer. Update `CHANGELOG.md` with every user-visible change.
- Release = push tag `v*` → `release.yml` builds, checksums (SHA-256), and
  publishes `dist/server-tools.sh` as a GitHub Release asset.

## Architecture pointers

- Layered optimization model (base / workload / optional) and capacity tiers
  (S/M/L/XL by RAM and expected concurrent users): `docs/PROFILES.md`.
- The sysctl tuning spec with per-key rationale: `docs/SYSCTL.md`. Phase 2
  implements exactly that spec — change the spec first, then the code.
- Rollback/manifest design and guarantees: `docs/ROLLBACK.md`.
- Repo layout and build pipeline: `docs/ARCHITECTURE.md`.

## Roadmap

Phases, current status, backlog ideas, and release criteria: `ROADMAP.md`
(read it only when planning what to build next).
