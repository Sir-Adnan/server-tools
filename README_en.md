# 🧰 ServerTools

A **premium Linux server optimization toolkit** with a zero runtime footprint —
built for high-traffic VPN infrastructure: Xray/Reality nodes (`marzban-node`,
`pg-node`/Pasarguard, `marznode`), Marzban/Pasarguard panels, WireGuard, x-ui,
and Hiddify — and for general-purpose tuning of any Linux server.

> Stable release: **v2.4.0** · one file, no dependencies, run as root.
> Version 1 is frozen under [`legacy/`](legacy/) and no longer updated.

📖 **[Full 0-to-100 guide (Persian) ← docs/GUIDE.md](docs/GUIDE.md)**

## 📥 Install & run

Run directly:

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh)
```

Install as the `st` command (recommended):

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh) --install
```

From then on just run `st`; update with `st --update`.

## ⚡ One command, whole-server tuning

Run `st` and pick **1 (Quick Optimize)**. It auto-detects the workload and
applies these layers on top of each other:

- **Base layer (always):** BBR + fq, RAM-scaled accept queues and buffers,
  timers/keepalive, safe hardening, `tcp_min_snd_mss` (CVE-2019-11479 floor),
  and file/map ceilings.
- **Workload layer (VPN node):** IPv4+IPv6 forwarding, sized conntrack, tuned
  timeouts, and automatic reservation of listening service ports.
- **Data-path layer (perf):** spreads NIC softirq across every core
  (RPS/RFS/XPS), CPU governor `performance`, THP `madvise` — all non-disruptive
  and zero-footprint.
- **Extras:** swap (zram or file), 1M nofile limit, journald cap + NTP, and DNS
  selection that actually sticks.

Everything is idempotent — re-running is safe and converges to the same state.

## 🧭 What it does (the menu)

| Section | What it does |
| --- | --- |
| **Optimize** | Quick (automatic, recommended) and Custom (pick profile & modules) |
| **Inspect** | Full System Status · Doctor drift check (is it still in effect?) |
| **Recover** | Roll back the last run, or restore the original pre-tool state |
| **Secure** | UFW · fail2ban · SSH hardening · anti-abuse · node-API restriction |
| **Tools** | Ping · **speedtest with a server/location picker (Ookla or HTTP)** · benchmark · MSS · **NOTRACK** · **full IPv6 disable** · live view · APT mirror · report |
| **Node & Docker** | Node config backup · official node installers · container file limits |

## ✨ Design principles

| Principle | Detail |
| --- | --- |
| Zero footprint ⚡ | One-shot: it tunes the kernel and exits. No daemons/cron/telemetry. Whether 100 or 100,000 users are connected, it costs nothing at runtime. |
| Capacity-aware 📊 | conntrack and buffers scale by tier or by **real user count** (`--users`), with a RAM estimate and an honest warning before applying. |
| No regressions 🛡️ | Capacity keys are set as ceilings — never below a modern kernel's own default. |
| Real rollback ♻️ | Every change is recorded in a manifest before it happens; a pristine copy of each touched file is kept forever. |
| Honest reporting ✅ | No fake "OK": each step shows its true status (OK/WARN/FAILED), and DNS and the rest are verified against the live system after applying. |
| Tested quality 🧪 | ShellCheck + shfmt in CI; boot-tested on Ubuntu 20.04/22.04/24.04 and Debian 11/12. |

## ⌨️ CLI options

```text
--status              Print the full system status and exit
--auto                Non-interactive optimize (base + detected profile)
      --profile NAME  general | vpn-node | wireguard | panel | full
      --tier S|M|L|XL --users N   --dns cloudflare|ip1,ip2
      --no-swap  --no-limits  --no-extras  --no-perf
--dry-run             Show the plan and exact sysctl diff, apply NOTHING
--verify              Doctor: is everything still in effect? (drift check)
--report              Full plain-text report for tickets/support
--rollback            Revert the latest recorded run
--rollback-original   Restore the state from before ServerTools ever ran
--install / --update  Install / self-update the st command
--json                Machine-readable output (for --verify)
--no-color · --debug · -v · -h
```

Exit codes (for Ansible/CI): `0` success · `1` a step failed · `2` usage error ·
`3` applied but with a warning or drift.

Fleet example:

```bash
st --auto --profile vpn-node --users 10000 --dns cloudflare
st --verify --json     # nightly drift check from your own automation
```

## 📚 Documentation

[📖 Full guide](docs/GUIDE.md) ·
[Architecture](docs/ARCHITECTURE.md) ·
[Profiles](docs/PROFILES.md) ·
[sysctl spec](docs/SYSCTL.md) ·
[Rollback](docs/ROLLBACK.md) ·
[FAQ](docs/FAQ.md) ·
[Changelog](CHANGELOG.md)

## 🏗️ Repository layout

```text
src/       modular source (core/ + modules/ + menu + main)
build.sh   compiles src/ into a single file
dist/      build output (what end users run)
docs/      documentation and technical specs
tests/     smoke tests
legacy/    version 1 (frozen)
```

## 🛠️ Development

```bash
./build.sh        # build dist/server-tools.sh
make lint         # shellcheck + shfmt
./tests/smoke.sh  # quick test, no root needed
```

Engineering rules live in [CLAUDE.md](CLAUDE.md): no new dependencies, no bare
`|| true`, track every file change in the manifest before touching it, and
`dist/` is generated (never edit it — change `src/` and run `./build.sh`).

## 👤 Creator

- Creator: **UnknownZero** — Telegram: **@UnknownZero**
- License: [MIT](LICENSE)

*مستندات فارسی: [README.md](README.md)*
