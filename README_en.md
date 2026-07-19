# 🧰 ServerTools

Linux server optimization toolkit — built for VPN infrastructure servers
(Xray/Reality nodes such as `marzban-node` and `pg-node`, Marzban/Pasarguard
panels, WireGuard, x-ui) as well as general-purpose server tuning.

> 🚧 **Status:** v2 is under active development (Phase 1 — core and
> infrastructure complete). The old stable script is frozen under
> [`legacy/`](legacy/) and no longer receives updates.

## Design principles

- **Zero footprint** — one-shot tool: it writes kernel-level settings and
  exits. No daemons, no cron, no telemetry. Whether 100 or 100,000 users are
  connected, ServerTools consumes nothing at runtime.
- **Layered optimization** — a base layer (always applied, whole server),
  a workload layer (VPN node / panel / general — auto-detected or manually
  chosen), and an optional layer (firewall, SSH hardening, …).
- **Capacity-aware** — conntrack and buffer sizing follow a capacity tier
  (up to 100k+ concurrent users) with the kernel RAM cost estimated up front.
- **Real rollback** — every change is recorded in a manifest; a pristine
  `original/` copy of each touched file is kept forever.
- **Tested quality** — ShellCheck + shfmt in CI; boot-tested on
  Ubuntu 20.04/22.04/24.04 and Debian 11/12.

## Install & run

v2 development preview:

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh)
```

Legacy (V15.2.0, frozen):

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/legacy/opt.sh)
```

CLI options: `--status`, `--rollback`, `--no-color`, `--debug`,
`-v/--version`, `-h/--help`. Interactive menu starts when no action is given.

## Roadmap

1. **Phase 1 (done)** — skeleton, core runtime, build system, CI.
2. **Phase 2** — optimization modules (sysctl/DNS/swap/limits), profiles,
   capacity tiers ([spec](docs/SYSCTL.md)).
3. **Phase 3** — security (UFW/fail2ban/SSH), VPN-aware tuning, network tools.
4. **Phase 4** — non-interactive `--auto`, `st` installer, self-update,
   first stable release.

See [docs/](docs/) for architecture and specs, and [CLAUDE.md](CLAUDE.md) for
the engineering rules. Persian documentation: [README.md](README.md).

**Creator:** UnknownZero — Telegram **@UnknownZero** · License: [MIT](LICENSE)
