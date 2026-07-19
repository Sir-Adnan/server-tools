# Profiles — the layered optimization model

> Status: **specification** — implemented by the Phase 2 modules.

## Why layers, not exclusive profiles

"Optimize the whole server" and "optimize for my workload" are not
alternatives. The base layer always covers the whole server; detection (or
manual choice) only decides what *extra* specialization goes on top.

```text
┌──────────────────────────────────────────────────────────────┐
│ Layer 3 — OPTIONAL (explicit user consent, cost stated)      │
│   UFW firewall · fail2ban · SSH hardening · irqbalance       │
├──────────────────────────────────────────────────────────────┤
│ Layer 2 — WORKLOAD (auto-detected, overridable)              │
│   vpn-node · panel · wireguard · general                     │
├──────────────────────────────────────────────────────────────┤
│ Layer 1 — BASE (always applied, whole server)                │
│   BBR/qdisc · core sysctl · limits · journald cap · NTP ·    │
│   DNS · swap (if missing) · log hygiene                      │
└──────────────────────────────────────────────────────────────┘
```

## Workload profiles (Layer 2)

| Profile | Detected via | Focus |
|---|---|---|
| `vpn-node` | `marzban-node`, `pg-node`, `xray`, `x-ui` containers/services | high conntrack, large buffers, forwarding, keepalive tuned for many idle clients |
| `wireguard` | active `wg` interfaces, wg-dashboard/wg-easy | everything in `vpn-node` **plus** IPv6 forwarding and MSS clamping |
| `panel` | Marzban/Pasarguard panel containers | modest network tuning; swap and service resilience matter more than throughput |
| `general` | nothing detected | complete general-purpose tuning (this is NOT a reduced profile) |
| `full` | manual choice | base + workload + every optional module with best-practice defaults |

A host can match several (rare); the UI shows all matches and asks.

## Capacity tiers

Conntrack tables and buffers consume real kernel RAM; sizing them for 100k
users on a 1 GB VPS would cause the very OOM problems we exist to prevent.
The tier is chosen automatically from RAM (overridable by the user), and the
estimated kernel memory cost is displayed **before** applying.

| Tier | Target concurrent users | Typical RAM | nf_conntrack_max | somaxconn / syn_backlog | rmem/wmem max |
|---|---|---|---|---|---|
| S | up to ~1k | ≤ 1 GB | 65,536 | 8,192 | 8 MB |
| M | up to ~10k | 2–4 GB | 262,144 | 16,384 | 16 MB |
| L | up to ~100k | 8–16 GB | 1,048,576 (+ explicit buckets) | 32,768 | 32 MB |
| XL | 100k+ | 32 GB+ | 2,097,152+ (+ tw_buckets/orphans tuning) | 65,535 | 64 MB |

Rule of thumb shown to the user: one conntrack entry ≈ 300 bytes, so a 2M
table can cost ~600 MB of kernel memory when full.

See `docs/SYSCTL.md` for the per-key values behind each tier.
