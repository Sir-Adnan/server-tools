# SYSCTL.md — kernel tuning specification

> Status: **implemented** by `src/modules/sysctl.sh` (Phase 2). This document
> and the module must stay in sync — change the spec first, then the code.

All values land in `/etc/sysctl.d/99-server-tools.conf` (tracked via
`st_track_file`). `TIER` refers to the capacity tier table in
`docs/PROFILES.md`.

## Layer 1 — base (always applied)

### Congestion control & queueing

| Key | Value | Why |
| --- | --- | --- |
| `net.core.default_qdisc` | `fq` with BBR, else `fq_codel` | BBR needs fq pacing; fq_codel fights bufferbloat otherwise |
| `net.ipv4.tcp_congestion_control` | `bbr` if kernel ≥ 4.9 and module loads, else `cubic` | best throughput/latency on lossy long-haul paths |

BBR persistence: `tcp_bbr` in `/etc/modules-load.d/server-tools.conf`
(tracked, so rollback removes it — a v1 gap).

### Connection accept path (TIER-scaled)

| Key | S / M / L / XL | Why |
| --- | --- | --- |
| `net.core.somaxconn` | 8192 / 16384 / 32768 / 65535 | accept queue for bursty client reconnects |
| `net.ipv4.tcp_max_syn_backlog` | same as somaxconn | SYN flood headroom |
| `net.core.netdev_max_backlog` | 16384 / 32768 / 65536 / 65536 | per-CPU ingress queue |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood fallback |

### Ports, timers, keepalive

| Key | Value | Why |
| --- | --- | --- |
| `net.ipv4.ip_local_port_range` | `10240 65535` | outbound port capacity; keeps privileged/low ports free |
| `net.ipv4.tcp_fin_timeout` | `30` | faster FIN_WAIT2 reclaim under churn |
| `net.ipv4.tcp_tw_reuse` | `1` | reuse TIME_WAIT for outbound |
| `net.ipv4.tcp_keepalive_time/intvl/probes` | `300 / 60 / 5` | detect dead tunnels in ~10 min instead of hours |
| `net.ipv4.tcp_slow_start_after_idle` | `0` | idle tunnels resume at full cwnd |
| `net.ipv4.tcp_no_metrics_save` | `1` | don't poison future connections with bad-path metrics |
| `net.ipv4.tcp_fastopen` | `3` | harmless enable both directions |
| `net.ipv4.tcp_notsent_lowat` | `16384` | caps unsent-buffer depth — lower proxy latency (Cloudflare-documented) |
| `net.ipv4.tcp_mtu_probing` | `1` | **changed vs legacy (was 0)** — mode 1 activates only after a blackhole is detected, preventing stalls on ICMP-filtered paths; the harmful aggressive mode is `2` |

### Buffers (TIER-scaled)

| Key | S / M / L / XL | Why |
| --- | --- | --- |
| `net.core.rmem_max` / `wmem_max` | 8 / 16 / 32 / 64 MB | BDP headroom for long-haul high-bandwidth paths |
| `net.ipv4.tcp_rmem` | `4096 87380 <rmem_max>` | autotuning bounds |
| `net.ipv4.tcp_wmem` | `4096 65536 <wmem_max>` | autotuning bounds |
| `net.core.rmem_default` / `wmem_default` | `262144` | sane default without autotuning |
| `net.ipv4.udp_rmem_min` / `udp_wmem_min` | `16384` | UDP floor under memory pressure (WireGuard/Hysteria2) |
| `net.ipv4.udp_mem` | scaled to RAM | QUIC/Hysteria2 total UDP memory |

### System capacity

| Key | Value | Why |
| --- | --- | --- |
| `fs.file-max` | `2097152` | sockets are files; 100k users × several fds |
| `vm.swappiness` | `10` | swap is an OOM safety net, not working memory |

## Layer 2 — workload keys

### `vpn-node` / `wireguard`

| Key | Value | Why |
| --- | --- | --- |
| `net.ipv4.ip_forward` | `1` | routing user traffic |
| `net.ipv6.conf.all.forwarding` | `1` | **v1 gap** — without it WireGuard/tunnelled IPv6 silently fails |
| `net.netfilter.nf_conntrack_max` | per TIER | NAT/firewall state table |
| `net.netfilter.nf_conntrack_buckets` | `max / 4` | hash table sized with the table (kernel default lags) |
| `net.netfilter.nf_conntrack_tcp_timeout_established` | `3600` | kernel default is **5 days** — idle VPN flows would exhaust the table |
| `net.ipv4.conf.all.rp_filter` | `2` | loose mode — strict breaks multi-homed/tunnel routing |
| `net.ipv4.conf.all.accept_redirects` / `send_redirects` | `0` | a router must not accept/emit ICMP redirects |
| `net.ipv4.conf.all.accept_source_route` | `0` | classic hardening |

Prerequisite handled by the module: `modprobe nf_conntrack` + persistence,
otherwise the `net.netfilter.*` keys silently fail to apply (a v1 bug).

Non-sysctl companion for `wireguard`: MSS clamping
(`-j TCPMSS --clamp-mss-to-pmtu` on FORWARD) — the most common fix for
"connects but pages don't load" behind NAT.

### `panel`

Base layer only, with tier capped at M — a dashboard host doesn't need a 1M
conntrack table; RAM is better left to the database.

## Deliberately NOT set

| What | Why not |
| --- | --- |
| Interface MTU / netplan MTU persistence | provider defaults differ (GCP 1460, Hetzner private 1450); forcing 1500 breaks networking — the v1 "cleanup" hazard |
| NIC ring buffers (`ethtool -G`) | frequently harms VPS latency; hypervisor-dependent |
| `Domains=~.` DNS routing | global DNS hijack; breaks cloud-internal resolution |
| `tcp_mtu_probing=2` | aggressive probing shrinks MSS pathologically |
| Disabling SACK/timestamps | outdated cargo-cult tuning; hurts modern stacks |
