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
| `net.core.netdev_budget` | `600` | packets drained per softirq poll — a single core otherwise caps PPS (paired with RPS, below) |
| `net.core.netdev_budget_usecs` | `8000` | time budget for the same poll |

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
| `net.ipv4.tcp_rfc1337` | `1` | protects TIME-WAIT sockets from RST assassination |
| `net.ipv4.tcp_mtu_probing` | `1` | **changed vs legacy (was 0)** — mode 1 activates only after a blackhole is detected, preventing stalls on ICMP-filtered paths; the harmful aggressive mode is `2` |
| `net.ipv4.tcp_min_snd_mss` | `512` | CVE-2019-11479 safe floor — keeps PMTU probing useful without letting a peer force a pathologically small MSS (goodput collapse / remote DoS) |

Applying qdisc live: `default_qdisc` only affects new interfaces, so the
module also runs `tc qdisc replace` on the default interface — no reboot
needed for the switch to fq.

### Buffers (TIER-scaled)

| Key | S / M / L / XL | Why |
| --- | --- | --- |
| `net.core.rmem_max` / `wmem_max` | 8 / 16 / 32 / 64 MB | BDP headroom for long-haul high-bandwidth paths |
| `net.ipv4.tcp_rmem` | `≥ 4096 87380 <rmem_max>` | autotuning bounds. **Per-field ceiling** — the middle value is the buffer each new socket starts with, and modern kernels default to `131072`; a hardcoded triple would shrink it back to the pre-4.20 `87380` |
| `net.ipv4.tcp_wmem` | `≥ 4096 65536 <wmem_max>` | autotuning bounds. **Per-field ceiling** (same rule; also stops a small tier from lowering a large kernel max) |
| `net.core.rmem_default` / `wmem_default` | `262144` | sane default without autotuning |
| `net.ipv4.udp_rmem_min` / `udp_wmem_min` | `16384` | UDP floor under memory pressure (WireGuard/Hysteria2) |
| `net.core.optmem_max` | `≥ 131072` | per-socket ancillary buffer headroom (**ceiling** — never below the kernel default, which is 131072 on modern kernels) |

### High-churn caps (L / XL only)

| Key | L / XL | Why |
| --- | --- | --- |
| `net.ipv4.tcp_max_tw_buckets` | 524288 / 1048576 | cap TIME-WAIT memory under mass reconnects |
| `net.ipv4.tcp_max_orphans` | 131072 / 262144 | cap orphaned-socket memory under churn |

### Reserved service ports (dynamic)

`net.ipv4.ip_local_reserved_ports` is generated at apply time from the
listening ports that fall inside our ephemeral range (10240-65535, up to 64
entries after collapsing consecutive runs into ranges) — an outgoing
connection can then never grab a panel/node port. TCP listeners are taken
as-is; UDP is sampled twice a second apart and only the stable intersection is
kept, so a proxy's transient outbound sockets never enter the list.

Two properties this key does *not* share with the others:

- **UDP churn is discarded wholesale.** A userspace proxy opens one unconnected
  UDP socket per session and a QUIC/Hysteria session easily outlives the two
  probes, so on a busy node the samples agree on dozens of ephemeral ports that
  belong to no service. More than `ST_UDP_SERVICE_MAX` (8) UDP candidates is
  therefore treated as session churn and dropped, with a warning; pin genuine
  UDP service ports with the `reserved_ports` config key.
- **Drift is judged by coverage, not equality.** This is the only key whose
  intent is rebuilt from the live system on every render, so the set legitimately
  differs between runs. Reserving *more* than the current render asks for is
  harmless; only a *missing* port is a hazard, and Doctor reports that
  separately (`_doctor_unreserved_ports`). Comparing for equality made the key
  report drift forever on a busy node.

### System capacity

| Key | Value | Why |
| --- | --- | --- |
| `fs.file-max` | `≥ 2097152` | sockets are files; 100k users × several fds. **Ceiling** — a kernel/distro that already set it higher (often unlimited) is left as-is |
| `fs.nr_open` | `≥ 2097152` | per-process fd ceiling — raising the nofile limit is silently capped by this. **Ceiling** |
| `vm.max_map_count` | `≥ 262144` | Xray/sing-box map many buffers per connection. **Ceiling** — kernels ≥ 6.7 default to 1048576, which is never lowered |
| `vm.swappiness` | `10` | swap is an OOM safety net, not working memory (100 on zram — see swap module) |
| `net.ipv4.icmp_echo_ignore_broadcasts` | `1` | drop broadcast pings (smurf hardening) |
| `net.ipv4.icmp_ignore_bogus_error_responses` | `1` | ignore malformed ICMP error replies |

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

## Companion — data-path tuning that isn't sysctl (`src/modules/perf.sh`)

Some wins live in `/sys`, not `/etc/sysctl.d`. The perf module applies them
live and persists each through ONE oneshot systemd unit
(`server-tools-perf.service`) that runs a generated, idempotent boot script and
exits — no resident process. The script and unit are tracked, so rollback
removes them; `perf_verify` reports drift in Doctor.

| Setting | Value | Why / guard |
| --- | --- | --- |
| RPS/RFS/XPS | `rps_cpus`/`xps_cpus` = all-cores mask; `rps_flow_cnt` = 4096; `net.core.rps_sock_flow_entries` = 32768 | spreads NIC softirq across cores — decisive on single-queue virtio. **Applied only when the NIC has fewer hardware queues than cores** (RSS already spreads a multi-queue NIC). Override: `rps_mode` config = `auto`\|`on`\|`off` |
| CPU governor | `performance` | no ramp-up latency on bursty proxy traffic. Skipped silently where `cpufreq` is absent (typical VPS) |
| Transparent Huge Pages | `madvise` (enabled + defrag) | stops khugepaged compaction stalls from adding tail latency, without denying THP to code that explicitly asks for it (`never` would) |

Non-disruptive by design: every write above takes effect for new packets/pages
without resetting the link, so it is safe to apply on a node already carrying
users. That is also why `ethtool -G` ring resizing is excluded (below).

## Optional — full IPv6 disable (`src/modules/ipv6.sh`)

Opt-in only, from Tools → Network → IPv6 control; **never** part of the base or
workload layers. It writes a *separate*, tracked drop-in
(`/etc/sysctl.d/99-server-tools-ipv6.conf`) so it can be undone independently of
the main tuning file:

```ini
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

`all.disable_ipv6` takes effect on every existing interface at once; `default`
covers interfaces created later; `lo` completes the shutdown. The knob is left
in place (not removed like GRUB's `ipv6.disable=1` would), so the base layer's
IPv6 keys (`forwarding`, `accept_ra`) still apply cleanly without "cannot stat"
errors. Guards: refuses on a host whose only default route is IPv6, and warns
when the live SSH session is over IPv6 or a service listens on `[::]`.
`ipv6_verify` reports drift in Doctor; Enable removes the drop-in and resets the
three keys live.

## Deliberately NOT set

| What | Why not |
| --- | --- |
| Interface MTU / netplan MTU persistence | provider defaults differ (GCP 1460, Hetzner private 1450); forcing 1500 breaks networking — the v1 "cleanup" hazard |
| NIC ring buffers (`ethtool -G`) | frequently harms VPS latency; hypervisor-dependent |
| `Domains=~.` DNS routing | global DNS hijack; breaks cloud-internal resolution |
| `tcp_mtu_probing=2` | aggressive probing shrinks MSS pathologically |
| Disabling SACK/timestamps | outdated cargo-cult tuning; hurts modern stacks |
| `net.ipv4.udp_mem` | the kernel already sizes the UDP pool from RAM; a fixed formula only ever caps it lower on a busy QUIC/Hysteria node |
| Per-interface `accept_ra=2` on static links | only added where the link already accepts RAs — on a statically-addressed link networkd holds it at 0 and would revert us forever (a false "drift") |
