# shellcheck shell=bash
# ============================================================================
# modules/tools.sh — on-demand network diagnostics. Read-only except where
# a tool explicitly says otherwise; nothing here runs in the background.
# ============================================================================

# Format: label|ip
readonly -a ST_PING_TARGETS=(
  'Iran - TCI (217.218.127.127)|217.218.127.127'
  'Iran - Shecan (178.22.122.100)|178.22.122.100'
  'Global - Cloudflare (1.1.1.1)|1.1.1.1'
  'Global - Google (8.8.8.8)|8.8.8.8'
)

tools_ping_matrix() {
  ui_section "Ping matrix (Iran + global, 3 probes each)"
  if ! has_cmd ping; then
    printf 'ping is not available on this system.\n'
    return 0
  fi
  printf 'Useful for judging how well this location serves users in Iran.\n\n'
  local entry label ip out loss avg
  for entry in "${ST_PING_TARGETS[@]}"; do
    IFS='|' read -r label ip <<<"$entry"
    out="$(ping -c 3 -W 1 "$ip" 2>/dev/null)" || out=''
    loss="$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' <<<"$out" | cut -d'%' -f1)" || loss=''
    avg="$(awk -F'/' '/rtt|round-trip/ {print $5; exit}' <<<"$out")" || avg=''
    if [[ -n $avg ]]; then
      printf '  %-38s loss %3s%%   avg %s ms\n' "$label" "${loss:-?}" "$avg"
    else
      printf '  %-38s %sunreachable%s\n' "$label" "$C_ERR" "$C_RESET"
    fi
  done
}

tools_tcp_status() {
  ui_section "TCP / conntrack live status"
  ui_kv "Congestion" "$(sysctl_get net.ipv4.tcp_congestion_control)"
  ui_kv "Qdisc" "$(sysctl_get net.core.default_qdisc)"
  ui_kv "Available cc" "$(sysctl_get net.ipv4.tcp_available_congestion_control)"
  ui_kv "IPv4 forward" "$(sysctl_get net.ipv4.ip_forward)"
  ui_kv "IPv6 forward" "$(sysctl_get net.ipv6.conf.all.forwarding)"

  local count max
  count="$(sysctl_get net.netfilter.nf_conntrack_count)"
  max="$(sysctl_get net.netfilter.nf_conntrack_max)"
  if [[ $count =~ ^[0-9]+$ && $max =~ ^[0-9]+$ && $max -gt 0 ]]; then
    ui_kv "Conntrack" "${count} / ${max} ($((count * 100 / max))% used)"
  else
    ui_kv "Conntrack" "module not loaded"
  fi
}

tools_listening_ports() {
  ui_section "Listening ports"
  if ! has_cmd ss; then
    printf 'ss (iproute2) is not available.\n'
    return 0
  fi
  # Display-only snapshot, capped with awk: `head` would SIGPIPE ss under
  # pipefail and turn a fine listing into a spurious warning.
  ss -tulnp 2>/dev/null | awk 'NR <= 30' || log_warn "Could not list sockets."
}

# Ookla speedtest CLI — the accurate, reliable path: it uses Ookla's own
# protocol and a nearby server, so it sidesteps the Cloudflare 403s / inbound
# throttling some hosts (notably in Iran) hit on plain HTTP tests. Fetched on
# demand, run once and deleted — zero persistent footprint (rule 1).
readonly ST_OOKLA_VER='1.2.0'
# Cloudflare's speed endpoints answer 403 to a bare curl UA on some IPs; a
# browser UA dodges that for the HTTP fallback.
readonly ST_HTTP_UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36'

# _st_ookla_arch — Ookla CLI arch tag for this machine (non-zero if unsupported).
_st_ookla_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) printf 'x86_64' ;;
    aarch64 | arm64) printf 'aarch64' ;;
    armv7* | armhf) printf 'armhf' ;;
    i386 | i686) printf 'i386' ;;
    *) return 1 ;;
  esac
}

# _st_fetch_ookla — download + extract the official Ookla CLI into a fresh temp
# dir; echo the dir on success (the caller runs and removes it). Empty output /
# non-zero on any failure, so the caller can fall back to the HTTP test.
_st_fetch_ookla() {
  local arch dir url
  arch="$(_st_ookla_arch)" || return 1
  has_cmd tar || return 1
  mkdir -p "$ST_LIB_DIR"
  dir="$(mktemp -d "${ST_LIB_DIR}/ookla.XXXXXX" 2>/dev/null)" || return 1
  url="https://install.speedtest.net/app/cli/ookla-speedtest-${ST_OOKLA_VER}-linux-${arch}.tgz"
  if has_cmd curl; then
    curl -fsSL --max-time 60 -o "${dir}/cli.tgz" "$url" 2>>"$ST_LOG_FILE" || {
      rm -rf "$dir"
      return 1
    }
  elif has_cmd wget; then
    wget -q -T 60 -O "${dir}/cli.tgz" "$url" 2>>"$ST_LOG_FILE" || {
      rm -rf "$dir"
      return 1
    }
  else
    rm -rf "$dir"
    return 1
  fi
  if ! tar -xzf "${dir}/cli.tgz" -C "$dir" 2>>"$ST_LOG_FILE" || [[ ! -x "${dir}/speedtest" ]]; then
    rm -rf "$dir"
    return 1
  fi
  printf '%s' "$dir"
}

# _st_fmt_speed BYTES_PER_SEC — "938.5 Mbit/s  (117.3 MB/s)" or "n/a".
_st_fmt_speed() {
  awk -v s="${1:-0}" 'BEGIN {
    if (s + 0 <= 0) { printf "n/a"; exit }
    printf "%.1f Mbit/s  (%.1f MB/s)", s * 8 / 1000000, s / 1048576
  }'
}

# _st_cf_streams N URL OUTDIR PREFIX WRITEOUT [UPLOAD_FILE] — run N parallel
# curl transfers, each writing its %{WRITEOUT} to OUTDIR/PREFIX<i>, and echo
# the summed rate (bytes/s). Parallel streams are what a real speed test uses:
# a single flow rarely saturates a fast path.
_st_cf_streams() {
  local n="$1" url="$2" dir="$3" prefix="$4" field="$5" upload="${6:-}" i
  rm -f "${dir}/${prefix}"* 2>/dev/null # reusable across fallback attempts
  for ((i = 1; i <= n; i++)); do
    if [[ -n $upload ]]; then
      curl -o /dev/null -s -A "$ST_HTTP_UA" --max-time 20 -w "%{${field}}\n" \
        --data-binary @"$upload" "$url" >"${dir}/${prefix}${i}" 2>/dev/null &
    else
      curl -o /dev/null -s -A "$ST_HTTP_UA" --max-time 20 -w "%{${field}}\n" \
        "$url" >"${dir}/${prefix}${i}" 2>/dev/null &
    fi
  done
  wait
  cat "${dir}/${prefix}"* 2>/dev/null | awk '{s += $1} END {printf "%.0f", s + 0}'
}

# tools_speedtest — a real, reliable bandwidth test. In order of preference:
#   1. an Ookla binary already on the host (gold standard);
#   2. the official Ookla CLI, fetched, run once and deleted (accurate, picks a
#      nearby server, sidesteps Cloudflare 403s some hosts get);
#   3. a self-contained HTTP test (parallel streams to Cloudflare + mirrors).
# The deprecated speedtest.net Python client is never used — it breaks against
# Ookla's API and is frequently filtered from Iran.
tools_speedtest() {
  ui_section "Bandwidth test"

  # 1. A real Ookla binary already installed — the Python "speedtest-cli" (even
  #    when it shadows the name) is excluded via the version check.
  if has_cmd speedtest && speedtest --version 2>/dev/null | grep -qi 'ookla'; then
    ui_confirm "Run the installed Ookla speedtest now? (uses bandwidth)" || return 2
    speedtest --accept-license --accept-gdpr || log_warn "Ookla speedtest exited with an error."
    return 0
  fi

  # 2. Fetch-and-run the official Ookla CLI (removed afterwards). Most accurate,
  #    and immune to the Cloudflare 403 the HTTP path can hit.
  if _st_ookla_arch >/dev/null 2>&1 && has_cmd tar && { has_cmd curl || has_cmd wget; }; then
    printf 'The most accurate test uses the official %sOokla%s speedtest client —\n' "$C_KEY" "$C_RESET"
    printf '%sdownloaded, run once, then deleted (nothing stays installed).%s\n' "$C_MUTED" "$C_RESET"
    if ui_confirm "Download and run it now? (uses bandwidth)"; then
      local odir
      odir="$(_st_fetch_ookla)" || odir=''
      if [[ -n $odir ]]; then
        printf '\n'
        "${odir}/speedtest" --accept-license --accept-gdpr || log_warn "Ookla speedtest exited with an error."
        rm -rf "$odir"
        return 0
      fi
      log_warn "Could not fetch the Ookla client — using the built-in HTTP test instead."
    fi
  fi

  # 3. Self-contained HTTP fallback.
  if ! has_cmd curl; then
    log_error "curl is required for the built-in bandwidth test."
    return 1
  fi
  printf '\nBuilt-in %sdownload · upload · latency%s test (Cloudflare + mirrors).\n' "$C_KEY" "$C_RESET"
  ui_confirm "Run it now? (transfers up to ~500 MB)" || return 2
  printf '\n'

  local base='https://speed.cloudflare.com' streams=4 ul_bytes=26214400
  local dir lat dl ul src dl_host='n/a'

  # --- Latency: best TCP-connect of three tiny requests --------------------
  printf '  %s%-9s%s measuring…' "$C_KEY" "Latency" "$C_RESET"
  lat="$(for _ in 1 2 3; do
    curl -o /dev/null -s -A "$ST_HTTP_UA" -w '%{time_connect}\n' --max-time 5 "${base}/__down?bytes=0" 2>/dev/null
  done | awk 'NF && $1 + 0 > 0 {if (m == 0 || $1 < m) m = $1} END {if (m > 0) printf "%.1f", m * 1000}')"
  printf '\r  %s%-9s%s %s ms            \n' "$C_KEY" "Latency" "$C_RESET" "${lat:-n/a}"

  mkdir -p "$ST_LIB_DIR"
  dir="$(mktemp -d "${ST_LIB_DIR}/sptest.XXXXXX" 2>/dev/null)" || dir=''
  if [[ -z $dir ]]; then
    log_error "Could not create a work directory for the test."
    return 1
  fi

  # --- Download: parallel streams, with mirror fallback. Cloudflare's __down
  # caps the byte count at 1e8, and some networks throttle large inbound CDN
  # transfers even when upload is fine — so we try Cloudflare, then mirrors,
  # and keep the first source that actually moves bytes.
  printf '  %s%-9s%s measuring…' "$C_KEY" "Download" "$C_RESET"
  dl=0
  for src in \
    "${base}/__down?bytes=100000000|Cloudflare" \
    'https://speed.hetzner.de/100MB.bin|Hetzner' \
    'http://ipv4.download.thinkbroadband.com/100MB.zip|thinkbroadband'; do
    dl="$(_st_cf_streams "$streams" "${src%%|*}" "$dir" dl speed_download)"
    if ((dl > 0)); then
      dl_host="${src##*|}"
      break
    fi
  done
  printf '\r  %s%-9s%s %s          \n' "$C_KEY" "Download" "$C_RESET" "$(_st_fmt_speed "$dl")"

  # --- Upload: N parallel streams of a zero-filled payload, summed ---------
  printf '  %s%-9s%s measuring…' "$C_KEY" "Upload" "$C_RESET"
  head -c "$ul_bytes" /dev/zero >"${dir}/payload" 2>/dev/null
  ul="$(_st_cf_streams "$streams" "${base}/__up" "$dir" ul speed_upload "${dir}/payload")"
  printf '\r  %s%-9s%s %s          \n' "$C_KEY" "Upload" "$C_RESET" "$(_st_fmt_speed "$ul")"

  rm -rf "$dir"

  if ((dl == 0 && ul == 0)); then
    log_error "Could not reach the Cloudflare speed servers — network blocked? See the log."
    return 1
  fi
  printf '  %s%-9s%s %sdown: %s · up: Cloudflare · %d streams%s\n' \
    "$C_MUTED" "via" "$C_RESET" "$C_MUTED" "$dl_host" "$streams" "$C_RESET"
  log_info "Bandwidth test: down=${dl}B/s (${dl_host}) up=${ul}B/s ping=${lat:-?}ms (${streams} streams)."
  return 0
}

# tools_benchmark — quick, dependency-light CPU and disk figures. Comparable
# between servers, not absolute hardware ratings. The disk test averages three
# runs (like bench.sh) so one cached run cannot flatter the result, and AES-NI
# is reported because it decides TLS/Reality throughput on a proxy node.
tools_benchmark() {
  ui_section "Quick benchmark"

  ui_kv "CPU" "$(cpu_model)"
  local aes='no'
  grep -qm1 -w aes /proc/cpuinfo 2>/dev/null && aes='yes'
  ui_kv "Cores · AES-NI" "$(cpu_cores) · ${aes}"

  if has_cmd sha256sum; then
    local start end
    start="$(date +%s%N)"
    dd if=/dev/zero bs=1M count=256 status=none 2>/dev/null | sha256sum >/dev/null
    end="$(date +%s%N)"
    ui_kv "SHA256 (256 MB)" "$(awk -v n=$((end - start)) 'BEGIN {printf "%.2f s", n / 1000000000}')"
  fi

  local target='/var/tmp' avail_mb
  avail_mb="$(df -Pm "$target" 2>/dev/null | awk 'NR == 2 {print $4}')" || avail_mb=0
  [[ $avail_mb =~ ^[0-9]+$ ]] || avail_mb=0
  if ((avail_mb > 2048)); then
    printf '  %s%-19s%s measuring…' "$C_KEY" "Disk write (3×1 GB)" "$C_RESET"
    local run out mbps sum=0 cnt=0
    for run in 1 2 3; do
      out="$(LC_ALL=C dd if=/dev/zero of="${target}/.st-bench" bs=1M count=1024 conv=fdatasync 2>&1)" || out=''
      # dd's summary line ends in "… , N MB/s" (or GB/s / kB/s) — normalise to MB/s.
      mbps="$(awk '/copied|bytes/ {u = $NF; v = $(NF - 1) + 0
        if (u == "GB/s") v *= 1024; else if (u == "kB/s") v /= 1024
        printf "%.0f", v; exit}' <<<"$out")"
      [[ $mbps =~ ^[0-9]+$ ]] && {
        sum=$((sum + mbps))
        cnt=$((cnt + 1))
      }
    done
    rm -f "${target}/.st-bench"
    if ((cnt > 0)); then
      printf '\r  %s%-19s%s %d MB/s (avg of %d)        \n' "$C_KEY" "Disk write (3×1 GB)" "$C_RESET" $((sum / cnt)) "$cnt"
    else
      printf '\r  %s%-19s%s unavailable        \n' "$C_KEY" "Disk write (3×1 GB)" "$C_RESET"
    fi
  else
    ui_kv "Disk write" "skipped (needs 2 GB free in ${target})"
  fi

  ui_kv "Load · RAM" "$(load_avg) · $(mem_total_mb) MB"
  return 0
}

# tools_watch — live view of what matters under load. A foreground viewer,
# not a service: it exits when you leave and leaves nothing behind.
tools_watch() {
  if [[ ! -t 0 ]]; then
    printf 'The live view needs an interactive terminal.\n'
    return 2
  fi
  local iface rx_prev tx_prev rx tx ct max sockets key
  iface="$(net_default_iface)" || iface=''
  if [[ -z $iface || ! -r /sys/class/net/${iface}/statistics/rx_bytes ]]; then
    printf 'Cannot read interface counters for the live view.\n'
    return 2
  fi
  rx_prev="$(cat "/sys/class/net/${iface}/statistics/rx_bytes")"
  tx_prev="$(cat "/sys/class/net/${iface}/statistics/tx_bytes")"

  while true; do
    sleep 2
    rx="$(cat "/sys/class/net/${iface}/statistics/rx_bytes")"
    tx="$(cat "/sys/class/net/${iface}/statistics/tx_bytes")"
    ct="$(sysctl_get net.netfilter.nf_conntrack_count)"
    max="$(sysctl_get net.netfilter.nf_conntrack_max)"
    sockets="$(awk '/^TCP:/ {print $3; exit}' /proc/net/sockstat 2>/dev/null)" || sockets='?'

    clear 2>/dev/null || true # cosmetic only
    ui_title "Live view — ${iface} (press q to quit)"
    ui_kv "Traffic" "$(awk -v r=$((rx - rx_prev)) -v t=$((tx - tx_prev)) \
      'BEGIN {printf "down %.2f Mbit/s · up %.2f Mbit/s", r * 8 / 2000000, t * 8 / 2000000}')"
    ui_kv "TCP sockets" "$sockets"
    if [[ $ct =~ ^[0-9]+$ && $max =~ ^[0-9]+$ && $max -gt 0 ]]; then
      ui_kv "Conntrack" "${ct} / ${max} ($((ct * 100 / max))%)"
    else
      ui_kv "Conntrack" "module not loaded"
    fi
    ui_kv "Load" "$(load_avg)"
    ui_kv "RAM available" "$(awk '/^MemAvailable:/ {printf "%d MB", $2 / 1024; exit}' /proc/meminfo)"
    rx_prev="$rx"
    tx_prev="$tx"

    # Non-blocking key check: the sleep above paces the loop.
    if read -rsn1 -t 0.01 key && [[ ${key,,} == q ]]; then
      printf '\n'
      return 0
    fi
  done
}

# tools_report — plain-text support bundle (also behind --report). Printed
# to stdout AND saved, so users can paste it into an issue/ticket directly.
tools_report() {
  local out="${ST_LIB_DIR}/report-${ST_RUN_ID}.txt"
  {
    printf '=== %s support report v%s — %s ===\n\n' "$ST_NAME" "$ST_VERSION" "$(date '+%F %T')"
    printf -- '--- System\n'
    printf 'OS: %s\nKernel: %s\nVirt: %s\nUptime: %s\n' \
      "$(os_pretty_name)" "$(kernel_release)" "$(detect_virt)" "$(uptime_pretty)"
    printf 'CPU: %s (%s cores)\nRAM: %s MB\nLoad: %s\n\n' \
      "$(cpu_model)" "$(cpu_cores)" "$(mem_total_mb)" "$(load_avg)"
    printf -- '--- Workload\n'
    printf 'Detected: %s\n' "$(detect_summary)"
    printf 'Saved profile/tier: %s / %s\n\n' \
      "$(config_get last_profile none)" "$(config_get last_tier -)"
    printf -- '--- DNS\n'
    printf 'Resolver stack: %s\n' "$(dns_stack)"
    printf 'Servers in effect: %s\n' "$(dns_effective_servers)"
    printf 'DNS over TLS: %s\n\n' "$(dns_over_tls_state)"
    printf -- '--- Kernel tuning (live)\n'
    local key
    for key in net.ipv4.tcp_congestion_control net.core.default_qdisc \
      net.ipv4.tcp_mtu_probing net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
      net.core.somaxconn net.core.rmem_max net.netfilter.nf_conntrack_max \
      net.netfilter.nf_conntrack_count fs.file-max vm.swappiness; do
      printf '%s = %s\n' "$key" "$(sysctl_get "$key")"
    done
    printf 'nofile soft/hard: %s / %s\n\n' \
      "$(ulimit -Sn 2>/dev/null || printf '?')" "$(ulimit -Hn 2>/dev/null || printf '?')"
    printf -- '--- Swap\n'
    if [[ -r /proc/swaps ]]; then cat /proc/swaps; else printf 'unavailable\n'; fi
    printf '\n'
    printf -- '--- Manifest (last 15 changes)\n'
    if [[ -f $ST_MANIFEST_FILE ]]; then
      awk 'NR > 1' "$ST_MANIFEST_FILE" | tail -n 15
    else
      printf 'no manifest yet\n'
    fi
    printf '\n'
    printf -- '--- Log (last 30 lines)\n'
    if [[ -f $ST_LOG_FILE ]]; then tail -n 30 "$ST_LOG_FILE"; else printf 'no log yet\n'; fi
    printf '\n=== end of report ===\n'
  } | tee "$out"
  printf '\n%sSaved:%s %s\n' "$C_OK" "$C_RESET" "$out"
  log_info "Support report written to ${out}."
}

tools_menu() {
  local choice
  while true; do
    ui_logo
    ui_title "Network & VPN Tools"
    ui_menu_group "Diagnose"
    ui_menu_item 1 "Ping matrix" "latency to Iran + global"
    ui_menu_item 2 "DNS latency" "ping every DNS provider"
    ui_menu_item 3 "TCP / conntrack" "BBR · forwarding · table usage"
    ui_menu_item 4 "Listening ports" "ss snapshot"
    ui_menu_group "Measure"
    ui_menu_item 9 "Bandwidth test" "speedtest or HTTP download"
    ui_menu_item b "Quick benchmark" "CPU and disk"
    ui_menu_item w "Live view" "traffic · sockets · conntrack"
    ui_menu_group "Network"
    ui_menu_item 5 "MSS clamping" "fix 'connects but no sites'"
    ui_menu_item n "Conntrack NOTRACK" "exempt proxy ports (Xray/Reality)"
    ui_menu_item 6 "Docker + UFW audit" "check the firewall bypass"
    ui_menu_group "System"
    ui_menu_item 8 "XanMod kernel" "BBRv3 — replaces the kernel"
    ui_menu_item m "APT mirror" "switch to an Iranian mirror"
    ui_menu_item 7 "Support report" "full plain-text dump"
    ui_menu_item 0 "Back"
    read -rp "$(_ui_prompt)" choice || return 0
    case "${choice:-}" in
      1)
        tools_ping_matrix
        ui_pause
        ;;
      2)
        dns_latency_test
        ui_pause
        ;;
      3)
        tools_tcp_status
        ui_pause
        ;;
      4)
        tools_listening_ports
        ui_pause
        ;;
      5)
        vpn_mss_clamp
        ui_pause
        ;;
      n | N)
        vpn_conntrack_bypass
        ui_pause
        ;;
      6)
        vpn_docker_ufw_audit
        ui_pause
        ;;
      7)
        tools_report
        ui_pause
        ;;
      8)
        kernel_xanmod_install
        ui_pause
        ;;
      9)
        tools_speedtest || true # outcome already reported
        ui_pause
        ;;
      b | B)
        tools_benchmark
        ui_pause
        ;;
      w | W) tools_watch || true ;;
      m | M)
        mirror_apply || true
        ui_pause
        ;;
      0) return 0 ;;
      *)
        printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET"
        sleep 1
        ;;
    esac
  done
}
