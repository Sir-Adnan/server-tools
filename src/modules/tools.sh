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
    printf -- '--- Kernel tuning (live)\n'
    local key
    for key in net.ipv4.tcp_congestion_control net.core.default_qdisc \
      net.ipv4.tcp_mtu_probing net.ipv4.ip_forward net.ipv6.conf.all.forwarding \
      net.core.somaxconn net.core.rmem_max net.netfilter.nf_conntrack_max \
      net.netfilter.nf_conntrack_count fs.file-max vm.swappiness; do
      printf '%s = %s\n' "$key" "$(sysctl_get "$key")"
    done
    printf '\n'
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
    ui_menu_item 1 "Ping matrix" "latency/loss to Iran + global targets"
    ui_menu_item 2 "DNS latency test" "ping every DNS provider"
    ui_menu_item 3 "TCP/conntrack status" "BBR, forwarding, table usage"
    ui_menu_item 4 "Listening ports" "ss -tulnp snapshot"
    ui_menu_item 5 "MSS clamping" "fix 'VPN connects but no sites' (WireGuard/NAT)"
    ui_menu_item 6 "Docker+UFW audit" "check the firewall bypass"
    ui_menu_item 7 "Support report" "full plain-text dump for issues/tickets"
    ui_menu_item 8 "XanMod kernel (BBRv3)" "ADVANCED — replaces the kernel"
    ui_menu_item 0 "Back"
    ui_hr
    read -rp "Select: " choice || return 0
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
      0) return 0 ;;
      *)
        printf '%sInvalid choice.%s\n' "$C_ERR" "$C_RESET"
        sleep 1
        ;;
    esac
  done
}
