# shellcheck shell=bash
# ============================================================================
# modules/sysinfo.sh — the System Status report (menu option and --status).
# Reads /proc directly where possible so it works even in minimal containers.
# ============================================================================

_meminfo_kb() { # _meminfo_kb FIELD — e.g. MemTotal
  awk -v field="$1:" '$1 == field {print $2; exit}' /proc/meminfo 2>/dev/null || printf '0'
}

_disk_root_summary() {
  if has_cmd df; then
    df -h / 2>/dev/null | awk 'NR == 2 {printf "%s used / %s (%s)", $3, $2, $5}'
  else
    printf 'unknown'
  fi
}

show_status() {
  ui_logo
  ui_title "System Status"

  ui_section "System"
  ui_kv "OS" "$(os_pretty_name)"
  ui_kv "Kernel" "$(kernel_release)"
  ui_kv "Virtualization" "$(detect_virt)"
  ui_kv "Uptime" "$(uptime_pretty)"
  ui_hr

  ui_section "CPU"
  ui_kv "Model" "$(cpu_model)"
  ui_kv "Cores" "$(cpu_cores)"
  ui_kv "Load (1/5/15m)" "$(load_avg)"
  ui_hr

  ui_section "Memory"
  local mem_total_kb mem_avail_kb swap_total_kb swap_free_kb
  mem_total_kb="$(_meminfo_kb MemTotal)"
  mem_avail_kb="$(_meminfo_kb MemAvailable)"
  swap_total_kb="$(_meminfo_kb SwapTotal)"
  swap_free_kb="$(_meminfo_kb SwapFree)"
  ui_kv "RAM" "$((mem_total_kb / 1024)) MB total, $((mem_avail_kb / 1024)) MB available"
  if ((swap_total_kb > 0)); then
    ui_kv "Swap" "$(((swap_total_kb - swap_free_kb) / 1024)) MB used / $((swap_total_kb / 1024)) MB"
  else
    ui_kv "Swap" "disabled"
  fi
  ui_kv "Disk (/)" "$(_disk_root_summary)"
  ui_hr

  ui_section "Network"
  ui_kv "Default IF" "$(net_default_iface || true)"
  ui_kv "Gateway" "$(net_default_gw || true)"
  ui_kv "Public IPv4" "$(net_public_ip4)"
  ui_kv "Public IPv6" "$(net_public_ip6)"
  ui_hr

  ui_section "TCP / Tuning"
  local cc
  cc="$(sysctl_get net.ipv4.tcp_congestion_control)"
  if [[ $cc == bbr* ]]; then
    ui_kv "Congestion" "${cc} (BBR enabled)"
  else
    ui_kv "Congestion" "${cc}"
  fi
  ui_kv "Qdisc" "$(sysctl_get net.core.default_qdisc)"
  ui_kv "MTU probing" "$(sysctl_get net.ipv4.tcp_mtu_probing)"
  ui_kv "IPv4 forward" "$(sysctl_get net.ipv4.ip_forward)"
  ui_kv "IPv6 forward" "$(sysctl_get net.ipv6.conf.all.forwarding)"
  ui_hr

  ui_section "ServerTools"
  ui_kv "Detected" "$(detect_summary)"
  ui_kv "Recorded changes" "$(manifest_entry_count)"
  ui_kv "Log file" "$ST_LOG_FILE"
  ui_hr_heavy

  ui_pause
}
