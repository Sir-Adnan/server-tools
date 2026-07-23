# shellcheck shell=bash
# ============================================================================
# modules/sysinfo.sh — the System Status report (menu option and --status).
#
# Everything is read live from /proc, /sys and the tools that are present;
# nothing is cached from a previous run, so the report always reflects the
# machine as it is right now. Missing tools degrade to "n/a", never an error.
# ============================================================================

_meminfo_kb() { # _meminfo_kb FIELD — e.g. MemTotal
  awk -v field="$1:" '$1 == field {print $2; exit}' /proc/meminfo 2>/dev/null || printf '0'
}

# _hr_mb MB — human readable size, one decimal from a gigabyte upwards.
_hr_mb() {
  local mb="${1:-0}"
  if ((mb >= 1024)); then
    awk -v m="$mb" 'BEGIN {printf "%.1f GB", m / 1024}'
  else
    printf '%s MB' "$mb"
  fi
}

# _pct USED TOTAL — integer percentage, "0" when total is zero.
_pct() {
  if (($2 > 0)); then
    printf '%d' $(($1 * 100 / $2))
  else
    printf '0'
  fi
}

_status_system() {
  ui_section "System"
  ui_kv "Hostname" "$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || printf 'unknown')"
  ui_kv "OS" "$(os_pretty_name)"
  ui_kv "Kernel" "$(kernel_release) ($(uname -m 2>/dev/null || printf 'unknown'))"
  ui_kv "Virtualization" "$(detect_virt)"
  ui_kv "Uptime" "$(uptime_pretty)"

  local tz='n/a' ntp=''
  if has_cmd timedatectl; then
    tz="$(timedatectl show -p Timezone --value 2>/dev/null)" || tz='n/a'
    ntp="$(timedatectl show -p NTPSynchronized --value 2>/dev/null)" || ntp=''
  fi
  case "$ntp" in
    yes) ui_kv "Time" "${tz} (NTP synchronized)" ;;
    no) ui_kv "Time" "${tz} (NTP NOT synchronized)" ;;
    *) ui_kv "Time" "$tz" ;;
  esac
}

_status_cpu() {
  ui_section "CPU"
  ui_kv "Model" "$(cpu_model)"
  ui_kv "Cores" "$(cpu_cores)"
  ui_kv "Load (1/5/15m)" "$(load_avg)"
}

# _swap_backend — how swap is provided: zram, file, partition, or none.
_swap_backend() {
  [[ -r /proc/swaps ]] || {
    printf 'unknown'
    return 0
  }
  awk 'NR > 1 {
    if ($1 ~ /zram/) kind = "zram (compressed RAM)"
    else if ($2 == "file") kind = "file " $1
    else kind = $2 " " $1
    print kind
    exit
  }' /proc/swaps
}

_status_memory() {
  ui_section "Memory & Storage"
  local total_kb avail_kb swap_total_kb swap_free_kb used_mb
  total_kb="$(_meminfo_kb MemTotal)"
  avail_kb="$(_meminfo_kb MemAvailable)"
  swap_total_kb="$(_meminfo_kb SwapTotal)"
  swap_free_kb="$(_meminfo_kb SwapFree)"
  used_mb=$(((total_kb - avail_kb) / 1024))

  ui_kv "RAM" "$(_hr_mb $((total_kb / 1024))) total · $(_hr_mb "$used_mb") used · $(_hr_mb $((avail_kb / 1024))) available"
  if ((swap_total_kb > 0)); then
    ui_kv "Swap" "$(_hr_mb $(((swap_total_kb - swap_free_kb) / 1024))) used / $(_hr_mb $((swap_total_kb / 1024))) · $(_swap_backend)"
  else
    ui_kv "Swap" "disabled"
  fi
  if has_cmd df; then
    ui_kv "Disk (/)" "$(df -h / 2>/dev/null | awk 'NR == 2 {printf "%s used / %s (%s full)", $3, $2, $5}')"
  fi
}

_status_network() {
  ui_section "Network"
  local iface mtu qdisc
  iface="$(net_default_iface)" || iface=''
  ui_kv "Default IF" "${iface:-unknown}"
  if [[ -n $iface ]]; then
    mtu="$(cat "/sys/class/net/${iface}/mtu" 2>/dev/null)" || mtu='?'
    qdisc="$(tc qdisc show dev "$iface" 2>/dev/null | awk 'NR == 1 {print $2}')" || qdisc=''
    ui_kv "MTU / qdisc" "${mtu} / ${qdisc:-unknown}"
  fi
  ui_kv "Gateway" "$(net_default_gw || printf 'unknown')"
  ui_kv "Public IPv4" "$(net_public_ip4)"
  ui_kv "Public IPv6" "$(net_public_ip6)"

  # Socket counts come from /proc — far cheaper than parsing `ss` output.
  if [[ -r /proc/net/sockstat ]]; then
    ui_kv "TCP sockets" "$(awk '/^TCP:/ {printf "%s in use · %s time-wait · %s orphan", $3, $7, $5}' /proc/net/sockstat)"
  fi
}

_status_dns() {
  ui_section "DNS"
  local stack
  stack="$(dns_stack)"
  case "$stack" in
    resolved) ui_kv "Resolver" "systemd-resolved" ;;
    resolvconf) ui_kv "Resolver" "resolvconf" ;;
    *) ui_kv "Resolver" "plain /etc/resolv.conf" ;;
  esac
  ui_kv "Servers in effect" "$(dns_effective_servers)"
  [[ $stack == resolved ]] && ui_kv "DNS over TLS" "$(dns_over_tls_state)"
  if [[ -L /etc/resolv.conf ]]; then
    ui_kv "resolv.conf" "symlink -> $(readlink /etc/resolv.conf 2>/dev/null)"
  else
    ui_kv "resolv.conf" "regular file"
  fi
}

_status_tuning() {
  ui_section "Kernel tuning"
  local cc
  cc="$(sysctl_get net.ipv4.tcp_congestion_control)"
  if [[ $cc == bbr* ]]; then
    ui_kv "Congestion" "${cc} (BBR active)"
  else
    ui_kv "Congestion" "${cc}"
  fi
  ui_kv "Default qdisc" "$(sysctl_get net.core.default_qdisc)"
  ui_kv "MTU probing" "$(sysctl_get net.ipv4.tcp_mtu_probing)"
  ui_kv "Forwarding" "IPv4=$(sysctl_get net.ipv4.ip_forward) · IPv6=$(sysctl_get net.ipv6.conf.all.forwarding)"
  ui_kv "Accept queues" "somaxconn=$(sysctl_get net.core.somaxconn) · backlog=$(sysctl_get net.core.netdev_max_backlog)"
  ui_kv "Socket buffers" "rmem_max=$(sysctl_get net.core.rmem_max) · wmem_max=$(sysctl_get net.core.wmem_max)"

  local ct_count ct_max
  ct_count="$(sysctl_get net.netfilter.nf_conntrack_count)"
  ct_max="$(sysctl_get net.netfilter.nf_conntrack_max)"
  if [[ $ct_count =~ ^[0-9]+$ && $ct_max =~ ^[0-9]+$ ]]; then
    ui_kv "Conntrack" "${ct_count} / ${ct_max} ($(_pct "$ct_count" "$ct_max")% used)"
  else
    ui_kv "Conntrack" "module not loaded"
  fi
}

_status_limits() {
  ui_section "Limits"
  ui_kv "nofile (this shell)" "soft=$(ulimit -Sn 2>/dev/null || printf '?') · hard=$(ulimit -Hn 2>/dev/null || printf '?')"
  if has_cmd systemctl; then
    ui_kv "systemd default" "$(systemctl show -p DefaultLimitNOFILE --value 2>/dev/null || printf 'n/a')"
  fi
  ui_kv "fs.file-max" "$(sysctl_get fs.file-max)"
  [[ -r /proc/sys/fs/file-nr ]] &&
    ui_kv "Open files" "$(awk '{print $1}' /proc/sys/fs/file-nr)"
  if has_cmd docker; then
    if grep -q 'default-ulimits' /etc/docker/daemon.json 2>/dev/null; then
      ui_kv "Docker ulimits" "configured in daemon.json"
    else
      ui_kv "Docker ulimits" "engine default (containers ignore limits.d)"
    fi
  fi
}

_status_security() {
  ui_section "Security"
  if has_cmd ufw; then
    ui_kv "Firewall (UFW)" "$(ufw status 2>/dev/null | awk 'NR == 1 {print $2; exit}' || printf 'unknown')"
  else
    ui_kv "Firewall (UFW)" "not installed"
  fi
  if has_cmd systemctl; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
      ui_kv "fail2ban" "active"
    else
      ui_kv "fail2ban" "inactive"
    fi
    if systemctl is-enabled --quiet server-tools-mss.service 2>/dev/null; then
      ui_kv "MSS clamping" "enabled at boot"
    fi
  fi
  if has_cmd sshd; then
    local sshd_cfg port pw
    sshd_cfg="$(sshd -T 2>/dev/null)" || sshd_cfg=''
    if [[ -n $sshd_cfg ]]; then
      port="$(awk '/^port / {print $2; exit}' <<<"$sshd_cfg")"
      pw="$(awk '/^passwordauthentication / {print $2; exit}' <<<"$sshd_cfg")"
      ui_kv "SSH" "port ${port:-?} · password auth ${pw:-?}"
    fi
  fi
}

_status_servertools() {
  ui_section "Workload & ServerTools"
  ui_kv "Detected" "$(detect_summary)"
  ui_kv "Version" "$ST_VERSION"
  local users
  users="$(config_get expected_users 0)"
  if [[ $users =~ ^[1-9][0-9]*$ ]]; then
    ui_kv "Applied profile" "$(config_get last_profile 'not applied yet') · tier $(config_get last_tier '-') · ${users} users"
  else
    ui_kv "Applied profile" "$(config_get last_profile 'not applied yet') · tier $(config_get last_tier '-')"
  fi
  ui_kv "Recorded changes" "$(manifest_entry_count) (last run: $(manifest_latest_run || printf 'none'))"
  ui_kv "Log file" "$ST_LOG_FILE"
  ui_kv "Backups" "$ST_BACKUP_DIR"
}

show_status() {
  ui_logo
  ui_title "System Status"

  _status_system
  ui_hr
  _status_cpu
  ui_hr
  _status_memory
  ui_hr
  _status_network
  ui_hr
  _status_dns
  ui_hr
  _status_tuning
  ui_hr
  _status_limits
  ui_hr
  _status_security
  ui_hr
  _status_servertools
  ui_hr_heavy
  printf '%sTip: "st --dry-run" shows which kernel keys still differ from the\n' "$C_MUTED"
  printf 'recommended profile; "st --report" writes all of this to a file.%s\n' "$C_RESET"

  ui_pause
}
