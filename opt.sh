#!/usr/bin/env bash
# ============================================================
# VPN SERVER OPTIMIZER — ENTERPRISE INFRA EDITION (V15.0.0-SAFE)
# Target: Xray / VLESS TCP Reality (stable, low-latency)
# UI: ASCII-only (no unicode/emoji/box-drawing) for clean terminals
#
# What this SAFE build does NOT do (on purpose):
# - DOES NOT touch MTU (no probing, no netplan MTU persist)
# - DOES NOT tune NIC ring buffers (ethtool ring often harms VPS latency)
# - DOES NOT enable tcp_mtu_probing (prevents runaway MTU shrink on lossy paths)
# - DOES NOT route all DNS via Domains=~. (no “global DNS hijack” behavior)
#
# Creator : UnknownZero
# Telegram ID : @UnknownZero
# ============================================================

set -Eeuo pipefail
IFS=$'\n\t'

# =========================
# CONFIG
# =========================
SCRIPT_NAME="vpn_optimizer"
VERSION="V15.0.0-SAFE"

BACKUP_ROOT="/root/vpn_optimizer_backups"
RUN_ID="$(date +%F_%H-%M-%S)"
BACKUP_DIR="${BACKUP_ROOT}/${RUN_ID}"
BACKUP_LATEST_LINK="${BACKUP_ROOT}/latest"

# Apply DNS to all interfaces? 0=default-route iface only (safer)
APPLY_DNS_TO_ALL_INTERFACES=0

# Optional toggles
ENABLE_SWAP=1
ENABLE_UFW_MENU=1
ENABLE_IRQBALANCE=1

# DNS defaults (avoid set -u crash)
DNS1="${DNS1:-1.1.1.1}"
DNS2="${DNS2:-1.0.0.1}"

# Swap sizing (only used if swap is missing)
SWAP_SIZE_GB="${SWAP_SIZE_GB:-2}"

# =========================
# LOG FILE
# =========================
LOG_FILE="/var/log/${SCRIPT_NAME}_safe.log"
if ! ( touch "$LOG_FILE" 2>/dev/null ); then
  LOG_FILE="/tmp/${SCRIPT_NAME}_safe.log"
  touch "$LOG_FILE" 2>/dev/null || true
fi

# =========================
# COLORS (no bright cyan)
# =========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
GRAY='\033[0;90m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# =========================
# ROOT CHECK
# =========================
if [[ ${EUID:-9999} -ne 0 ]]; then
  echo -e "${RED}This script must be run as root.${NC}"
  exit 1
fi

# =========================
# LOG ROTATION (fail-safe)
# =========================
rotate_logs() {
  [[ -f "$LOG_FILE" ]] || return 0
  local size=0
  if command -v stat >/dev/null 2>&1; then
    size="$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)"
  fi
  # rotate if > 2MB
  if [[ "${size:-0}" -gt 2097152 ]]; then
    mv -f "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
    : > "$LOG_FILE" 2>/dev/null || true
  fi
}

log() {
  rotate_logs || true
  local msg="$*"
  local ts
  ts="$(date '+%F %T')"
  if command -v tee >/dev/null 2>&1; then
    echo -e "[$ts] $msg" | tee -a "$LOG_FILE" >/dev/null || true
  else
    echo -e "[$ts] $msg" >> "$LOG_FILE" 2>/dev/null || true
  fi
}

# =========================
# BACKUP HELPERS
# =========================
init_backup_dir() {
  mkdir -p "$BACKUP_DIR" 2>/dev/null || true
  mkdir -p "$BACKUP_ROOT" 2>/dev/null || true
  ln -sfn "$BACKUP_DIR" "$BACKUP_LATEST_LINK" 2>/dev/null || true
}

backup() {
  local src="$1"
  [[ -e "$src" || -L "$src" ]] || return 0
  local b="${BACKUP_DIR}/$(basename "$src").bak"
  # preserve symlink as symlink
  if [[ -L "$src" ]]; then
    local tgt
    tgt="$(readlink "$src" 2>/dev/null || true)"
    [[ -n "${tgt:-}" ]] && ln -sfn "$tgt" "$b" 2>/dev/null || true
  else
    cp -a "$src" "$b" 2>/dev/null || true
  fi
}

restore_from_latest_or_remove() {
  local dest="$1"
  local latest="${BACKUP_LATEST_LINK}/$(basename "$dest").bak"
  if [[ -e "$latest" || -L "$latest" ]]; then
    rm -f "$dest" 2>/dev/null || true
    if [[ -L "$latest" ]]; then
      ln -sfn "$(readlink "$latest")" "$dest" 2>/dev/null || true
    else
      cp -a "$latest" "$dest" 2>/dev/null || true
    fi
    return 0
  fi
  rm -f "$dest" 2>/dev/null || true
  return 0
}

# =========================
# UI HELPERS
# =========================
hr()  { echo -e "${GRAY}------------------------------------------------${NC}"; }
hr2() { echo -e "${GRAY}================================================${NC}"; }

kv() {
  local k="$1" v="$2"
  printf "%b%-12s%b %b%s%b\n" "$DIM" "$k:" "$NC" "$BOLD" "$v" "$NC"
}

title_box() {
  local text="$1"
  hr
  echo -e "${BOLD}${GREEN}${text}${NC}"
  hr
}

pause() {
  if [[ -t 0 ]]; then
    read -rp "$(echo -e "${GRAY}Press Enter...${NC}")"
  else
    sleep 1
  fi
}

repeat_char() {
  local ch="$1" n="$2"
  local out=""
  while (( n > 0 )); do
    out+="$ch"
    n=$((n-1))
  done
  printf "%s" "$out"
}

progress_bar() {
  local pct="$1"
  local title="${2:-}"
  local width=32
  local filled=$(( pct * width / 100 ))
  local empty=$(( width - filled ))
  local bar
  bar="$(repeat_char "#" "$filled")$(repeat_char "." "$empty")"
  printf "\r%b[%s] %3s%%%b %s" "$BLUE" "$bar" "$pct" "$NC" "$title"
}

run_step() {
  local idx="$1" total="$2" title="$3" fn="$4"
  local pct=$(( idx * 100 / total ))
  progress_bar "$pct" "$title"
  echo -ne "\n${DIM}${title}${NC} ... "
  if "$fn"; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}FAIL${NC}"
    return 1
  fi
}

# =========================
# BASIC UTILS
# =========================
is_valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.'
  read -r o1 o2 o3 o4 <<<"$ip"
  for o in "$o1" "$o2" "$o3" "$o4"; do
    (( o >= 0 && o <= 255 )) || return 1
  done
  return 0
}

get_default_iface() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $5; exit}'
}

get_default_gw_ipv4() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $3; exit}'
}

ver_ge() {
  # returns 0 if $1 >= $2 (semver-ish: major.minor.patch)
  local a="$1" b="$2"
  awk -v A="$a" -v B="$b" '
    function splitv(v, arr,   n,i){ n=split(v,arr,"."); for(i=n+1;i<=3;i++) arr[i]=0 }
    BEGIN{
      splitv(A,a); splitv(B,b);
      for(i=1;i<=3;i++){
        if(a[i]+0>b[i]+0){exit 0}
        if(a[i]+0<b[i]+0){exit 1}
      }
      exit 0
    }'
}

install_pkg() {
  local pkg="$1"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y "$pkg" >/dev/null 2>&1 || return 1
    return 0
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$pkg" >/dev/null 2>&1 || return 1
    return 0
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$pkg" >/dev/null 2>&1 || return 1
    return 0
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1 || return 1
    return 0
  fi
  return 1
}

detect_dns_stack() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "resolved"
  else
    echo "plain"
  fi
}

# =========================
# SYSTEM INFO (computed once)
# =========================
RAM_MB="$(free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo 0)"
OS_NAME="$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Unknown")"
KERNEL_FULL="$(uname -r 2>/dev/null || echo "Unknown")"
KERNEL_BASE="${KERNEL_FULL%%-*}"
PHY_INTERFACES="$(ls /sys/class/net 2>/dev/null | grep -Ev 'lo|docker|veth|tun|wg|br-|cali' || true)"
DEFAULT_IFACE="$(get_default_iface || true)"
DEFAULT_GW="$(get_default_gw_ipv4 || true)"

if [[ "${APPLY_DNS_TO_ALL_INTERFACES}" -eq 1 ]]; then
  TARGET_INTERFACES="$PHY_INTERFACES"
else
  if [[ -n "${DEFAULT_IFACE:-}" ]]; then
    TARGET_INTERFACES="$DEFAULT_IFACE"
  else
    TARGET_INTERFACES="$PHY_INTERFACES"
  fi
fi

# =========================
# BANNER / SUMMARY
# =========================
print_banner() {
  echo -e "${MAGENTA}${BOLD}"
  cat <<'EOF'
 _    _  ____  _   _
| |  | |/ __ \| \ | |
| |  | | |  | |  \| |
| |  | | |  | | . ` |
| |__| | |__| | |\  |
 \____/ \____/|_| \_|
EOF
  echo -e "${NC}"
}

summary_line() {
  local cc qdisc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")"
  echo -e "${GRAY}cc=${cc}  qdisc=${qdisc}  DNS=${DNS1}/${DNS2}  IF=${DEFAULT_IFACE:-?}${NC}"
}

# =========================
# 1) BBR/QDISC
# =========================
BBR_ALGO="cubic"
QDISC="fq_codel"

check_kernel_bbr() {
  log "Checking Kernel & BBR support (kernel=${KERNEL_BASE})"
  local kernel_ok=1

  if command -v dpkg >/dev/null 2>&1; then
    dpkg --compare-versions "$KERNEL_BASE" ge "4.9" && kernel_ok=0 || kernel_ok=1
  else
    ver_ge "$KERNEL_BASE" "4.9" && kernel_ok=0 || kernel_ok=1
  fi

  if (( kernel_ok != 0 )); then
    log "Kernel < 4.9 — BBR not supported, using cubic."
    BBR_ALGO="cubic"
    QDISC="fq_codel"
    return 0
  fi

  modprobe tcp_bbr &>/dev/null || true
  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    BBR_ALGO="bbr"
    QDISC="fq"
    log "BBR is available and will be enabled."
  else
    BBR_ALGO="cubic"
    QDISC="fq_codel"
    log "BBR not available — using cubic."
  fi

  if [[ "$BBR_ALGO" == "bbr" ]]; then
    mkdir -p /etc/modules-load.d
    backup /etc/modules-load.d/bbr.conf
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
  fi
  return 0
}

# =========================
# 2) DNS (SAFE)
# =========================
select_dns() {
  clear
  title_box "DNS Provider Selection"
  echo -e "${BOLD}1)${NC} Cloudflare  (1.1.1.1 / 1.0.0.1)"
  echo -e "${BOLD}2)${NC} Google      (8.8.8.8 / 8.8.4.4)"
  echo -e "${BOLD}3)${NC} Quad9       (9.9.9.9 / 149.112.112.112)"
  echo -e "${BOLD}4)${NC} OpenDNS     (208.67.222.222 / 208.67.220.220)"
  echo -e "${BOLD}5)${NC} Shecan      (178.22.122.100 / 185.51.200.2)"
  echo -e "${BOLD}6)${NC} Custom"
  echo -e "${BOLD}0)${NC} Keep current"
  hr2
  read -rp "Choice: " d

  case "${d:-}" in
    1) DNS1=1.1.1.1; DNS2=1.0.0.1 ;;
    2) DNS1=8.8.8.8; DNS2=8.8.4.4 ;;
    3) DNS1=9.9.9.9; DNS2=149.112.112.112 ;;
    4) DNS1=208.67.222.222; DNS2=208.67.220.220 ;;
    5) DNS1=178.22.122.100; DNS2=185.51.200.2 ;;
    6)
      read -rp "DNS1: " DNS1
      read -rp "DNS2: " DNS2
      ;;
    0) return 0 ;;
    *) DNS1=1.1.1.1; DNS2=1.0.0.1 ;;
  esac

  if ! is_valid_ipv4 "$DNS1" || ! is_valid_ipv4 "$DNS2"; then
    log "Invalid DNS entered. Falling back to Cloudflare."
    DNS1=1.1.1.1; DNS2=1.0.0.1
  fi
  return 0
}

apply_dns() {
  log "Applying DNS safely (no Domains=~., no interface routing hacks)."
  local stack
  stack="$(detect_dns_stack)"

  if [[ "$stack" == "resolved" ]]; then
    mkdir -p /etc/systemd/resolved.conf.d
    local dropin="/etc/systemd/resolved.conf.d/99-${SCRIPT_NAME}.conf"
    backup "$dropin"

    cat > "$dropin" <<EOF
# Generated by ${SCRIPT_NAME} ${VERSION}
[Resolve]
DNS=${DNS1} ${DNS2}
FallbackDNS=${DNS2}
EOF

    systemctl restart systemd-resolved >/dev/null 2>&1 || true
  else
    # plain resolv.conf mode
    backup /etc/resolv.conf
    # If it's a symlink, replace with a regular file to make it persistent
    if [[ -L /etc/resolv.conf ]]; then
      rm -f /etc/resolv.conf 2>/dev/null || true
    fi
    cat > /etc/resolv.conf <<EOF
# Generated by ${SCRIPT_NAME} ${VERSION}
nameserver ${DNS1}
nameserver ${DNS2}
EOF
  fi
  return 0
}

# =========================
# 3) SYSCTL (SAFE)
# =========================
calc_buf_max() {
  # outputs RMAX WMAX (bytes), conservative to avoid bufferbloat
  local rmax wmax
  if (( RAM_MB <= 1024 )); then
    rmax=$(( 8 * 1024 * 1024 ))
    wmax=$(( 8 * 1024 * 1024 ))
  elif (( RAM_MB <= 4096 )); then
    rmax=$(( 16 * 1024 * 1024 ))
    wmax=$(( 16 * 1024 * 1024 ))
  elif (( RAM_MB <= 8192 )); then
    rmax=$(( 32 * 1024 * 1024 ))
    wmax=$(( 32 * 1024 * 1024 ))
  else
    rmax=$(( 64 * 1024 * 1024 ))
    wmax=$(( 64 * 1024 * 1024 ))
  fi
  echo "$rmax $wmax"
}

apply_sysctl() {
  backup /etc/sysctl.d/99-vpn-opt.conf

  local CONNTRACK
  if (( RAM_MB <= 1024 )); then CONNTRACK=65536
  elif (( RAM_MB <= 4096 )); then CONNTRACK=262144
  else CONNTRACK=$((RAM_MB * 64)); fi
  (( CONNTRACK > 2000000 )) && CONNTRACK=2000000

  local RMAX WMAX
  read -r RMAX WMAX <<<"$(calc_buf_max)"

  # Backlog values: high enough for VPN, not insane
  local SOMAX=8192
  local SYNBK=8192
  local NETDEV=16384
  if (( RAM_MB >= 4096 )); then
    SOMAX=16384
    SYNBK=16384
    NETDEV=32768
  fi

  cat > /etc/sysctl.d/99-vpn-opt.conf <<EOF
# Generated by ${SCRIPT_NAME} ${VERSION}
# Focus: stable low-latency for VLESS TCP Reality

# Congestion control
net.core.default_qdisc=${QDISC}
net.ipv4.tcp_congestion_control=${BBR_ALGO}

# Backlogs (moderate)
net.core.somaxconn=${SOMAX}
net.ipv4.tcp_max_syn_backlog=${SYNBK}
net.core.netdev_max_backlog=${NETDEV}
net.ipv4.tcp_syncookies=1

# Ports
net.ipv4.ip_local_port_range=10240 65535

# TCP behavior (sane defaults)
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=60
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_tw_reuse=1

# IMPORTANT: disable MTU probing (prevents runaway MTU shrink on lossy/filtered paths)
net.ipv4.tcp_mtu_probing=0

# Socket buffers (conservative to avoid bufferbloat)
net.core.rmem_max=${RMAX}
net.core.wmem_max=${WMAX}
net.core.rmem_default=262144
net.core.wmem_default=262144
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.ipv4.tcp_rmem=4096 87380 ${RMAX}
net.ipv4.tcp_wmem=4096 65536 ${WMAX}

# Forwarding (VPN servers need this)
net.ipv4.ip_forward=1

# Conntrack sizing (helps NAT-heavy setups)
net.netfilter.nf_conntrack_max=${CONNTRACK}

# VM / files
vm.swappiness=10
fs.file-max=2097152
EOF

  sysctl --system >/dev/null 2>&1 || true
  return 0
}

# =========================
# 4) LIMITS
# =========================
apply_limits() {
  backup /etc/security/limits.d/99-vpn.conf
  backup /etc/systemd/system.conf

  mkdir -p /etc/security/limits.d
  cat > /etc/security/limits.d/99-vpn.conf <<'EOF'
# Generated by vpn_optimizer SAFE
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  if [[ -f /etc/systemd/system.conf ]]; then
    if grep -q '^DefaultLimitNOFILE=' /etc/systemd/system.conf; then
      sed -i 's/^DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/' /etc/systemd/system.conf
    else
      echo "DefaultLimitNOFILE=1048576" >> /etc/systemd/system.conf
    fi
  else
    echo "DefaultLimitNOFILE=1048576" > /etc/systemd/system.conf
  fi

  systemctl daemon-reexec >/dev/null 2>&1 || true
  return 0
}

# =========================
# 5) IRQBALANCE (optional)
# =========================
setup_irqbalance() {
  [[ "$ENABLE_IRQBALANCE" -eq 1 ]] || return 0
  install_pkg irqbalance || true

  if command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now irqbalance >/dev/null 2>&1 || true
  fi
  return 0
}

# =========================
# 6) SWAP (optional)
# =========================
setup_swap() {
  [[ "$ENABLE_SWAP" -eq 1 ]] || return 0

  if swapon --show | grep -q .; then
    log "Swap already enabled."
    return 0
  fi

  local swapfile="/swapfile"
  local size_gb="${SWAP_SIZE_GB:-2}"
  local size_mb=$(( size_gb * 1024 ))

  backup /etc/fstab

  if [[ ! -e "$swapfile" ]]; then
    if command -v fallocate >/dev/null 2>&1; then
      fallocate -l "${size_gb}G" "$swapfile" 2>/dev/null || dd if=/dev/zero of="$swapfile" bs=1M count="$size_mb" status=none
    else
      dd if=/dev/zero of="$swapfile" bs=1M count="$size_mb" status=none
    fi
    chmod 600 "$swapfile" 2>/dev/null || true
    mkswap "$swapfile" >/dev/null 2>&1 || true
  fi

  swapon "$swapfile" >/dev/null 2>&1 || true
  grep -q '^\s*/swapfile\s' /etc/fstab 2>/dev/null || echo "/swapfile none swap sw 0 0" >> /etc/fstab
  return 0
}

# =========================
# 7) LEGACY CLEANUP (risk-reducer)
# =========================
cleanup_legacy() {
  title_box "Cleanup Legacy Risky Tweaks"

  local iface
  iface="$(get_default_iface || true)"
  if [[ -n "${iface:-}" ]]; then
    local cur
    cur="$(ip link show dev "$iface" 2>/dev/null | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}' || true)"
    if [[ -n "${cur:-}" && "${cur:-}" != "1500" ]]; then
      echo -e "${YELLOW}Resetting MTU on ${iface} to 1500 (runtime only).${NC}"
      ip link set dev "$iface" mtu 1500 2>/dev/null || true
      log "Legacy cleanup: set MTU=1500 on ${iface} (was ${cur})."
    fi
  fi

  # Remove legacy netplan override (DNS/MTU scripts often leave this behind)
  if [[ -f /etc/netplan/99-vpn-override.yaml ]]; then
    echo -e "${YELLOW}Removing /etc/netplan/99-vpn-override.yaml${NC}"
    rm -f /etc/netplan/99-vpn-override.yaml 2>/dev/null || true
    if command -v netplan >/dev/null 2>&1; then
      netplan generate >/dev/null 2>&1 || true
      netplan apply >/dev/null 2>&1 || true
    fi
    log "Legacy cleanup: removed netplan override."
  fi

  # Remove older resolved drop-ins that forced Domains=~. and other hacks
  local d1="/etc/systemd/resolved.conf.d/99-vpn_optimizer.conf"
  local d2="/etc/systemd/resolved.conf.d/99-${SCRIPT_NAME}.conf"
  for d in "$d1" "$d2"; do
    if [[ -f "$d" ]]; then
      echo -e "${YELLOW}Removing ${d}${NC}"
      rm -f "$d" 2>/dev/null || true
      log "Legacy cleanup: removed ${d}"
    fi
  done

  if command -v resolvectl >/dev/null 2>&1; then
    for i in $TARGET_INTERFACES; do
      resolvectl revert "$i" 2>/dev/null || true
    done
  fi

  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
  fi

  echo -e "${GREEN}OK: Legacy cleanup done (best effort).${NC}"
  hr
  pause
  return 0
}

# =========================
# 8) ROLLBACK
# =========================
restore_defaults() {
  read -rp "Rollback will revert files touched by this script (latest run). Continue? [y/N]: " c
  [[ "${c:-}" != "y" ]] && return 0

  restore_from_latest_or_remove /etc/sysctl.d/99-vpn-opt.conf
  restore_from_latest_or_remove /etc/security/limits.d/99-vpn.conf
  restore_from_latest_or_remove /etc/systemd/system.conf
  restore_from_latest_or_remove "/etc/systemd/resolved.conf.d/99-${SCRIPT_NAME}.conf"

  swapoff /swapfile 2>/dev/null || true
  rm -f /swapfile 2>/dev/null || true
  sed -i '\|^\s*/swapfile\s|d' /etc/fstab 2>/dev/null || true

  sysctl --system >/dev/null 2>&1 || true
  systemctl restart systemd-resolved >/dev/null 2>&1 || true

  echo -e "${GREEN}OK: Rollback complete.${NC}"
  pause
  return 0
}

# =========================
# 9) STATUS
# =========================
show_status() {
  clear
  title_box "System Status (Detailed)"

  kv "OS" "$OS_NAME"
  kv "Kernel" "$KERNEL_FULL"
  kv "RAM" "${RAM_MB} MB"
  kv "Default IF" "${DEFAULT_IFACE:-unknown}"
  kv "Gateway" "${DEFAULT_GW:-unknown}"
  kv "DNS" "${DNS1} / ${DNS2}"
  hr2

  echo -e "${BOLD}${BLUE}Networking:${NC}"
  echo "ip -br link:"
  ip -br link 2>/dev/null || true
  echo
  echo "ip route:"
  ip route 2>/dev/null || true
  echo
  echo "sysctl highlights:"
  sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc net.ipv4.tcp_mtu_probing net.core.rmem_max net.core.wmem_max 2>/dev/null || true
  hr2

  echo -e "${BOLD}${BLUE}DNS stack:${NC}"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "systemd-resolved: active"
    resolvectl status 2>/dev/null | sed -n '1,140p' || true
  else
    echo "systemd-resolved: not active"
    echo "/etc/resolv.conf:"
    ls -l /etc/resolv.conf 2>/dev/null || true
    sed -n '1,80p' /etc/resolv.conf 2>/dev/null || true
  fi

  hr
  pause
  return 0
}

# =========================
# 10) OPTIMIZE SERVER (SAFE APPLY)
# =========================
optimize_server() {
  clear
  title_box "Run Optimization (SAFE)"

  init_backup_dir
  echo -e "${GRAY}Backups: ${NC}${BOLD}$BACKUP_DIR${NC}"
  echo -e "${GRAY}Log    : ${NC}${BOLD}$LOG_FILE${NC}"
  hr2

  select_dns

  clear
  title_box "Applying Changes"

  # Build step list dynamically (so the bar is accurate)
  local steps=()
  steps+=(check_kernel_bbr)
  steps+=(apply_dns)
  steps+=(apply_sysctl)
  steps+=(apply_limits)
  if [[ "$ENABLE_IRQBALANCE" -eq 1 ]]; then steps+=(setup_irqbalance); fi
  if [[ "$ENABLE_SWAP" -eq 1 ]]; then steps+=(setup_swap); fi

  local total="${#steps[@]}"
  local step=0

  for fn in "${steps[@]}"; do
    step=$((step+1))
    case "$fn" in
      check_kernel_bbr) run_step "$step" "$total" "Kernel/BBR check" "$fn" ;;
      apply_dns)        run_step "$step" "$total" "Apply DNS (safe)" "$fn" ;;
      apply_sysctl)     run_step "$step" "$total" "Apply sysctl network tuning (safe)" "$fn" ;;
      apply_limits)     run_step "$step" "$total" "Apply system limits (nofile)" "$fn" ;;
      setup_irqbalance) run_step "$step" "$total" "Enable irqbalance (optional)" "$fn" ;;
      setup_swap)       run_step "$step" "$total" "Setup swap (optional)" "$fn" ;;
      *)                run_step "$step" "$total" "$fn" "$fn" ;;
    esac
  done

  progress_bar 100 "Done"
  echo
  hr
  echo -e "${GREEN}DONE: Optimization completed successfully.${NC}"
  echo -e "${GRAY}Backups: ${NC}${BOLD}$BACKUP_DIR${NC}${GRAY} (latest -> ${BOLD}$BACKUP_LATEST_LINK${NC}${GRAY})${NC}"
  echo -e "${GRAY}Log: ${NC}${BOLD}$LOG_FILE${NC}"
  hr
  pause
  return 0
}

# =========================
# 11) UFW FIREWALL
# =========================
setup_ufw() {
  install_pkg ufw || true

  local SSH_PORT
  SSH_PORT="$(ss -tnlp 2>/dev/null | awk '/sshd/{print $4}' | awk -F: '{print $NF}' | head -n1 || true)"
  [[ -z "${SSH_PORT:-}" ]] && SSH_PORT=22

  ufw allow "${SSH_PORT}/tcp" >/dev/null 2>&1 || true
  ufw default deny incoming >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true

  read -rp "Extra allowed ports (e.g. 80/tcp 443/tcp 4443/tcp) [empty=none]: " ports
  if [[ -n "${ports:-}" ]]; then
    for p in $ports; do ufw allow "$p" >/dev/null 2>&1 || true; done
  fi

  ufw --force enable >/dev/null 2>&1 || true
  ufw status verbose || true
  return 0
}

# =========================
# MAIN LOOP (MENU)
# =========================
while true; do
  clear
  print_banner

  echo -e "${BOLD}${GREEN}VPN SERVER OPTIMIZER - ${VERSION}${NC}  ${GRAY}(VLESS TCP Reality SAFE)${NC}"
  hr2
  kv "OS" "$OS_NAME"
  kv "Kernel" "$KERNEL_BASE"
  kv "RAM" "${RAM_MB} MB"
  kv "Interfaces" "$(echo "${PHY_INTERFACES:-}" | tr '\n' ' ' | xargs)"
  hr2
  summary_line
  hr

  echo -e "${BOLD}[1]${NC} Optimize Server (Safe Apply)"
  echo -e "${BOLD}[2]${NC} System Status (Detailed)"
  echo -e "${BOLD}[3]${NC} Rollback (latest backup)"
  echo -e "${BOLD}[4]${NC} Enable irqbalance"
  echo -e "${BOLD}[5]${NC} DNS Provider (Safe Apply)"
  echo -e "${BOLD}[6]${NC} Cleanup legacy risky tweaks (MTU/netplan/resolved)"
  if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
    echo -e "${BOLD}[7]${NC} Setup Firewall (UFW)"
    echo -e "${BOLD}[8]${NC} Reboot Server"
    echo -e "${BOLD}[0]${NC} Exit"
  else
    echo -e "${BOLD}[7]${NC} Reboot Server"
    echo -e "${BOLD}[0]${NC} Exit"
  fi

  hr
  echo -e "${GRAY}Creator: UnknownZero  Telegram ID: @UnknownZero${NC}"
  hr2

  read -rp "Select: " opt

  case "${opt:-}" in
    1) optimize_server ;;
    2) show_status ;;
    3) restore_defaults ;;
    4)
      title_box "Enable irqbalance"
      setup_irqbalance
      if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet irqbalance 2>/dev/null; then
        echo -e "${GREEN}OK: irqbalance is active.${NC}"
      else
        echo -e "${YELLOW}WARN: irqbalance is not active (some VMs have limited IRQ behavior).${NC}"
      fi
      hr
      pause
      ;;
    5)
      select_dns
      title_box "Apply DNS (SAFE)"
      init_backup_dir
      run_step 1 1 "Apply DNS (safe)" apply_dns || true
      hr
      pause
      ;;
    6) cleanup_legacy ;;
    7)
      if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
        title_box "UFW Firewall"
        setup_ufw
        pause
      else
        reboot
      fi
      ;;
    8)
      if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
        reboot
      else
        echo -e "${RED}Invalid option.${NC}"
        sleep 1
      fi
      ;;
    0) exit ;;
    *) echo -e "${RED}Invalid option.${NC}"; sleep 1 ;;
  esac
done
