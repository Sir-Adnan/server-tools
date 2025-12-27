#!/usr/bin/env bash
# ============================================================
# VPN SERVER OPTIMIZER — UI POLISHED SAFE BUILD (V15.1.0-UI)
# Target: Xray / VLESS TCP Reality (stable, low-latency)
#
# SAFE by design:
# - DOES NOT touch MTU (no probing, no netplan MTU persist)
# - DOES NOT tune NIC ring buffers (ethtool ring often harms VPS latency)
# - DISABLES tcp_mtu_probing (prevents runaway MTU shrink on lossy paths)
# - DOES NOT route all DNS via Domains=~. (no global DNS hijack)
# ============================================================

set -Eeuo pipefail
IFS=$'\n\t'

# =========================
# CONFIG
# =========================
SCRIPT_NAME="vpn_optimizer"
VERSION="V15.1.0-UI"

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
# COLORS (tasteful)
# =========================
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Modern-ish palette
FG_RED='\033[38;5;203m'
FG_GREEN='\033[38;5;82m'
FG_YELLOW='\033[38;5;220m'
FG_BLUE='\033[38;5;75m'
FG_MAGENTA='\033[38;5;141m'
FG_CYAN='\033[38;5;51m'
FG_GRAY='\033[38;5;245m'
FG_WHITE='\033[38;5;255m'

# =========================
# ROOT CHECK
# =========================
if [[ ${EUID:-9999} -ne 0 ]]; then
  echo -e "${FG_RED}${BOLD}This script must be run as root.${RESET}"
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
term_width() {
  local c
  c="$(tput cols 2>/dev/null || echo 90)"
  # clamp
  (( c < 70 )) && c=70
  (( c > 110 )) && c=110
  echo "$c"
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

hr() {
  local w; w="$(term_width)"
  echo -e "${FG_GRAY}$(repeat_char "-" "$w")${RESET}"
}

hr2() {
  local w; w="$(term_width)"
  echo -e "${FG_GRAY}$(repeat_char "=" "$w")${RESET}"
}

center() {
  local text="$1"
  local w; w="$(term_width)"
  local len=${#text}
  if (( len >= w )); then
    echo "$text"
    return
  fi
  local pad=$(( (w - len) / 2 ))
  printf "%*s%s\n" "$pad" "" "$text"
}

title_box() {
  local text="$1"
  hr
  echo -e "${BOLD}${FG_CYAN}$(center "$text")${RESET}"
  hr
}

section() {
  local text="$1"
  echo -e "${BOLD}${FG_BLUE}[$text]${RESET}"
}

kv() {
  local k="$1" v="$2"
  printf "%b%-18s%b %b%s%b\n" "$DIM$FG_GRAY" "$k:" "$RESET" "$BOLD$FG_WHITE" "$v" "$RESET"
}

ok()   { echo -e "${FG_GREEN}${BOLD}OK${RESET}"; }
warn() { echo -e "${FG_YELLOW}${BOLD}WARN${RESET}"; }
fail() { echo -e "${FG_RED}${BOLD}FAIL${RESET}"; }

pause() {
  if [[ -t 0 ]]; then
    read -rp "$(echo -e "${FG_GRAY}Press Enter...${RESET}")"
  else
    sleep 1
  fi
}

progress_bar() {
  local pct="$1"
  local title="${2:-}"
  local width=28
  local filled=$(( pct * width / 100 ))
  local empty=$(( width - filled ))
  local bar
  bar="$(repeat_char "#" "$filled")$(repeat_char "." "$empty")"
  printf "\r%b[%s] %3s%%%b %s" "$FG_MAGENTA" "$bar" "$pct" "$RESET" "$title"
}

run_step() {
  local idx="$1" total="$2" title="$3" fn="$4"
  local pct=$(( idx * 100 / total ))
  progress_bar "$pct" "$title"
  echo -ne "\n${DIM}${FG_GRAY}${title}${RESET} ... "
  if "$fn"; then
    ok
  else
    fail
    return 1
  fi
}

print_logo() {
  clear
  local w; w="$(term_width)"
  echo -e "${FG_MAGENTA}${BOLD}"
  cat <<'EOF'
 __      __  _____  _   _
 \ \    / / |  __ \| \ | |
  \ \  / /  | |__) |  \| |
   \ \/ /   |  ___/| . ` |
    \  /    | |    | |\  |
     \/     |_|    |_| \_|
EOF
  echo -e "${RESET}"
  echo -e "${BOLD}${FG_CYAN}$(center "Optimizer For VPN Servers By @UnknownZero")${RESET}"
  echo -e "${DIM}${FG_GRAY}$(center "SAFE build for VLESS TCP Reality | UI polished")${RESET}"
  hr2
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
# SYSTEM INFO (base)
# =========================
OS_NAME="$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Unknown")"
KERNEL_FULL="$(uname -r 2>/dev/null || echo "Unknown")"
KERNEL_BASE="${KERNEL_FULL%%-*}"
PHY_INTERFACES="$(ls /sys/class/net 2>/dev/null | grep -Ev 'lo|docker|veth|tun|wg|br-|cali' || true)"
DEFAULT_IFACE="$(get_default_iface || true)"
DEFAULT_GW="$(get_default_gw_ipv4 || true)"

# refreshable RAM MB (do not freeze)
get_ram_mb() { free -m 2>/dev/null | awk '/Mem:/ {print $2}' || echo 0; }

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
# NETWORK / IP HELPERS
# =========================
has_cmd() { command -v "$1" >/dev/null 2>&1; }

curl_quick() {
  # curl_quick <ipver> <url>
  local ipver="$1" url="$2"
  if ! has_cmd curl; then return 1; fi
  if [[ "$ipver" == "4" ]]; then
    curl -4 -fsS --max-time 2 "$url" 2>/dev/null | tr -d ' \n\r'
  else
    curl -6 -fsS --max-time 2 "$url" 2>/dev/null | tr -d ' \n\r'
  fi
}

get_public_ip4() {
  local ip=""
  ip="$(curl_quick 4 "https://api.ipify.org" || true)"
  [[ -n "$ip" ]] || ip="$(curl_quick 4 "https://ifconfig.co/ip" || true)"
  [[ -n "$ip" ]] || ip="$(curl_quick 4 "https://ip.sb" || true)"
  if is_valid_ipv4 "$ip"; then
    echo "$ip"
    return 0
  fi
  # fallback to first global ipv4 on interface
  ip="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  echo "${ip:-N/A}"
}

get_public_ip6() {
  local ip=""
  ip="$(curl_quick 6 "https://api64.ipify.org" || true)"
  [[ -n "$ip" ]] || ip="$(curl_quick 6 "https://ifconfig.co/ip" || true)"
  [[ -n "$ip" ]] || ip="$(curl_quick 6 "https://ip.sb" || true)"
  # basic sanity: must contain :
  if [[ "$ip" == *:* ]]; then
    echo "$ip"
    return 0
  fi
  ip="$(ip -6 addr show scope global 2>/dev/null | awk '/inet6 /{print $2}' | cut -d/ -f1 | head -n1 || true)"
  echo "${ip:-N/A}"
}

# CPU usage via /proc/stat (more portable than parsing top)
cpu_usage_pct() {
  local a b idle_a idle_b total_a total_b
  read -r _ a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 < /proc/stat
  idle_a=$((a4 + a5))
  total_a=$((a1+a2+a3+a4+a5+a6+a7+a8+a9+a10))
  sleep 0.4
  read -r _ b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 < /proc/stat
  idle_b=$((b4 + b5))
  total_b=$((b1+b2+b3+b4+b5+b6+b7+b8+b9+b10))
  local idle_delta=$((idle_b - idle_a))
  local total_delta=$((total_b - total_a))
  if (( total_delta <= 0 )); then echo "0"; return; fi
  local usage=$(( (1000 * (total_delta - idle_delta) / total_delta + 5) / 10 ))
  echo "$usage"
}

cpu_model() {
  local m=""
  if has_cmd lscpu; then
    m="$(lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' || true)"
  fi
  if [[ -z "$m" ]]; then
    m="$(awk -F: '/model name/ {gsub(/^[ \t]+/,"",$2); print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
  fi
  echo "${m:-Unknown}"
}

uptime_pretty() {
  if has_cmd uptime; then
    uptime -p 2>/dev/null | sed 's/^up //'
  else
    echo "Unknown"
  fi
}

# =========================
# BBR/QDISC
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
# DNS (SAFE)
# =========================
select_dns() {
  print_logo
  title_box "DNS Provider Selection"
  echo -e "${BOLD}${FG_WHITE}[1]${RESET} Cloudflare  ${FG_GRAY}(1.1.1.1 / 1.0.0.1)${RESET}"
  echo -e "${BOLD}${FG_WHITE}[2]${RESET} Google      ${FG_GRAY}(8.8.8.8 / 8.8.4.4)${RESET}"
  echo -e "${BOLD}${FG_WHITE}[3]${RESET} Quad9       ${FG_GRAY}(9.9.9.9 / 149.112.112.112)${RESET}"
  echo -e "${BOLD}${FG_WHITE}[4]${RESET} OpenDNS     ${FG_GRAY}(208.67.222.222 / 208.67.220.220)${RESET}"
  echo -e "${BOLD}${FG_WHITE}[5]${RESET} Shecan      ${FG_GRAY}(178.22.122.100 / 185.51.200.2)${RESET}"
  echo -e "${BOLD}${FG_WHITE}[6]${RESET} Custom"
  echo -e "${BOLD}${FG_WHITE}[0]${RESET} Keep current"
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
    backup /etc/resolv.conf
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
# SYSCTL (SAFE)
# =========================
calc_buf_max() {
  local ram_mb; ram_mb="$(get_ram_mb)"
  local rmax wmax
  if (( ram_mb <= 1024 )); then
    rmax=$(( 8 * 1024 * 1024 ))
    wmax=$(( 8 * 1024 * 1024 ))
  elif (( ram_mb <= 4096 )); then
    rmax=$(( 16 * 1024 * 1024 ))
    wmax=$(( 16 * 1024 * 1024 ))
  elif (( ram_mb <= 8192 )); then
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

  local RAM_MB; RAM_MB="$(get_ram_mb)"
  local CONNTRACK
  if (( RAM_MB <= 1024 )); then CONNTRACK=65536
  elif (( RAM_MB <= 4096 )); then CONNTRACK=262144
  else CONNTRACK=$((RAM_MB * 64)); fi
  (( CONNTRACK > 2000000 )) && CONNTRACK=2000000

  local RMAX WMAX
  read -r RMAX WMAX <<<"$(calc_buf_max)"

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

net.core.default_qdisc=${QDISC}
net.ipv4.tcp_congestion_control=${BBR_ALGO}

net.core.somaxconn=${SOMAX}
net.ipv4.tcp_max_syn_backlog=${SYNBK}
net.core.netdev_max_backlog=${NETDEV}
net.ipv4.tcp_syncookies=1

net.ipv4.ip_local_port_range=10240 65535

net.ipv4.tcp_fastopen=3
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=60
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_tw_reuse=1

# IMPORTANT: disable MTU probing
net.ipv4.tcp_mtu_probing=0

# Socket buffers (conservative)
net.core.rmem_max=${RMAX}
net.core.wmem_max=${WMAX}
net.core.rmem_default=262144
net.core.wmem_default=262144
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.ipv4.tcp_rmem=4096 87380 ${RMAX}
net.ipv4.tcp_wmem=4096 65536 ${WMAX}

net.ipv4.ip_forward=1

net.netfilter.nf_conntrack_max=${CONNTRACK}

vm.swappiness=10
fs.file-max=2097152
EOF

  sysctl --system >/dev/null 2>&1 || true
  return 0
}

# =========================
# LIMITS
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
# IRQBALANCE (optional)
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
# SWAP (optional)
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
# LEGACY CLEANUP
# =========================
cleanup_legacy() {
  print_logo
  title_box "Cleanup Legacy Risky Tweaks"

  local iface
  iface="$(get_default_iface || true)"
  if [[ -n "${iface:-}" ]]; then
    local cur
    cur="$(ip link show dev "$iface" 2>/dev/null | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}' || true)"
    if [[ -n "${cur:-}" && "${cur:-}" != "1500" ]]; then
      echo -e "${FG_YELLOW}${BOLD}Resetting MTU on ${iface} to 1500 (runtime only).${RESET}"
      ip link set dev "$iface" mtu 1500 2>/dev/null || true
      log "Legacy cleanup: set MTU=1500 on ${iface} (was ${cur})."
    fi
  fi

  if [[ -f /etc/netplan/99-vpn-override.yaml ]]; then
    echo -e "${FG_YELLOW}${BOLD}Removing /etc/netplan/99-vpn-override.yaml${RESET}"
    rm -f /etc/netplan/99-vpn-override.yaml 2>/dev/null || true
    if command -v netplan >/dev/null 2>&1; then
      netplan generate >/dev/null 2>&1 || true
      netplan apply >/dev/null 2>&1 || true
    fi
    log "Legacy cleanup: removed netplan override."
  fi

  local d1="/etc/systemd/resolved.conf.d/99-vpn_optimizer.conf"
  local d2="/etc/systemd/resolved.conf.d/99-${SCRIPT_NAME}.conf"
  for d in "$d1" "$d2"; do
    if [[ -f "$d" ]]; then
      echo -e "${FG_YELLOW}${BOLD}Removing ${d}${RESET}"
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

  echo -e "${FG_GREEN}${BOLD}OK:${RESET} Legacy cleanup done (best effort)."
  hr
  pause
  return 0
}

# =========================
# ROLLBACK
# =========================
restore_defaults() {
  print_logo
  title_box "Rollback (Latest Backup)"
  echo -e "${FG_YELLOW}${BOLD}Rollback will revert files touched by this script (latest run).${RESET}"
  read -rp "Continue? [y/N]: " c
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

  echo -e "${FG_GREEN}${BOLD}OK:${RESET} Rollback complete."
  hr
  pause
  return 0
}

# =========================
# STATUS (Enhanced)
# =========================
show_status() {
  print_logo
  title_box "System Status (Enhanced)"

  local RAM_MB; RAM_MB="$(get_ram_mb)"
  local cpu_m; cpu_m="$(cpu_model)"
  local cpu_cores; cpu_cores="$(nproc 2>/dev/null || echo 0)"
  local cpu_use; cpu_use="$(cpu_usage_pct 2>/dev/null || echo 0)"
  local up; up="$(uptime_pretty)"

  local cc qdisc mtu_probe
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")"
  mtu_probe="$(sysctl -n net.ipv4.tcp_mtu_probing 2>/dev/null || echo "?")"

  local bbr_state
  if [[ "$cc" == "bbr" ]]; then
    bbr_state="Enabled (bbr)"
  else
    bbr_state="Disabled (using: ${cc})"
  fi

  local mem_total mem_used mem_free mem_avail
  if has_cmd free; then
    mem_total="$(free -h | awk '/Mem:/ {print $2}' || echo "?")"
    mem_used="$(free -h | awk '/Mem:/ {print $3}' || echo "?")"
    mem_free="$(free -h | awk '/Mem:/ {print $4}' || echo "?")"
    mem_avail="$(free -h | awk '/Mem:/ {print $7}' || echo "?")"
  else
    mem_total="?"; mem_used="?"; mem_free="?"; mem_avail="?"
  fi

  local disk_total disk_used disk_avail disk_pct
  disk_total="$(df -h / 2>/dev/null | awk 'NR==2{print $2}' || echo "?")"
  disk_used="$(df -h / 2>/dev/null | awk 'NR==2{print $3}' || echo "?")"
  disk_avail="$(df -h / 2>/dev/null | awk 'NR==2{print $4}' || echo "?")"
  disk_pct="$(df -h / 2>/dev/null | awk 'NR==2{print $5}' || echo "?")"

  local swap_on swap_total swap_used
  if swapon --show 2>/dev/null | grep -q .; then
    swap_on="Enabled"
    swap_total="$(free -h 2>/dev/null | awk '/Swap:/ {print $2}' || echo "?")"
    swap_used="$(free -h 2>/dev/null | awk '/Swap:/ {print $3}' || echo "?")"
  else
    swap_on="Disabled"
    swap_total="0"
    swap_used="0"
  fi

  local ip4 ip6
  ip4="$(get_public_ip4)"
  ip6="$(get_public_ip6)"

  section "System"
  kv "OS" "$OS_NAME"
  kv "Kernel" "$KERNEL_FULL"
  kv "Uptime" "${up:-Unknown}"
  hr

  section "CPU"
  kv "Model" "$cpu_m"
  kv "Cores/Threads" "$cpu_cores"
  kv "Usage" "${cpu_use}%"
  hr

  section "Memory"
  kv "RAM Total" "$mem_total"
  kv "RAM Used" "$mem_used"
  kv "RAM Free" "$mem_free"
  kv "RAM Available" "$mem_avail"
  hr

  section "Disk (/)"
  kv "Total" "$disk_total"
  kv "Used" "$disk_used"
  kv "Free" "$disk_avail"
  kv "Usage" "$disk_pct"
  hr

  section "Swap"
  kv "Status" "$swap_on"
  kv "Total" "$swap_total"
  kv "Used" "$swap_used"
  hr

  section "Network"
  kv "Default IF" "${DEFAULT_IFACE:-unknown}"
  kv "Gateway" "${DEFAULT_GW:-unknown}"
  kv "IPv4 (public)" "${ip4:-N/A}"
  kv "IPv6 (public)" "${ip6:-N/A}"
  hr

  section "TCP / VPN Tuning"
  kv "BBR" "$bbr_state"
  kv "qdisc" "$qdisc"
  kv "tcp_mtu_probing" "$mtu_probe"
  kv "DNS (selected)" "${DNS1} / ${DNS2}"
  hr

  section "Quick Network Snapshot"
  echo -e "${DIM}${FG_GRAY}ip -br addr:${RESET}"
  ip -br addr 2>/dev/null || true
  echo
  echo -e "${DIM}${FG_GRAY}ip route:${RESET}"
  ip route 2>/dev/null || true
  echo
  echo -e "${DIM}${FG_GRAY}DNS stack:${RESET}"
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo -e "${FG_GREEN}systemd-resolved: active${RESET}"
    resolvectl dns 2>/dev/null || true
  else
    echo -e "${FG_YELLOW}systemd-resolved: not active${RESET}"
    ls -l /etc/resolv.conf 2>/dev/null || true
    sed -n '1,40p' /etc/resolv.conf 2>/dev/null || true
  fi

  hr2
  echo -e "${DIM}${FG_GRAY}Log: ${LOG_FILE}${RESET}"
  pause
  return 0
}

# =========================
# OPTIMIZE SERVER (SAFE APPLY)
# =========================
optimize_server() {
  print_logo
  title_box "Run Optimization (SAFE)"

  init_backup_dir
  echo -e "${FG_GRAY}Backups:${RESET} ${BOLD}${FG_WHITE}$BACKUP_DIR${RESET}"
  echo -e "${FG_GRAY}Log:${RESET}     ${BOLD}${FG_WHITE}$LOG_FILE${RESET}"
  hr

  select_dns

  print_logo
  title_box "Applying Changes"

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
  echo -e "${FG_GREEN}${BOLD}DONE:${RESET} Optimization completed successfully."
  echo -e "${FG_GRAY}Backups:${RESET} ${BOLD}${FG_WHITE}$BACKUP_DIR${RESET} ${DIM}${FG_GRAY}(latest -> $BACKUP_LATEST_LINK)${RESET}"
  echo -e "${FG_GRAY}Log:${RESET}     ${BOLD}${FG_WHITE}$LOG_FILE${RESET}"
  hr
  pause
  return 0
}

# =========================
# UFW FIREWALL
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
# MENU LOOP
# =========================
while true; do
  print_logo

  local_ram="$(get_ram_mb)"
  local_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
  local_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")"
  local_ip4="$(get_public_ip4)"
  local_ip6="$(get_public_ip6)"

  echo -e "${BOLD}${FG_WHITE}VPN SERVER OPTIMIZER${RESET} ${DIM}${FG_GRAY}${VERSION}${RESET}   ${FG_GRAY}(VLESS TCP Reality SAFE)${RESET}"
  hr

  kv "OS" "$OS_NAME"
  kv "Kernel" "$KERNEL_BASE"
  kv "RAM" "${local_ram} MB"
  kv "Default IF" "${DEFAULT_IFACE:-unknown}"
  kv "IPv4/IPv6" "${local_ip4:-N/A} | ${local_ip6:-N/A}"
  hr

  echo -e "${DIM}${FG_GRAY}TCP:${RESET} cc=${BOLD}${FG_WHITE}${local_cc}${RESET}  qdisc=${BOLD}${FG_WHITE}${local_qdisc}${RESET}   ${DIM}${FG_GRAY}DNS:${RESET} ${DNS1}/${DNS2}"
  hr2

  echo -e "${BOLD}${FG_WHITE}[1]${RESET} Optimize Server (Safe Apply)"
  echo -e "${BOLD}${FG_WHITE}[2]${RESET} System Status (Enhanced)"
  echo -e "${BOLD}${FG_WHITE}[3]${RESET} Rollback (latest backup)"
  echo -e "${BOLD}${FG_WHITE}[4]${RESET} Enable irqbalance"
  echo -e "${BOLD}${FG_WHITE}[5]${RESET} DNS Provider (Safe Apply)"
  echo -e "${BOLD}${FG_WHITE}[6]${RESET} Cleanup legacy risky tweaks (MTU/netplan/resolved)"
  if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
    echo -e "${BOLD}${FG_WHITE}[7]${RESET} Setup Firewall (UFW)"
    echo -e "${BOLD}${FG_WHITE}[8]${RESET} Reboot Server"
    echo -e "${BOLD}${FG_WHITE}[0]${RESET} Exit"
  else
    echo -e "${BOLD}${FG_WHITE}[7]${RESET} Reboot Server"
    echo -e "${BOLD}${FG_WHITE}[0]${RESET} Exit"
  fi

  hr
  echo -e "${DIM}${FG_GRAY}Optimizer For VPN Servers By @UnknownZero${RESET}"
  hr2

  read -rp "Select: " opt

  case "${opt:-}" in
    1) optimize_server ;;
    2) show_status ;;
    3) restore_defaults ;;
    4)
      print_logo
      title_box "Enable irqbalance"
      setup_irqbalance
      if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet irqbalance 2>/dev/null; then
        echo -e "${FG_GREEN}${BOLD}OK:${RESET} irqbalance is active."
      else
        echo -e "${FG_YELLOW}${BOLD}WARN:${RESET} irqbalance is not active (some VMs limit IRQ behavior)."
      fi
      hr
      pause
      ;;
    5)
      select_dns
      print_logo
      title_box "Apply DNS (SAFE)"
      init_backup_dir
      run_step 1 1 "Apply DNS (safe)" apply_dns || true
      hr
      pause
      ;;
    6) cleanup_legacy ;;
    7)
      if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
        print_logo
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
        echo -e "${FG_RED}${BOLD}Invalid option.${RESET}"
        sleep 1
      fi
      ;;
    0) exit ;;
    *) echo -e "${FG_RED}${BOLD}Invalid option.${RESET}"; sleep 1 ;;
  esac
done
