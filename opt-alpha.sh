#!/bin/bash
# ============================================================
# VPN SERVER OPTIMIZER — ENTERPRISE INFRA EDITION (V14.3)
# Targets: Xray (TCP/Reality/WS/gRPC) + Hysteria2 (UDP/QUIC)
# UI Upgrade: Fancy Menus, Progress Display, Rich System Status
# Creator : UnknownZero
# Telegram ID : @UnknownZero
# ============================================================

set -Eeuo pipefail
IFS=$'\n\t'

# =========================
# GLOBAL CONFIG
# =========================
SCRIPT_NAME="vpn_optimizer"
VERSION="V14.3"
LOG_FILE="/var/log/${SCRIPT_NAME}.log"
LOG_MAX_SIZE=$((5 * 1024 * 1024))     # 5MB
LOG_MAX_COUNT=10
LOG_RETENTION_DAYS=30

BACKUP_ROOT="/root/${SCRIPT_NAME}_backups"
RUN_ID="$(date +%F_%H-%M-%S)"
BACKUP_DIR="${BACKUP_ROOT}/${RUN_ID}"
BACKUP_LATEST_LINK="${BACKUP_ROOT}/latest"

APPLY_DNS_TO_ALL_INTERFACES=0

ENABLE_SWAP=1
ENABLE_UFW_MENU=1
ENABLE_MTU_OPTIMIZE=1

ENABLE_IRQBALANCE=1
ENABLE_ETHTOOL_RING=1

MTU_PROBE_TIMEOUT=1
MTU_MIN=1280
MTU_HEADROOM=8

RING_DESIRED=4096

# =========================
# COLORS / UI
# =========================
RED='\033[38;5;196m'
GREEN='\033[38;5;46m'
YELLOW='\033[38;5;226m'
BLUE='\033[38;5;33m'
CYAN='\033[38;5;51m'
PURPLE='\033[38;5;141m'
GRAY='\033[38;5;245m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Icons
ICON_OK="✅"
ICON_RUN="⏳"
ICON_WARN="⚠️"
ICON_FAIL="❌"
ICON_INFO="ℹ️"
ICON_NET="🌐"
ICON_CPU="🧠"
ICON_RAM="💾"
ICON_DISK="🗄️"
ICON_OS="🖥️"
ICON_TIME="⏱️"
ICON_LOCK="🔐"
ICON_FIRE="🔥"
ICON_WRENCH="🛠️"
ICON_ROCKET="🚀"
ICON_REDO="🔄"
ICON_LIST="📊"
ICON_DNS="📡"
ICON_MTU="📏"

# =========================
# ROOT CHECK
# =========================
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}This script must be run as root${NC}"
  exit 1
fi

# =========================
# LOGGING & ROTATION
# =========================
rotate_logs() {
  [[ -f "$LOG_FILE" ]] || return
  local size rotated
  size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)

  if (( size >= LOG_MAX_SIZE )); then
    rotated="$LOG_FILE.$(date +%F-%H%M).old"
    mv "$LOG_FILE" "$rotated"
    gzip -f "$rotated" || true
    : > "$LOG_FILE"
  fi

  ls -t "$LOG_FILE".*.gz 2>/dev/null | tail -n +$((LOG_MAX_COUNT + 1)) | xargs -r rm -- || true
  find "$(dirname "$LOG_FILE")" -name "$(basename "$LOG_FILE")*.gz" -mtime +"$LOG_RETENTION_DAYS" -delete || true
}

rotate_logs
exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo -e "[$(date '+%F %T')] $*"; }

mkdir -p "$BACKUP_DIR"
ln -sfn "$BACKUP_DIR" "$BACKUP_LATEST_LINK"

backup() {
  local src="$1"
  [[ -f "$src" ]] && cp -a "$src" "$BACKUP_DIR/$(basename "$src").bak"
}

restore_from_latest_or_remove() {
  local dest="$1"
  local latest="${BACKUP_LATEST_LINK}/$(basename "$dest").bak"
  if [[ -f "$latest" ]]; then
    cp -a "$latest" "$dest"
    return 0
  fi
  rm -f "$dest"
  return 0
}

# =========================
# UI HELPERS
# =========================
term_cols() { tput cols 2>/dev/null || echo 80; }

hr() {
  local c; c="$(term_cols)"
  printf "${GRAY}%*s${NC}\n" "$c" "" | tr ' ' '━'
}

title_box() {
  local text="$1"
  hr
  echo -e "${BOLD}${CYAN}$text${NC}"
  hr
}

kv() {
  # kv "Label" "Value"
  local k="$1" v="$2"
  printf "${BLUE}%-20s${NC} ${BOLD}%s${NC}\n" "$k" "$v"
}

subkv() {
  local k="$1" v="$2"
  printf "${GRAY}  %-18s${NC} %s\n" "$k" "$v"
}

pause() { read -rp "$(echo -e "${GRAY}Press Enter...${NC}")"; }

progress_bar() {
  # progress_bar percent "message"
  local p="$1" msg="$2"
  local width=30
  local filled=$((p * width / 100))
  local empty=$((width - filled))
  local bar
  bar="$(printf "%0.s█" $(seq 1 $filled) 2>/dev/null)"
  bar+="${DIM}$(printf "%0.s░" $(seq 1 $empty) 2>/dev/null)${NC}"
  printf "\r${PURPLE}${BOLD}[%3s%%]${NC} ${GREEN}%s${NC} ${GRAY}%s${NC}   " "$p" "$bar" "$msg"
}

# Error trap for nicer output
on_error() {
  local line="$1" cmd="$2"
  echo
  echo -e "${RED}${ICON_FAIL} خطا در اجرای اسکریپت${NC}"
  echo -e "${YELLOW}Line:${NC} $line"
  echo -e "${YELLOW}Cmd :${NC} $cmd"
  echo -e "${GRAY}Log:${NC} $LOG_FILE"
  echo
  pause
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

# =========================
# BASIC HELPERS
# =========================
is_valid_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.
  read -r a b c d <<<"$ip"
  (( a<=255 && b<=255 && c<=255 && d<=255 ))
}

ver_ge() {
  local a="$1" b="$2"
  local IFS=.
  local -a A=($a) B=($b)
  local i
  for ((i=${#A[@]}; i<${#B[@]}; i++)); do A[i]=0; done
  for ((i=0; i<${#A[@]}; i++)); do
    [[ -z "${B[i]:-}" ]] && B[i]=0
    ((10#${A[i]} > 10#${B[i]})) && return 0
    ((10#${A[i]} < 10#${B[i]})) && return 1
  done
  return 0
}

get_default_iface() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $5}' | head -n1
}

get_default_gw_ipv4() {
  ip route show default 0.0.0.0/0 2>/dev/null | awk '{print $3}' | head -n1
}

detect_init_dns_stack() {
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo "resolved"
  else
    echo "plain"
  fi
}

swap_active() {
  swapon --noheadings 2>/dev/null | grep -q .
}

get_iface_mtu() {
  local iface="$1"
  ip link show dev "$iface" 2>/dev/null | awk '/mtu/ {for(i=1;i<=NF;i++) if($i=="mtu"){print $(i+1); exit}}'
}

install_pkg() {
  local pkg="$1"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1 || return 1
    return 0
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$pkg" >/dev/null 2>&1 || return 1
    return 0
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$pkg" >/dev/null 2>&1 || return 1
    return 0
  fi
  return 1
}

# =========================
# SYSTEM INFO
# =========================
RAM_MB=$(free -m | awk '/Mem:/ {print $2}')
OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
KERNEL_FULL=$(uname -r)
KERNEL_BASE="${KERNEL_FULL%%-*}"
PHY_INTERFACES=$(ls /sys/class/net | grep -Ev 'lo|docker|veth|tun|wg|br-|cali' || true)
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

# ============================================================
# 1) KERNEL & BBR
# ============================================================
check_kernel_bbr() {
  log "Checking Kernel & BBR support (kernel=${KERNEL_BASE})"

  local kernel_ok=1
  if command -v dpkg >/dev/null 2>&1; then
    dpkg --compare-versions "$KERNEL_BASE" ge "4.9" && kernel_ok=0 || kernel_ok=1
  else
    ver_ge "$KERNEL_BASE" "4.9" && kernel_ok=0 || kernel_ok=1
  fi

  if (( kernel_ok != 0 )); then
    log "Kernel < 4.9 — BBR not supported, using cubic"
    BBR_ALGO="cubic"
    QDISC="fq_codel"
    return
  fi

  modprobe tcp_bbr &>/dev/null || true
  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
    BBR_ALGO="bbr"
    QDISC="fq"
    log "BBR supported and will be enabled"
  else
    BBR_ALGO="cubic"
    QDISC="fq_codel"
    log "BBR module unavailable — using cubic"
  fi

  if [[ "$BBR_ALGO" == "bbr" ]]; then
    mkdir -p /etc/modules-load.d
    backup /etc/modules-load.d/bbr.conf
    echo "tcp_bbr" > /etc/modules-load.d/bbr.conf
  fi
}

# ============================================================
# 2) DNS
# ============================================================
select_dns() {
  clear
  title_box "📡 انتخاب DNS"
  echo -e "${CYAN}1) Cloudflare${NC}   ${GRAY}(1.1.1.1 / 1.0.0.1)${NC}"
  echo -e "${CYAN}2) Google${NC}       ${GRAY}(8.8.8.8 / 8.8.4.4)${NC}"
  echo -e "${CYAN}3) Quad9${NC}        ${GRAY}(9.9.9.9 / 149.112.112.112)${NC}"
  echo -e "${CYAN}4) OpenDNS${NC}      ${GRAY}(208.67.222.222 / 208.67.220.220)${NC}"
  echo -e "${CYAN}5) Shecan${NC}       ${GRAY}(178.22.122.100 / 185.51.200.2)${NC}"
  echo -e "${CYAN}6) Custom${NC}"
  hr
  read -rp "➤ انتخاب شما: " d

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
    *) DNS1=1.1.1.1; DNS2=1.0.0.1 ;;
  esac

  if ! is_valid_ipv4 "$DNS1" || ! is_valid_ipv4 "$DNS2"; then
    log "Invalid DNS entered. Falling back to Cloudflare."
    DNS1=1.1.1.1; DNS2=1.0.0.1
  fi
}

apply_dns() {
  log "Applying DNS (targets: $(echo "$TARGET_INTERFACES" | tr '\n' ' '))"

  local dns_stack
  dns_stack="$(detect_init_dns_stack)"

  if [[ "$dns_stack" == "resolved" ]]; then
    mkdir -p /etc/systemd/resolved.conf.d
    local dropin="/etc/systemd/resolved.conf.d/99-${SCRIPT_NAME}.conf"
    backup "$dropin"

    cat > "$dropin" <<EOF
[Resolve]
DNS=$DNS1 $DNS2
FallbackDNS=$DNS2
Domains=~.
DNSStubListener=no
EOF

    systemctl restart systemd-resolved >/dev/null 2>&1 || true
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf >/dev/null 2>&1 || true

    for iface in $TARGET_INTERFACES; do
      resolvectl revert "$iface" 2>/dev/null || true
      resolvectl dns "$iface" "$DNS1" "$DNS2" 2>/dev/null || true
      resolvectl domain "$iface" "~." 2>/dev/null || true
    done
  else
    backup /etc/resolv.conf
    cat > /etc/resolv.conf <<EOF
nameserver $DNS1
nameserver $DNS2
EOF
  fi
}

apply_netplan_override() {
  [[ -d /etc/netplan ]] || return 0
  log "Applying Netplan DHCP DNS override"

  local np="/etc/netplan/99-vpn-override.yaml"
  backup "$np"

  {
    echo "network:"
    echo "  version: 2"
    echo "  ethernets:"
    for i in $TARGET_INTERFACES; do
      echo "    $i:"
      echo "      dhcp4-overrides:"
      echo "        use-dns: false"
      echo "      dhcp6-overrides:"
      echo "        use-dns: false"
    done
  } > "$np"
  chmod 600 "$np"

  if netplan generate >/dev/null 2>&1 && netplan apply >/dev/null 2>&1; then
    :
  else
    log "Netplan failed — rolling back"
    restore_from_latest_or_remove "$np" || true
    netplan apply >/dev/null 2>&1 || true
  fi
}

# ============================================================
# 3) SYSCTL
# ============================================================
apply_sysctl() {
  backup /etc/sysctl.d/99-vpn-opt.conf

  local CONNTRACK
  if (( RAM_MB <= 1024 )); then CONNTRACK=65536
  elif (( RAM_MB <= 4096 )); then CONNTRACK=262144
  else CONNTRACK=$((RAM_MB * 64)); fi
  (( CONNTRACK > 2000000 )) && CONNTRACK=2000000

  local RMAX=$((128 * 1024 * 1024))
  local WMAX=$((128 * 1024 * 1024))

  cat > /etc/sysctl.d/99-vpn-opt.conf <<EOF
net.core.default_qdisc=$QDISC
net.ipv4.tcp_congestion_control=$BBR_ALGO

net.core.somaxconn=65535
net.core.netdev_max_backlog=250000
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_syncookies=1

net.ipv4.ip_local_port_range=10240 65535

net.ipv4.tcp_fastopen=3
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_fin_timeout=30
net.ipv4.tcp_keepalive_time=300
net.ipv4.tcp_keepalive_intvl=60
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_tw_reuse=1

net.core.rmem_max=$RMAX
net.core.wmem_max=$WMAX
net.core.rmem_default=262144
net.core.wmem_default=262144
net.ipv4.udp_rmem_min=16384
net.ipv4.udp_wmem_min=16384
net.ipv4.tcp_rmem=4096 87380 $RMAX
net.ipv4.tcp_wmem=4096 65536 $WMAX

net.netfilter.nf_conntrack_max=$CONNTRACK
net.ipv4.ip_forward=1

vm.swappiness=10
fs.file-max=2097152
EOF

  sysctl --system >/dev/null || true
}

# ============================================================
# 4) LIMITS
# ============================================================
apply_limits() {
  backup /etc/security/limits.d/99-vpn.conf
  cat > /etc/security/limits.d/99-vpn.conf <<EOF
* soft nofile 500000
* hard nofile 500000
root soft nofile 500000
root hard nofile 500000
EOF

  backup /etc/systemd/system.conf
  sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf
  echo "DefaultLimitNOFILE=500000" >> /etc/systemd/system.conf
  systemctl daemon-reexec >/dev/null 2>&1 || true
}

# ============================================================
# 5) MTU OPTIMIZATION (SAFE)
# ============================================================
_ping_df_ipv4() {
  local target="$1" payload="$2"
  ping -4 -c 1 -W "$MTU_PROBE_TIMEOUT" -M do -s "$payload" "$target" >/dev/null 2>&1
}

probe_path_mtu_ipv4() {
  local target="$1" current_mtu="$2"
  local payload_low payload_high mid best lo hi
  payload_low=1200
  payload_high=$((current_mtu - 28))
  (( payload_high > 1472 )) && payload_high=1472

  if ! _ping_df_ipv4 "$target" 1200; then
    echo ""
    return 0
  fi

  best=1200
  lo=$payload_low
  hi=$payload_high

  while (( lo <= hi )); do
    mid=$(((lo + hi) / 2))
    if _ping_df_ipv4 "$target" "$mid"; then
      best="$mid"
      lo=$((mid + 1))
    else
      hi=$((mid - 1))
    fi
  done

  echo $((best + 28))
}

apply_mtu_runtime() {
  local iface="$1" new_mtu="$2"
  ip link set dev "$iface" mtu "$new_mtu" >/dev/null 2>&1
}

persist_mtu_netplan() {
  [[ -d /etc/netplan ]] || return 0
  local np="/etc/netplan/99-vpn-override.yaml"
  [[ -f "$np" ]] || return 0

  backup "$np"
  {
    echo "network:"
    echo "  version: 2"
    echo "  ethernets:"
    for i in $TARGET_INTERFACES; do
      echo "    $i:"
      echo "      mtu: $OPT_MTU"
      echo "      dhcp4-overrides:"
      echo "        use-dns: false"
      echo "      dhcp6-overrides:"
      echo "        use-dns: false"
    done
  } > "$np"
  chmod 600 "$np"

  if netplan generate >/dev/null 2>&1 && netplan apply >/dev/null 2>&1; then
    :
  else
    restore_from_latest_or_remove "$np" || true
    netplan apply >/dev/null 2>&1 || true
  fi
}

optimize_mtu() {
  [[ "$ENABLE_MTU_OPTIMIZE" -eq 1 ]] || return 0
  [[ -n "${DEFAULT_IFACE:-}" ]] || return 0

  local iface="$DEFAULT_IFACE"
  local current_mtu
  current_mtu="$(get_iface_mtu "$iface" || true)"
  [[ -n "${current_mtu:-}" ]] || return 0

  local -a targets=()
  [[ -n "${DEFAULT_GW:-}" ]] && targets+=("$DEFAULT_GW")
  targets+=("1.1.1.1" "8.8.8.8" "9.9.9.9")

  local best_mtu="" t mtu_t
  for t in "${targets[@]}"; do
    mtu_t="$(probe_path_mtu_ipv4 "$t" "$current_mtu")"
    if [[ -n "${mtu_t:-}" ]]; then
      if [[ -z "$best_mtu" || "$mtu_t" -lt "$best_mtu" ]]; then
        best_mtu="$mtu_t"
      fi
    fi
  done

  [[ -n "${best_mtu:-}" ]] || return 0

  local proposed=$((best_mtu - MTU_HEADROOM))
  (( proposed < MTU_MIN )) && proposed=$MTU_MIN
  (( proposed >= current_mtu )) && return 0

  local old="$current_mtu"
  apply_mtu_runtime "$iface" "$proposed" || true
  if ping -4 -c 1 -W 1 1.1.1.1 >/dev/null 2>&1; then
    OPT_MTU="$proposed"
    persist_mtu_netplan
  else
    apply_mtu_runtime "$iface" "$old" || true
  fi
}

# ============================================================
# 6) IRQBALANCE
# ============================================================
setup_irqbalance() {
  [[ "$ENABLE_IRQBALANCE" -eq 1 ]] || return 0

  if ! command -v irqbalance >/dev/null 2>&1; then
    install_pkg irqbalance || return 0
  fi

  systemctl enable --now irqbalance >/dev/null 2>&1 || true
}

# ============================================================
# 7) ETHTOOL RING (FAIL-SAFE)
# ============================================================
tune_ethtool_ring_for_iface() {
  local iface="$1"
  ip link show dev "$iface" >/dev/null 2>&1 || return 0

  local out
  out="$(ethtool -g "$iface" 2>/dev/null || true)"
  [[ -n "${out:-}" ]] || return 0

  local max_rx max_tx cur_rx cur_tx
  max_rx="$(awk 'BEGIN{inmax=0} /^Pre-set maximums:/{inmax=1;next} /^Current hardware settings:/{inmax=0} inmax && $1=="RX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"
  max_tx="$(awk 'BEGIN{inmax=0} /^Pre-set maximums:/{inmax=1;next} /^Current hardware settings:/{inmax=0} inmax && $1=="TX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"
  cur_rx="$(awk 'BEGIN{incur=0} /^Current hardware settings:/{incur=1;next} incur && $1=="RX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"
  cur_tx="$(awk 'BEGIN{incur=0} /^Current hardware settings:/{incur=1;next} incur && $1=="TX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"

  [[ -n "${max_rx:-}" && -n "${max_tx:-}" ]] || return 0

  local target_rx="$max_rx"
  local target_tx="$max_tx"
  (( target_rx > RING_DESIRED )) && target_rx="$RING_DESIRED"
  (( target_tx > RING_DESIRED )) && target_tx="$RING_DESIRED"

  if [[ -n "${cur_rx:-}" && -n "${cur_tx:-}" ]]; then
    (( cur_rx >= target_rx && cur_tx >= target_tx )) && return 0
  fi

  local -a candidates=()
  local v="$target_rx"
  while (( v >= 256 )); do candidates+=("$v"); v=$((v/2)); done

  local rx_try tx_try
  for rx_try in "${candidates[@]}"; do
    for tx_try in "${candidates[@]}"; do
      if [[ -n "${cur_rx:-}" && rx_try -lt cur_rx ]]; then continue; fi
      if [[ -n "${cur_tx:-}" && tx_try -lt cur_tx ]]; then continue; fi
      if ethtool -G "$iface" rx "$rx_try" tx "$tx_try" >/dev/null 2>&1; then
        return 0
      fi
    done
  done
  return 0
}

setup_ethtool_ring() {
  [[ "$ENABLE_ETHTOOL_RING" -eq 1 ]] || return 0

  if ! command -v ethtool >/dev/null 2>&1; then
    install_pkg ethtool || return 0
  fi

  local ifaces=""
  if [[ -n "${DEFAULT_IFACE:-}" ]]; then
    ifaces="$DEFAULT_IFACE"
  else
    ifaces="$TARGET_INTERFACES"
  fi

  local i
  for i in $ifaces; do
    tune_ethtool_ring_for_iface "$i"
  done
}

# ============================================================
# 8) SWAP
# ============================================================
setup_swap() {
  [[ "$ENABLE_SWAP" -eq 1 ]] || return 0
  swap_active && return 0

  local SIZE=$((RAM_MB / 4))
  (( SIZE < 2048 )) && SIZE=2048
  (( SIZE > 16384 )) && SIZE=16384

  local FREE
  FREE=$(df -m / | awk 'NR==2{print $4}')
  (( FREE < SIZE + 2048 )) && return 0

  fallocate -l "${SIZE}M" /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count="$SIZE" status=none
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -qE '^\s*/swapfile\s' /etc/fstab || echo "/swapfile none swap sw 0 0" >> /etc/fstab
}

# ============================================================
# 9) UFW (optional)
# ============================================================
setup_ufw() {
  install_pkg ufw || true

  local SSH_PORT
  SSH_PORT="$(ss -tnlp 2>/dev/null | awk '/sshd/{print $4}' | awk -F: '{print $NF}' | head -n1 || true)"
  [[ -z "${SSH_PORT:-}" ]] && SSH_PORT=22

  ufw allow "${SSH_PORT}/tcp" >/dev/null || true
  ufw default deny incoming >/dev/null || true
  ufw default allow outgoing >/dev/null || true

  read -rp "Extra allowed ports (space separated, e.g. 80/tcp 443/tcp 51820/udp) [empty=none]: " ports
  if [[ -n "${ports:-}" ]]; then
    for p in $ports; do ufw allow "$p" >/dev/null || true; done
  fi

  ufw --force enable >/dev/null || true
  ufw status verbose || true
}

# ============================================================
# 10) ROLLBACK
# ============================================================
restore_defaults() {
  read -rp "Rollback will revert files touched by this script (latest run). Continue? [y/N]: " c
  [[ "${c:-}" != "y" ]] && return

  restore_from_latest_or_remove /etc/sysctl.d/99-vpn-opt.conf
  restore_from_latest_or_remove /etc/security/limits.d/99-vpn.conf
  restore_from_latest_or_remove /etc/systemd/system.conf
  restore_from_latest_or_remove "/etc/systemd/resolved.conf.d/99-${SCRIPT_NAME}.conf"
  restore_from_latest_or_remove /etc/netplan/99-vpn-override.yaml

  swapoff /swapfile 2>/dev/null || true
  rm -f /swapfile
  sed -i '\|^\s*/swapfile\s|d' /etc/fstab || true

  sysctl --system >/dev/null || true
  netplan apply >/dev/null 2>&1 || true
  systemctl restart systemd-resolved >/dev/null 2>&1 || true
  ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf >/dev/null 2>&1 || true

  echo -e "${GREEN}${ICON_OK} Rollback complete${NC}"
  pause
}

# ============================================================
# RICH STATUS SCREEN
# ============================================================
get_cpu_model() {
  awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo 2>/dev/null | sed 's/^[ \t]*//'
}

get_public_ip_best_effort() {
  local proto="$1" # -4 or -6
  command -v curl >/dev/null 2>&1 || { echo "N/A"; return; }
  curl -sS --max-time 2 "$proto" https://api.ipify.org 2>/dev/null || echo "N/A"
}

show_dns_status() {
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    echo -e "${GRAY}${ICON_DNS} systemd-resolved: active${NC}"
    local global_dns
    global_dns="$(resolvectl status 2>/dev/null | awk '
      /^Global/ {g=1}
      g && /DNS Servers:/ {sub("DNS Servers:",""); print; exit}
    ' | sed 's/^[ \t]*//')"
    [[ -n "${global_dns:-}" ]] && subkv "Global DNS" "$global_dns"

    # Show per-link if possible
    local link_dns
    link_dns="$(resolvectl status 2>/dev/null | awk '
      /Link [0-9]+ \(/ {link=$0}
      /DNS Servers:/ {sub("DNS Servers:",""); print link " -> " $0}
    ' | head -n 3)"
    [[ -n "${link_dns:-}" ]] && subkv "Link DNS" "$(echo "$link_dns" | tr '\n' ' | ')"
  else
    echo -e "${GRAY}${ICON_DNS} systemd-resolved: inactive${NC}"
  fi

  if [[ -f /etc/resolv.conf ]]; then
    local rc
    rc="$(grep -E '^\s*nameserver\s+' /etc/resolv.conf 2>/dev/null | awk '{print $2}' | xargs || true)"
    [[ -n "${rc:-}" ]] && subkv "/etc/resolv.conf" "$rc"
  fi
}

show_bbr_status() {
  local cc avail qdisc
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")"
  avail="$(sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | sed 's/.*=//;s/^[ \t]*//')"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")"

  if [[ "$cc" == "bbr" ]]; then
    subkv "Congestion" "${GREEN}bbr (enabled)${NC}"
  else
    subkv "Congestion" "${YELLOW}${cc}${NC}"
  fi
  subkv "Qdisc" "$qdisc"
  [[ -n "${avail:-}" ]] && subkv "Available" "$avail"

  # bbr2 availability hint
  if echo "$avail" | grep -qw bbr2; then
    subkv "Hint" "BBR2 is available (optional)"
  fi
}

show_ring_status() {
  local iface="$1"
  command -v ethtool >/dev/null 2>&1 || { subkv "Ring buffers" "ethtool not installed"; return; }

  local out
  out="$(ethtool -g "$iface" 2>/dev/null || true)"
  [[ -n "${out:-}" ]] || { subkv "Ring buffers" "Not supported on this NIC"; return; }

  local max_rx max_tx cur_rx cur_tx
  max_rx="$(awk 'BEGIN{inmax=0} /^Pre-set maximums:/{inmax=1;next} /^Current hardware settings:/{inmax=0} inmax && $1=="RX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"
  max_tx="$(awk 'BEGIN{inmax=0} /^Pre-set maximums:/{inmax=1;next} /^Current hardware settings:/{inmax=0} inmax && $1=="TX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"
  cur_rx="$(awk 'BEGIN{incur=0} /^Current hardware settings:/{incur=1;next} incur && $1=="RX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"
  cur_tx="$(awk 'BEGIN{incur=0} /^Current hardware settings:/{incur=1;next} incur && $1=="TX:"{print $2;exit}' <<<"$out" 2>/dev/null || true)"

  [[ -n "${cur_rx:-}" && -n "${cur_tx:-}" ]] && subkv "Ring current" "RX=$cur_rx  TX=$cur_tx"
  [[ -n "${max_rx:-}" && -n "${max_tx:-}" ]] && subkv "Ring max"     "RX=$max_rx  TX=$max_tx"
}

show_status() {
  clear
  title_box "${ICON_LIST} وضعیت سیستم (System Status)"

  # OS / Kernel / Uptime
  kv "${ICON_OS} OS" "$OS_NAME"
  kv "Kernel" "$KERNEL_FULL"
  kv "${ICON_TIME} Uptime" "$(uptime -p 2>/dev/null || uptime)"
  kv "Hostname" "$(hostname 2>/dev/null || echo N/A)"
  if command -v systemd-detect-virt >/dev/null 2>&1; then
    kv "Virtualization" "$(systemd-detect-virt 2>/dev/null || echo unknown)"
  fi
  hr

  # CPU / RAM
  kv "${ICON_CPU} CPU Model" "$(get_cpu_model 2>/dev/null || echo N/A)"
  kv "CPU Cores" "$(nproc 2>/dev/null || echo N/A)"
  kv "Load Avg" "$(awk '{print $1" "$2" "$3}' /proc/loadavg 2>/dev/null || echo N/A)"
  echo
  kv "${ICON_RAM} Memory" "$(free -h 2>/dev/null | awk '/Mem:/ {print $3" / "$2" used"}' || echo N/A)"
  kv "Swap" "$(free -h 2>/dev/null | awk '/Swap:/ {print $3" / "$2" used"}' || echo N/A)"
  hr

  # Network basics
  kv "${ICON_NET} Default IF" "${DEFAULT_IFACE:-unknown}"
  if [[ -n "${DEFAULT_IFACE:-}" ]]; then
    kv "${ICON_MTU} MTU" "$(get_iface_mtu "$DEFAULT_IFACE" 2>/dev/null || echo N/A)"
    local v4 v6
    v4="$(ip -4 addr show dev "$DEFAULT_IFACE" 2>/dev/null | awk '/inet /{print $2}' | xargs || true)"
    v6="$(ip -6 addr show dev "$DEFAULT_IFACE" 2>/dev/null | awk '/inet6 / && $2 !~ /^fe80/ {print $2}' | xargs || true)"
    [[ -n "${v4:-}" ]] && kv "IPv4 (IF)" "$v4" || kv "IPv4 (IF)" "N/A"
    [[ -n "${v6:-}" ]] && kv "IPv6 (IF)" "$v6" || kv "IPv6 (IF)" "N/A"
  fi

  # Public IP best-effort
  local pub4 pub6
  pub4="$(get_public_ip_best_effort -4)"
  pub6="$(get_public_ip_best_effort -6)"
  kv "Public IPv4" "$pub4"
  kv "Public IPv6" "$pub6"

  hr

  # DNS
  echo -e "${BOLD}${CYAN}${ICON_DNS} DNS Status${NC}"
  show_dns_status
  hr

  # BBR / Qdisc
  echo -e "${BOLD}${CYAN}📈 TCP / BBR Status${NC}"
  show_bbr_status
  hr

  # irqbalance
  echo -e "${BOLD}${CYAN}⚙️ CPU / IRQ${NC}"
  if systemctl is-active --quiet irqbalance 2>/dev/null; then
    subkv "irqbalance" "${GREEN}active${NC}"
  else
    subkv "irqbalance" "${YELLOW}inactive/not installed${NC}"
  fi

  # conntrack
  local ct_count ct_max
  ct_count="$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || echo N/A)"
  ct_max="$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || echo N/A)"
  subkv "Conntrack" "count=$ct_count  max=$ct_max"

  # ring buffers
  if [[ -n "${DEFAULT_IFACE:-}" ]]; then
    show_ring_status "$DEFAULT_IFACE"
  fi

  hr

  # Disk
  echo -e "${BOLD}${CYAN}${ICON_DISK} Disk${NC}"
  df -h / 2>/dev/null | awk 'NR==1{print;next}{print}' | sed "s/^/${GRAY}/;s/$/${NC}/" || true
  hr

  pause
}

# ============================================================
# OPTIMIZE FLOW with PROGRESS
# ============================================================
run_step() {
  # run_step step_number total_steps "Title" function_name
  local idx="$1" total="$2" title="$3" fn="$4"
  local pct=$(( idx * 100 / total ))

  progress_bar "$pct" "$title"
  echo -ne "\n${ICON_RUN} ${CYAN}${title}${NC} ... "
  if "$fn"; then
    echo -e "${GREEN}${ICON_OK}${NC}"
  else
    echo -e "${RED}${ICON_FAIL}${NC}"
    return 1
  fi
}

optimize_server() {
  clear
  title_box "${ICON_ROCKET} اجرای بهینه‌سازی (Optimize Server)"

  echo -e "${GRAY}${ICON_INFO} این عملیات تنظیمات شبکه/سیستم را برای VPN (Xray Reality + Hysteria2) انجام می‌دهد.${NC}"
  echo -e "${GRAY}${ICON_INFO} Backup ها در: ${BOLD}$BACKUP_DIR${NC}"
  hr

  select_dns

  clear
  title_box "${ICON_ROCKET} در حال اجرا..."

  local total=9
  local step=0

  step=$((step+1)); run_step "$step" "$total" "بررسی کرنل و BBR" check_kernel_bbr
  step=$((step+1)); run_step "$step" "$total" "اعمال DNS" apply_dns
  step=$((step+1)); run_step "$step" "$total" "Netplan Override (در صورت وجود)" apply_netplan_override
  step=$((step+1)); run_step "$step" "$total" "اعمال Sysctl (Network Tuning)" apply_sysctl
  step=$((step+1)); run_step "$step" "$total" "افزایش Limits (nofile)" apply_limits
  step=$((step+1)); run_step "$step" "$total" "بهینه‌سازی MTU (Safe)" optimize_mtu
  step=$((step+1)); run_step "$step" "$total" "فعال‌سازی irqbalance" setup_irqbalance
  step=$((step+1)); run_step "$step" "$total" "تنظیم Ring Buffer (ethtool)" setup_ethtool_ring
  step=$((step+1)); run_step "$step" "$total" "ایجاد Swap (اختیاری)" setup_swap

  progress_bar 100 "تمام شد"
  echo
  hr
  echo -e "${GREEN}${ICON_OK} بهینه‌سازی با موفقیت انجام شد.${NC}"
  echo -e "${GRAY}${ICON_INFO} Backups: ${BOLD}$BACKUP_DIR${NC}  ${GRAY}(latest -> ${BOLD}$BACKUP_LATEST_LINK${NC}${GRAY})${NC}"
  echo -e "${GRAY}${ICON_INFO} Log: ${BOLD}$LOG_FILE${NC}"
  hr
  pause
}

# ============================================================
# MENU UI
# ============================================================
print_banner() {
  echo -e "${PURPLE}${BOLD}"
  cat <<'EOF'
██╗   ██╗██████╗ ███╗   ██╗
██║   ██║██╔══██╗████╗  ██║
██║   ██║██████╔╝██╔██╗ ██║
╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║
 ╚████╔╝ ██║     ██║ ╚████║
  ╚═══╝  ╚═╝     ╚═╝  ╚═══╝
EOF
  echo -e "${NC}"
}

quick_summary_line() {
  local cc qdisc dns_hint
  cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "?")"
  qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "?")"
  dns_hint="$DNS1/$DNS2"
  echo -e "${GRAY}${ICON_INFO} cc:${NC} ${BOLD}${cc}${NC}  ${GRAY}| qdisc:${NC} ${BOLD}${qdisc}${NC}  ${GRAY}| IF:${NC} ${BOLD}${DEFAULT_IFACE:-?}${NC}"
}

while true; do
  clear
  print_banner

  echo -e "${BOLD}${CYAN} VPN SERVER OPTIMIZER — ${VERSION}${NC}   ${GRAY}(Xray Reality + Hysteria2)${NC}"
  hr
  kv "${ICON_OS} OS" "$OS_NAME"
  kv "Kernel" "$KERNEL_BASE"
  kv "${ICON_RAM} RAM" "${RAM_MB} MB"
  kv "${ICON_NET} Interfaces" "$(echo "${PHY_INTERFACES:-}" | tr '\n' ' ' | xargs)"
  hr
  quick_summary_line
  hr

  echo -e " ${GREEN}${ICON_ROCKET} [1]${NC} اجرای بهینه‌سازی کامل (Optimize)"
  echo -e " ${CYAN}${ICON_LIST} [2]${NC} نمایش وضعیت کامل سیستم (System Status)"
  echo -e " ${YELLOW}${ICON_REDO} [3]${NC} بازگردانی تغییرات (Rollback)"
  echo -e " ${BLUE}${ICON_WRENCH} [4]${NC} فعال‌سازی irqbalance"
  echo -e " ${BLUE}🔧 [5]${NC} تنظیم Ring Buffer (ethtool)"
  if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
    echo -e " ${PURPLE}${ICON_LOCK} [6]${NC} تنظیم فایروال UFW"
    echo -e " ${PURPLE}${ICON_REDO} [7]${NC} ریبوت سرور"
    echo -e " ${RED}❌ [0]${NC} خروج"
  else
    echo -e " ${PURPLE}${ICON_REDO} [6]${NC} ریبوت سرور"
    echo -e " ${RED}❌ [0]${NC} خروج"
  fi

  hr
  echo -e " ${GRAY}Creator:${NC} ${BOLD}UnknownZero${NC}   ${GRAY}Telegram ID:${NC} ${CYAN}@UnknownZero${NC}"
  hr

  read -rp "➤ انتخاب: " opt

  case "${opt:-}" in
    1) optimize_server ;;
    2) show_status ;;
    3) restore_defaults ;;
    4)
      title_box "⚙️ فعال‌سازی irqbalance"
      setup_irqbalance
      if systemctl is-active --quiet irqbalance 2>/dev/null; then
        echo -e "${GREEN}${ICON_OK} irqbalance فعال شد.${NC}"
      else
        echo -e "${YELLOW}${ICON_WARN} irqbalance فعال نشد (ممکنه روی VM اثر محدود باشه).${NC}"
      fi
      hr
      pause
      ;;
    5)
      title_box "🔧 تنظیم Ring Buffer"
      setup_ethtool_ring
      echo -e "${GREEN}${ICON_OK} تلاش برای تنظیم ring انجام شد (best effort).${NC}"
      echo -e "${GRAY}${ICON_INFO} برای مشاهده جزئیات: System Status${NC}"
      hr
      pause
      ;;
    6)
      if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
        title_box "${ICON_LOCK} UFW Firewall"
        setup_ufw
        pause
      else
        reboot
      fi
      ;;
    7)
      if [[ "$ENABLE_UFW_MENU" -eq 1 ]]; then
        reboot
      else
        echo -e "${RED}Invalid option${NC}"
        sleep 1
      fi
      ;;
    0) exit ;;
    *) echo -e "${RED}${ICON_FAIL} گزینه نامعتبر${NC}"; sleep 1 ;;
  esac
done
