#!/bin/bash

# ==================================================
# VPN SERVER OPTIMIZER - V4.5 PRODUCTION (FIXED)
# Optimized for: Xray, Marzban, Sing-box
# Fix: Forces Global DNS Priority (Prevents Leak)
# ==================================================

# -------- Colors --------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# -------- Root Check --------
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[!] Please run as root (sudo -i)${NC}"
  exit 1
fi

# -------- System Info --------
RAM_MB=$(free -m | awk '/Mem:/ {print $2}')
OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')

# -------- Progress --------
progress() {
    echo -ne " ${BLUE}[Processing]${NC} "
    for i in {1..15}; do echo -ne "▓"; sleep 0.03; done
    echo -e " ${GREEN}[OK]${NC}"
}

# =========================
# 1. SYSCTL OPTIMIZATION
# =========================
setup_sysctl() {
    echo -e "${YELLOW}➤ Applying Kernel & Network Optimization...${NC}"

    if [[ $RAM_MB -le 2048 ]]; then
        CONNTRACK=131072
    elif [[ $RAM_MB -le 4096 ]]; then
        CONNTRACK=262144
    else
        CONNTRACK=524288
    fi

cat > /etc/sysctl.d/99-vpn-production.conf <<EOF
# Queue & Congestion
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Core Network
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535

# TCP Behavior
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_retries2 = 8

# Keepalive (Xray/V2Ray)
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5

# Buffers (1Gbps)
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Conntrack & System
net.netfilter.nf_conntrack_max = $CONNTRACK
net.ipv4.ip_forward = 1
vm.swappiness = 10
fs.file-max = 1000000
EOF

    sysctl --system > /dev/null 2>&1
    progress
}

# =========================
# 2. DNS CONFIG (FIXED)
# =========================
setup_dns() {
    echo -e "${YELLOW}➤ Configuring DNS (Forcing Global Priority)...${NC}"

    # CRITICAL FIX: 'Domains=~.' forces systemd to use these DNS servers 
    # for ALL traffic, overriding the Interface/DHCP DNS.
cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=1.0.0.1 8.8.4.4
Domains=~.
DNSStubListener=no
EOF

    # Fix: Unlock resolv.conf if provider locked it
    if command -v chattr &> /dev/null; then
        chattr -i /etc/resolv.conf > /dev/null 2>&1
    fi

    systemctl restart systemd-resolved
    
    # Force symlink to uplink file (Not stub) to bypass local caching issues
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    progress
}

# =========================
# 3. LIMITS
# =========================
setup_limits() {
    echo -e "${YELLOW}➤ Increasing File Limits...${NC}"

cat > /etc/security/limits.d/99-vpn.conf <<EOF
* soft nofile 262144
* hard nofile 262144
root soft nofile 262144
root hard nofile 262144
EOF

    sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf
    echo "DefaultLimitNOFILE=262144" >> /etc/systemd/system.conf
    systemctl daemon-reexec > /dev/null 2>&1
    progress
}

# =========================
# 4. SWAP MANAGER
# =========================
setup_swap() {
    if swapon --show | grep -q swap; then
        echo -e "${GREEN}   Swap already exists. Skipped.${NC}"
        return
    fi

    if [[ $RAM_MB -le 2048 ]]; then
        SWAP_SIZE=2G
    elif [[ $RAM_MB -le 4096 ]]; then
        SWAP_SIZE=4G
    else
        echo -e "${GREEN}   High RAM detected. Swap skipped.${NC}"
        return
    fi

    echo -e "${YELLOW}➤ Creating Swap ($SWAP_SIZE)...${NC}"
    fallocate -l $SWAP_SIZE /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$(( ${SWAP_SIZE%G} * 1024 ))
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null
    swapon /swapfile
    echo "/swapfile none swap sw 0 0" >> /etc/fstab
    progress
}

# =========================
# 5. EXTRAS
# =========================
setup_extra() {
    echo -e "${YELLOW}➤ Syncing Time & Optimizing SSH...${NC}"
    timedatectl set-ntp true

    if [ -f /etc/ssh/sshd_config ]; then
        # Backup before edit
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
        sed -i 's/UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
        systemctl restart ssh
    fi
    progress
}

cleanup() {
    echo -e "${YELLOW}➤ Cleaning System...${NC}"
    journalctl --vacuum-size=50M > /dev/null 2>&1
    apt-get autoremove -y > /dev/null 2>&1
    progress
}

# =========================
# MAIN MENU (PRO UI)
# =========================
while true; do
    clear
    echo -e "${CYAN}"
    echo " ██╗   ██╗██████╗ ███╗   ██╗"
    echo " ██║   ██║██╔══██╗████╗  ██║"
    echo " ██║   ██║██████╔╝██╔██╗ ██║"
    echo " ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║"
    echo "  ╚████╔╝ ██║     ██║ ╚████║"
    echo "   ╚═══╝  ╚═╝     ╚═╝  ╚═══╝"
    echo -e "${NC}"

    echo -e "${BOLD}${GREEN}   VPN SERVER OPTIMIZER — V4.5 PRODUCTION${NC}"
    echo -e "${YELLOW}   Xray • Marzban • Sing-box${NC}"
    echo -e "${CYAN}   Creator Telegram ID : @UnknownZero${NC}"
    echo
    echo -e "${BLUE}────────────────────────────────────────${NC}"
    echo -e "${CYAN} OS:${NC} $OS_NAME     ${CYAN}RAM:${NC} ${RAM_MB} MB"
    echo -e "${BLUE}────────────────────────────────────────${NC}"
    echo

    echo -e " ${GREEN}[1]${NC} 🚀 Start Full Optimization"
    echo -e " ${CYAN}[2]${NC} 📊 System Status"
    echo -e " ${CYAN}[3]${NC} 🔄 Reboot Server"
    echo
    echo -e " ${RED}[0]${NC} ❌ Exit"
    echo
    read -p " ➤ Select option: " opt

    case $opt in
        1)
            setup_dns
            setup_sysctl
            setup_limits
            setup_swap
            setup_extra
            cleanup
            echo -e "\n${GREEN}✔ Optimization Completed Successfully${NC}"
            echo -e "${YELLOW}⚠ Reboot required for changes to take effect.${NC}"
            read -p "Press Enter to return..."
            ;;
        2)
            clear
            echo -e "${CYAN}--- System Status ---${NC}"
            echo "Queue Algo:   $(sysctl net.core.default_qdisc | awk '{print $3}')"
            echo "Congestion:   $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
            echo "Open Files:   $(ulimit -n)"
            echo "Swap Usage:   $(free -h | awk '/Swap/ {print $3 " / " $2}')"
            echo "Time Sync:    $(timedatectl | grep 'synchronized' | awk '{print $4}')"
            echo
            read -p "Press Enter to return..."
            ;;
        3) reboot ;;
        0) exit ;;
        *) echo "Invalid option"; sleep 1 ;;
    esac
done
