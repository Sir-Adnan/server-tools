#!/bin/bash

# ==================================================
# VPN SERVER OPTIMIZER - V6 (STABLE & SMART)
# Optimized for: Xray, Marzban, Sing-box
# Features: Idempotent, Kernel Checks, Anti-Leak
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
MAIN_IF=$(ip route | awk '/default/ {print $5}' | head -n1)

# -------- Progress --------
progress() {
    echo -ne " ${BLUE}[Processing]${NC} "
    for i in {1..15}; do echo -ne "▓"; sleep 0.03; done
    echo -e " ${GREEN}[OK]${NC}"
}

# =========================
# 0. KERNEL CHECK (NEW)
# =========================
check_bbr_support() {
    echo -e "${YELLOW}➤ Checking Kernel BBR Support...${NC}"
    
    # Try to load BBR module if not loaded
    modprobe tcp_bbr &>/dev/null

    if sysctl net.ipv4.tcp_available_congestion_control | grep -q bbr; then
        echo -e "${GREEN}   BBR is supported and ready.${NC}"
        BBR_ALGO="bbr"
        QDISC_ALGO="fq"
    else
        echo -e "${RED}   Warning: BBR not supported on this Kernel!${NC}"
        echo -e "${YELLOW}   Fallback to CUBIC to prevent errors.${NC}"
        BBR_ALGO="cubic"
        QDISC_ALGO="fq_codel"
    fi
}

# =========================
# 1. SYSCTL OPTIMIZATION
# =========================
setup_sysctl() {
    echo -e "${YELLOW}➤ Applying Kernel & Network Optimization...${NC}"

    # Safe Conntrack Limit
    if [[ $RAM_MB -le 2048 ]]; then
        CONNTRACK=131072
    elif [[ $RAM_MB -le 4096 ]]; then
        CONNTRACK=262144
    else
        CONNTRACK=524288
    fi

cat > /etc/sysctl.d/99-vpn-production.conf <<EOF
# --- Congestion Control (Dynamic) ---
net.core.default_qdisc = $QDISC_ALGO
net.ipv4.tcp_congestion_control = $BBR_ALGO

# --- Core Network ---
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535

# --- TCP Behavior ---
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_retries2 = 8

# --- Keepalive (Xray Optimized) ---
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5

# --- Buffers (Balanced) ---
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# --- Conntrack & Routing ---
net.netfilter.nf_conntrack_max = $CONNTRACK
net.ipv4.ip_forward = 1
vm.swappiness = 10
fs.file-max = 1000000
EOF

    sysctl --system > /dev/null 2>&1
    progress
}

# =========================
# 2. DNS BLOCKER (SMART)
# =========================
block_isp_dns() {
    echo -e "${YELLOW}➤ Blocking ISP DNS (DHCP Override)...${NC}"
    
    # 1. Smart Update for dhclient.conf (Idempotent)
    if [ -f /etc/dhcp/dhclient.conf ]; then
        if ! grep -q "supersede domain-name-servers 1.1.1.1, 8.8.8.8;" /etc/dhcp/dhclient.conf; then
            # Clean old lines just in case
            sed -i '/supersede domain-name-servers/d' /etc/dhcp/dhclient.conf
            echo 'supersede domain-name-servers 1.1.1.1, 8.8.8.8;' >> /etc/dhcp/dhclient.conf
            echo -e "${GREEN}   Updated dhclient.conf${NC}"
        else
            echo -e "${GREEN}   dhclient.conf already configured. Skipped.${NC}"
        fi
    fi

    # 2. Configure Systemd-Resolved
cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=1.0.0.1 8.8.4.4
Domains=~.
DNSStubListener=no
EOF

    # 3. Force Link-Specific DNS (Runtime)
    if [ -n "$MAIN_IF" ]; then
        resolvectl dns "$MAIN_IF" 1.1.1.1 8.8.8.8 2>/dev/null
        resolvectl domain "$MAIN_IF" "~." 2>/dev/null
    fi

    # 4. Unlock resolv.conf
    if command -v chattr &> /dev/null; then
        chattr -i /etc/resolv.conf > /dev/null 2>&1
    fi
    
    systemctl restart systemd-resolved
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    
    progress
}

# =========================
# 3. LIMITS (SMART)
# =========================
setup_limits() {
    echo -e "${YELLOW}➤ Verifying File Limits...${NC}"

    # Overwrite limits.d file (Safe idempotent method)
cat > /etc/security/limits.d/99-vpn.conf <<EOF
* soft nofile 262144
* hard nofile 262144
root soft nofile 262144
root hard nofile 262144
EOF

    # Check system.conf before appending
    if ! grep -q "DefaultLimitNOFILE=262144" /etc/systemd/system.conf; then
        sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf
        echo "DefaultLimitNOFILE=262144" >> /etc/systemd/system.conf
    fi
    
    systemctl daemon-reexec > /dev/null 2>&1
    progress
}

# =========================
# 4. SWAP MANAGER (SAFE)
# =========================
setup_swap() {
    # Check if swap is ACTIVE
    if swapon --show | grep -q swap; then
        echo -e "${GREEN}   Swap is active. Skipped.${NC}"
        return
    fi
    
    # Check if swapfile EXISTS but not mounted
    if [ -f /swapfile ]; then
        echo -e "${YELLOW}   Swapfile exists but not active. Enabling...${NC}"
        swapon /swapfile
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
    
    # Check fstab before appending
    if ! grep -q "/swapfile none swap sw 0 0" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    progress
}

# =========================
# 5. EXTRAS
# =========================
setup_extra() {
    echo -e "${YELLOW}➤ Syncing Time & SSH...${NC}"
    timedatectl set-ntp true

    if [ -f /etc/ssh/sshd_config ]; then
        if ! grep -q "UseDNS no" /etc/ssh/sshd_config; then
            cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
            sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
            sed -i 's/UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
            systemctl restart ssh
        fi
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
# MAIN MENU
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

    echo -e "${BOLD}${GREEN}   VPN SERVER OPTIMIZER — V6 STABLE${NC}"
    echo -e "${YELLOW}   Idempotent • BBR Check • Anti-Leak${NC}"
    echo -e "${CYAN}   Creator Telegram ID : @UnknownZero${NC}"
    echo
    echo -e "${BLUE}────────────────────────────────────────${NC}"
    echo -e "${CYAN} OS:${NC} $OS_NAME     ${CYAN}RAM:${NC} ${RAM_MB} MB"
    echo -e "${CYAN} IF:${NC} $MAIN_IF"
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
            check_bbr_support # Check first
            block_isp_dns
            setup_sysctl
            setup_limits
            setup_swap
            setup_extra
            cleanup
            echo -e "\n${GREEN}✔ Optimization Completed Successfully${NC}"
            echo -e "${YELLOW}⚠ Reboot recommended.${NC}"
            read -p "Press Enter to return..."
            ;;
        2)
            clear
            echo -e "${CYAN}--- System Status ---${NC}"
            echo "Queue Algo:   $(sysctl net.core.default_qdisc | awk '{print $3}')"
            echo "Congestion:   $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
            echo "Open Files:   $(ulimit -n)"
            echo "Swap Usage:   $(free -h | awk '/Swap/ {print $3 " / " $2}')"
            
            echo -e "\n${CYAN}--- DNS Check ---${NC}"
            echo -e "${BOLD}Global:${NC} $(resolvectl status | grep 'DNS Servers' | head -n1 | awk '{$1=$2=""; print $0}')"
            if [ -n "$MAIN_IF" ]; then
                echo -e "${BOLD}Interface ($MAIN_IF):${NC} $(resolvectl status $MAIN_IF | grep 'DNS Servers' | awk '{$1=$2=""; print $0}')"
            fi
            echo
            read -p "Press Enter to return..."
            ;;
        3) reboot ;;
        0) exit ;;
        *) echo "Invalid option"; sleep 1 ;;
    esac
done
