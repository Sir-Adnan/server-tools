#!/bin/bash

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Root Check
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root (sudo -i).${NC}"
  exit 1
fi

# Banner Function
show_banner() {
    clear
    echo -e "${CYAN}##################################################${NC}"
    echo -e "${CYAN}#${NC} ${YELLOW}    __  ____  __________  ___    _   ______  ${NC} ${CYAN}#${NC}"
    echo -e "${CYAN}#${NC} ${YELLOW}   / / / / / /_  __/ __ \/   |  / | / / __ \ ${NC} ${CYAN}#${NC}"
    echo -e "${CYAN}#${NC} ${YELLOW}  / / / / /   / / / /_/ / /| | /  |/ / / / / ${NC} ${CYAN}#${NC}"
    echo -e "${CYAN}#${NC} ${YELLOW} / /_/ / /___/ / / _, _/ ___ |/ /|  / /_/ /  ${NC} ${CYAN}#${NC}"
    echo -e "${CYAN}#${NC} ${YELLOW} \____/_____/_/ /_/ |_/_/  |_/_/ |_/\____/   ${NC} ${CYAN}#${NC}"
    echo -e "${CYAN}#${NC} ${PURPLE}      PREMIUM VPN SERVER OPTIMIZER 2025       ${NC} ${CYAN}#${NC}"
    echo -e "${CYAN}##################################################${NC}"
}

# 1. DNS Setup (Cloudflare + Google)
setup_dns() {
    echo -e "${BLUE}[*] Configuring Smart DNS (Cloudflare + Google)...${NC}"
    INTERFACE=$(ip -o link show | awk -F': ' '$2 !~ /lo|docker|virbr/ {print $2; exit}')
    
    cat <<EOL > /etc/systemd/resolved.conf
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=1.0.0.1 8.8.4.4
Domains=~.
DNSStubListener=yes
EOL

    systemctl restart systemd-resolved
    resolvectl dns "$INTERFACE" 1.1.1.1 8.8.8.8
    resolvectl domain "$INTERFACE" "~."
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    echo -e "${GREEN}OK: DNS configured successfully.${NC}"
}

# 2. Ultra Network & BBR Tuning
setup_network() {
    echo -e "${BLUE}[*] Applying Ultra Kernel Tuning for 1000+ Users...${NC}"
    cp /etc/sysctl.conf /etc/sysctl.conf.bak
    
    cat <<EOL > /etc/sysctl.conf
# BBR Activation
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# High-Load Network Parameters
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3

# Connection Tracking for VPN
net.netfilter.nf_conntrack_max = 2000000
net.nf_conntrack_max = 2000000

# Huge Buffers for Smooth Traffic
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# Stability Settings
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 20
vm.swappiness = 10
EOL
    sysctl -p
    echo -e "${GREEN}OK: Kernel optimized for high traffic.${NC}"
}

# 3. Swap Creation
setup_swap() {
    if [ $(swapon --show | wc -l) -eq 0 ]; then
        echo -e "${BLUE}[*] Creating 2GB Swap file for stability...${NC}"
        fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        echo -e "${GREEN}OK: 2GB Swap activated.${NC}"
    else
        echo -e "${YELLOW}INFO: Swap already exists. Skipping...${NC}"
    fi
}

# 4. Cleanup & File Limits
cleanup_and_limits() {
    echo -e "${BLUE}[*] Cleaning logs and increasing file limits...${NC}"
    # File Limits
    cat <<EOL > /etc/security/limits.conf
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
EOL
    # Journal Cleanup
    journalctl --vacuum-size=50M
    apt-get autoremove -y > /dev/null
    echo -e "${GREEN}OK: System cleaned.${NC}"
}

# Main Logic
while true; do
    show_banner
    echo -e "${CYAN}Available Options:${NC}"
    echo -e "${GREEN}1)${NC} Full Optimization ${YELLOW}(Highly Recommended)${NC}"
    echo -e "${GREEN}2)${NC} Clean Logs & Free Space"
    echo -e "${GREEN}3)${NC} Show Current Status"
    echo -e "${RED}E)${NC} Exit"
    echo -e "${CYAN}--------------------------------------------------${NC}"
    read -p "Select an option: " choice

    case $choice in
        1)
            setup_dns
            setup_network
            setup_swap
            cleanup_and_limits
            echo -e "\n${GREEN}ALL PROCESSES COMPLETED!${NC}"
            echo -e "${YELLOW}Please reboot your server: ${NC}reboot"
            exit 0
            ;;
        2)
            cleanup_and_limits
            read -p "Done. Press Enter to return..."
            ;;
        3)
            show_banner
            echo -e "${BLUE}--- System Status ---${NC}"
            echo -e "${CYAN}TCP BBR:${NC} $(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')"
            echo -e "${CYAN}Active DNS:${NC} $(resolvectl status | grep 'Current DNS Server' | head -n 1 | awk '{print $4}')"
            echo -e "${CYAN}Swap Usage:${NC} $(free -h | grep Swap | awk '{print $3 "/" $2}')"
            echo -e "${CYAN}TCP Connections:${NC} $(ss -ant | wc -l)"
            read -p "Press Enter to return..."
            ;;
        E|e)
            echo -e "${GREEN}Good luck! Goodbye.${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid option!${NC}"
            sleep 1
            ;;
    esac
done
