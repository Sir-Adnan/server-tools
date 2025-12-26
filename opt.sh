#!/bin/bash

# ==================================================
# VPN SERVER OPTIMIZER - V11 (INFRASTRUCTURE EDITION)
# Features: Dynamic Swap %, Multi-Interface Netplan, Time-based Logs
# ==================================================

# -------- Configuration --------
LOG_FILE="/var/log/vpn_optimizer.log"
BACKUP_DIR="/root/vpn_backups_$(date +%F_%H-%M)"
MAX_LOG_SIZE=$((5 * 1024 * 1024))   # 5MB limit per file
MAX_LOG_COUNT=10                    # Keep last 10 files
LOG_RETENTION_DAYS=30               # Delete logs older than 30 days

# -------- Colors --------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# -------- Logger & Rotation --------
rotate_logs() {
    # 1. Size-based Rotation
    if [ -f "$LOG_FILE" ]; then
        FILE_SIZE=$(stat -c%s "$LOG_FILE")
        if [ "$FILE_SIZE" -ge "$MAX_LOG_SIZE" ]; then
            TIMESTAMP=$(date +%F-%H%M)
            mv "$LOG_FILE" "$LOG_FILE.$TIMESTAMP.old"
            gzip "$LOG_FILE.$TIMESTAMP.old"
            touch "$LOG_FILE"
        fi
    fi

    # 2. Count-based Cleanup (Keep top N)
    ls -t $LOG_FILE.*.gz 2>/dev/null | tail -n +$((MAX_LOG_COUNT + 1)) | xargs -r rm --

    # 3. Time-based Cleanup (Older than N days)
    find $(dirname "$LOG_FILE") -name "$(basename "$LOG_FILE")*.gz" -mtime +$LOG_RETENTION_DAYS -delete
}

rotate_logs
exec > >(tee -i "$LOG_FILE") 2>&1

# -------- Helpers --------
log_msg() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1"; }
backup_file() {
    local file_path=$1
    if [ -f "$file_path" ]; then
        mkdir -p "$BACKUP_DIR"
        cp "$file_path" "$BACKUP_DIR/$(basename "$file_path").bak"
        log_msg "Backup created: $file_path"
    fi
}

vercomp() {
    if [[ $1 == $2 ]]; then return 0; fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++)); do ver1[i]=0; done
    for ((i=0; i<${#ver1[@]}; i++)); do
        if [[ -z ${ver2[i]} ]]; then ver2[i]=0; fi
        if ((10#${ver1[i]} > 10#${ver2[i]})); then return 1; fi
        if ((10#${ver1[i]} < 10#${ver2[i]})); then return 2; fi
    done
    return 0
}

# -------- Root Check --------
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[!] Please run as root (sudo -i)${NC}"
  exit 1
fi

# -------- System Info --------
RAM_MB=$(free -m | awk '/Mem:/ {print $2}')
OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
# Detect ALL physical interfaces (excluding lo, docker, veth, etc.)
PHY_INTERFACES=$(ls /sys/class/net | grep -vE 'lo|docker|veth|tun|wg|br-|cali')
KERNEL_FULL=$(uname -r)
KERNEL_BASE=$(echo "$KERNEL_FULL" | cut -d- -f1)

# =========================
# 1. KERNEL CHECK
# =========================
check_kernel_bbr() {
    echo -e "${YELLOW}➤ Checking Kernel & BBR...${NC}"
    log_msg "Kernel: $KERNEL_FULL"

    vercomp "$KERNEL_BASE" "4.9"
    if [[ $? == 2 ]]; then
        echo -e "${RED}   WARNING: Kernel < 4.9. BBR impossible.${NC}"
        BBR_ALGO="cubic"
        QDISC_ALGO="fq_codel"
    else
        modprobe tcp_bbr &>/dev/null
        if sysctl net.ipv4.tcp_available_congestion_control | grep -q bbr; then
            echo -e "${GREEN}   BBR is supported.${NC}"
            BBR_ALGO="bbr"
            QDISC_ALGO="fq"
        else
            echo -e "${RED}   BBR module missing. Using Cubic.${NC}"
            BBR_ALGO="cubic"
            QDISC_ALGO="fq_codel"
        fi
    fi
}

# =========================
# 2. SYSCTL OPTIMIZATION
# =========================
setup_sysctl() {
    echo -e "${YELLOW}➤ Applying Kernel Optimizations...${NC}"
    
    # Dynamic Conntrack
    if [[ $RAM_MB -le 1024 ]]; then CONNTRACK=65536
    elif [[ $RAM_MB -le 4096 ]]; then CONNTRACK=262144
    else CONNTRACK=$((RAM_MB * 64)); fi # High RAM scaling

    # Cap Conntrack at 2 Million to prevent RAM exhaustion on massive servers
    if [[ $CONNTRACK -gt 2000000 ]]; then CONNTRACK=2000000; fi

    backup_file "/etc/sysctl.d/99-vpn-opt.conf"

cat > /etc/sysctl.d/99-vpn-opt.conf <<EOF
net.core.default_qdisc = $QDISC_ALGO
net.ipv4.tcp_congestion_control = $BBR_ALGO
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.netfilter.nf_conntrack_max = $CONNTRACK
net.ipv4.ip_forward = 1
vm.swappiness = 10
fs.file-max = 2097152
EOF

    sysctl --system > /dev/null 2>&1
    log_msg "Sysctl applied. Algo: $BBR_ALGO | Conntrack: $CONNTRACK"
}

# =========================
# 3. DNS & MULTI-INTERFACE NETPLAN
# =========================
setup_dns_safe() {
    echo -e "${YELLOW}➤ Configuring DNS...${NC}"

    # 1. Netplan for ALL Physical Interfaces
    if [ -d /etc/netplan ]; then
        echo -e "${BLUE}   Configuring Netplan for: $PHY_INTERFACES${NC}"
        backup_file "/etc/netplan/99-vpn-override.yaml"
        
        # Start YAML content
        echo "network:" > /etc/netplan/99-vpn-override.yaml
        echo "  version: 2" >> /etc/netplan/99-vpn-override.yaml
        echo "  ethernets:" >> /etc/netplan/99-vpn-override.yaml
        
        # Loop through all detected interfaces
        for iface in $PHY_INTERFACES; do
            echo "    $iface:" >> /etc/netplan/99-vpn-override.yaml
            echo "      dhcp4-overrides:" >> /etc/netplan/99-vpn-override.yaml
            echo "        use-dns: false" >> /etc/netplan/99-vpn-override.yaml
            echo "      dhcp6-overrides:" >> /etc/netplan/99-vpn-override.yaml
            echo "        use-dns: false" >> /etc/netplan/99-vpn-override.yaml
        done
        
        chmod 600 /etc/netplan/99-vpn-override.yaml
        
        if command -v netplan &>/dev/null; then
            if netplan generate > /dev/null 2>&1; then
                netplan apply > /dev/null 2>&1
                log_msg "Netplan applied for interfaces: $PHY_INTERFACES"
            else
                echo -e "${RED}   Netplan Generation Error! Reverting...${NC}"
                rm -f /etc/netplan/99-vpn-override.yaml
                log_msg "ERROR: Netplan generation failed."
            fi
        fi
    fi

    # 2. Systemd-Resolved
    if lsattr /etc/resolv.conf 2>/dev/null | grep -q "i"; then
        chattr -i /etc/resolv.conf
    fi
    backup_file "/etc/systemd/resolved.conf"
    
    mkdir -p /etc/systemd/resolved.conf.d/
cat > /etc/systemd/resolved.conf <<EOF
[Resolve]
DNS=1.1.1.1 8.8.8.8
FallbackDNS=1.0.0.1 8.8.4.4
Domains=~.
DNSStubListener=no
EOF
    
    systemctl restart systemd-resolved
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    
    # 3. Runtime Force (Flush all interfaces)
    for iface in $PHY_INTERFACES; do
        resolvectl revert "$iface" 2>/dev/null
        resolvectl dns "$iface" 1.1.1.1 8.8.8.8 2>/dev/null
        resolvectl domain "$iface" "~." 2>/dev/null
    done
}

# =========================
# 4. DYNAMIC RATIO SWAP
# =========================
setup_swap() {
    if swapon --show | grep -q swap; then
        echo -e "${GREEN}   Swap is active. Skipped.${NC}"
        return
    fi

    # 1. Calculate Target Swap (25% of RAM)
    # Using integer arithmetic (MB)
    TARGET_SWAP_MB=$((RAM_MB / 4))

    # 2. Apply Constraints (Min 2GB, Max 16GB)
    if [ "$TARGET_SWAP_MB" -lt 2048 ]; then
        TARGET_SWAP_MB=2048
    elif [ "$TARGET_SWAP_MB" -gt 16384 ]; then
        TARGET_SWAP_MB=16384
    fi

    # 3. Check Disk Space Safety (Require Swap size + 2GB Buffer)
    FREE_DISK_KB=$(df -k / | awk 'NR==2 {print $4}')
    REQUIRED_SPACE_KB=$(( (TARGET_SWAP_MB + 2048) * 1024 ))

    if [ "$FREE_DISK_KB" -lt "$REQUIRED_SPACE_KB" ]; then
        echo -e "${RED}   Not enough disk space for ${TARGET_SWAP_MB}MB Swap!${NC}"
        log_msg "ERROR: Low disk space for Swap calculation."
        return
    fi

    echo -e "${YELLOW}➤ Creating Swap (${TARGET_SWAP_MB}MB)...${NC}"
    fallocate -l "${TARGET_SWAP_MB}M" /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=$TARGET_SWAP_MB
    chmod 600 /swapfile
    mkswap /swapfile > /dev/null
    swapon /swapfile
    
    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
    log_msg "Swap created: ${TARGET_SWAP_MB}MB"
}

# =========================
# 5. LIMITS & EXTRAS
# =========================
setup_limits() {
    backup_file "/etc/security/limits.d/99-vpn.conf"
cat > /etc/security/limits.d/99-vpn.conf <<EOF
* soft nofile 500000
* hard nofile 500000
root soft nofile 500000
root hard nofile 500000
EOF
    # Append to system.conf if not present
    if ! grep -q "DefaultLimitNOFILE=500000" /etc/systemd/system.conf; then
        backup_file "/etc/systemd/system.conf"
        sed -i '/DefaultLimitNOFILE/d' /etc/systemd/system.conf
        echo "DefaultLimitNOFILE=500000" >> /etc/systemd/system.conf
        systemctl daemon-reexec
    fi
}

setup_extra() {
    timedatectl set-ntp true
    if [ -f /etc/ssh/sshd_config ]; then
        if ! grep -q "UseDNS no" /etc/ssh/sshd_config; then
            backup_file "/etc/ssh/sshd_config"
            sed -i 's/#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
            sed -i 's/UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
            systemctl restart ssh
        fi
    fi
}

cleanup() {
    echo -e "${YELLOW}➤ Cleaning Logs...${NC}"
    journalctl --vacuum-size=50M > /dev/null 2>&1
    apt-get autoremove -y > /dev/null 2>&1
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
    echo -e "${BOLD}${GREEN}   VPN SERVER OPTIMIZER — V11 INFRA${NC}"
    echo -e "${YELLOW}   Multi-IF Netplan • % Based Swap • Log Age${NC}
    echo -e "${YELLOW}   Idempotent • BBR Check • Anti-Leak${NC}"
    echo -e "${CYAN}   Creator Telegram ID : @UnknownZero${NC}"
    echo -e "${CYAN}==============================================${NC}""
    echo -e "${CYAN}==============================================${NC}"
    echo -e " ${CYAN}OS:${NC} $OS_NAME | ${CYAN}Kernel:${NC} $KERNEL_BASE"
    echo -e " ${CYAN}RAM:${NC} ${RAM_MB}MB | ${CYAN}Interfaces:${NC} $(echo $PHY_INTERFACES | tr '\n' ' ')"
    echo
    echo -e " ${GREEN}[1]${NC} 🚀 Run Optimization"
    echo -e " ${CYAN}[2]${NC} 📊 System Status"
    echo -e " ${CYAN}[3]${NC} 🔄 Reboot"
    echo -e " ${RED}[0]${NC} ❌ Exit"
    echo
    read -p " Select: " opt

    case $opt in
        1)
            mkdir -p "$BACKUP_DIR"
            log_msg "--- Start V11 Optimization ---"
            check_kernel_bbr
            setup_dns_safe
            setup_sysctl
            setup_limits
            setup_swap
            setup_extra
            cleanup
            echo -e "\n${GREEN}✔ DONE! Backups at: $BACKUP_DIR${NC}"
            read -p "Press Enter..."
            ;;
        2)
            clear
            echo -e "${CYAN}--- Swap ---${NC}"
            free -h | grep Swap
            echo -e "\n${CYAN}--- DNS Global ---${NC}"
            resolvectl status | grep -A 2 "Global"
            echo -e "\n${CYAN}--- Netplan Override ---${NC}"
            [ -f /etc/netplan/99-vpn-override.yaml ] && cat /etc/netplan/99-vpn-override.yaml || echo "None"
            echo
            read -p "Press Enter..."
            ;;
        3) reboot ;;
        0) exit ;;
        *) echo "Invalid"; sleep 1 ;;
    esac
done
