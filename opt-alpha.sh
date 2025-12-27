#!/bin/bash

# ==================================================
# VPN SERVER OPTIMIZER - V12 (ADVANCED EDITION)
# Features: Dynamic Swap, Multi-Interface Netplan, Custom DNS, UFW Manager, Restore
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
    if [ -f "$LOG_FILE" ]; then
        FILE_SIZE=$(stat -c%s "$LOG_FILE")
        if [ "$FILE_SIZE" -ge "$MAX_LOG_SIZE" ]; then
            TIMESTAMP=$(date +%F-%H%M)
            mv "$LOG_FILE" "$LOG_FILE.$TIMESTAMP.old"
            gzip "$LOG_FILE.$TIMESTAMP.old"
            touch "$LOG_FILE"
        fi
    fi
    ls -t $LOG_FILE.*.gz 2>/dev/null | tail -n +$((MAX_LOG_COUNT + 1)) | xargs -r rm --
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
    
    if [[ $RAM_MB -le 1024 ]]; then CONNTRACK=65536
    elif [[ $RAM_MB -le 4096 ]]; then CONNTRACK=262144
    else CONNTRACK=$((RAM_MB * 64)); fi
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
    local P_DNS=$1
    local S_DNS=$2
    echo -e "${YELLOW}➤ Configuring DNS to ${P_DNS} and ${S_DNS}...${NC}"

    # 1. Netplan for ALL Physical Interfaces
    if [ -d /etc/netplan ]; then
        echo -e "${BLUE}   Configuring Netplan for: $PHY_INTERFACES${NC}"
        backup_file "/etc/netplan/99-vpn-override.yaml"
        
        echo "network:" > /etc/netplan/99-vpn-override.yaml
        echo "  version: 2" >> /etc/netplan/99-vpn-override.yaml
        echo "  ethernets:" >> /etc/netplan/99-vpn-override.yaml
        
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
                log_msg "Netplan applied."
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
DNS=$P_DNS $S_DNS
FallbackDNS=1.1.1.1 8.8.8.8
Domains=~.
DNSStubListener=no
EOF
    
    systemctl restart systemd-resolved
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
    
    # 3. Runtime Force
    for iface in $PHY_INTERFACES; do
        resolvectl revert "$iface" 2>/dev/null
        resolvectl dns "$iface" $P_DNS $S_DNS 2>/dev/null
        resolvectl domain "$iface" "~." 2>/dev/null
    done
}

select_dns_menu() {
    echo -e "\n${CYAN}--- Select DNS Provider ---${NC}"
    echo -e " ${GREEN}[1]${NC} Cloudflare (Recommended) [1.1.1.1, 1.0.0.1]"
    echo -e " ${GREEN}[2]${NC} Google Public DNS      [8.8.8.8, 8.8.4.4]"
    echo -e " ${GREEN}[3]${NC} OpenDNS                [208.67.222.222, 208.67.220.220]"
    echo -e " ${GREEN}[4]${NC} Custom Input           [User Defined]"
    read -p " Select DNS: " dns_opt
    
    case $dns_opt in
        1) DNS1="1.1.1.1"; DNS2="1.0.0.1" ;;
        2) DNS1="8.8.8.8"; DNS2="8.8.4.4" ;;
        3) DNS1="208.67.222.222"; DNS2="208.67.220.220" ;;
        4) 
           read -p " Enter Primary DNS IP: " DNS1
           read -p " Enter Secondary DNS IP: " DNS2
           ;;
        *) echo -e "${RED}Invalid selection. Using Cloudflare.${NC}"; DNS1="1.1.1.1"; DNS2="1.0.0.1" ;;
    esac
}

# =========================
# 4. DYNAMIC RATIO SWAP
# =========================
setup_swap() {
    if swapon --show | grep -q swap; then
        echo -e "${GREEN}   Swap is active. Skipped.${NC}"
        return
    fi

    TARGET_SWAP_MB=$((RAM_MB / 4))
    if [ "$TARGET_SWAP_MB" -lt 2048 ]; then TARGET_SWAP_MB=2048; fi
    if [ "$TARGET_SWAP_MB" -gt 16384 ]; then TARGET_SWAP_MB=16384; fi

    FREE_DISK_KB=$(df -k / | awk 'NR==2 {print $4}')
    REQUIRED_SPACE_KB=$(( (TARGET_SWAP_MB + 2048) * 1024 ))

    if [ "$FREE_DISK_KB" -lt "$REQUIRED_SPACE_KB" ]; then
        echo -e "${RED}   Not enough disk space for Swap!${NC}"
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

# =========================
# 6. UFW FIREWALL MANAGER
# =========================
setup_ufw() {
    echo -e "${YELLOW}➤ Installing and Configuring UFW...${NC}"
    apt-get update -y > /dev/null 2>&1
    apt-get install ufw -y > /dev/null 2>&1

    echo -e "${BLUE}   Resetting UFW rules...${NC}"
    ufw --force reset > /dev/null 2>&1
    ufw default deny incoming
    ufw default allow outgoing

    # SSH Handling
    read -p " Enter your SSH Port (Default 22): " ssh_port
    ssh_port=${ssh_port:-22}
    ufw allow "$ssh_port"/tcp
    echo -e "${GREEN}   Allowed SSH Port: $ssh_port${NC}"

    # Custom Ports
    echo -e "${CYAN}   Enter other ports to open (e.g. 443, 80, 2053). Type 'done' to finish.${NC}"
    while true; do
        read -p "   Port to open: " cport
        if [[ "$cport" == "done" ]]; then
            break
        fi
        if [[ "$cport" =~ ^[0-9]+$ ]]; then
            ufw allow "$cport"
            echo -e "   Opened port: $cport"
        else
            echo -e "${RED}   Invalid port number.${NC}"
        fi
    done

    echo -e "${YELLOW}➤ Enabling UFW...${NC}"
    echo "y" | ufw enable
    echo -e "${GREEN}✔ UFW is Active and Enabled!${NC}"
}

# =========================
# 7. RESTORE DEFAULTS
# =========================
restore_defaults() {
    echo -e "${RED}➤ WARNING: RESTORING DEFAULTS${NC}"
    echo -e "${YELLOW}This will delete custom Sysctl, Netplan, Limits, and Swap configs.${NC}"
    read -p "Are you sure? (y/n): " confirm
    if [[ "$confirm" != "y" ]]; then return; fi

    # 1. Sysctl
    rm -f /etc/sysctl.d/99-vpn-opt.conf
    sysctl --system > /dev/null 2>&1
    echo -e "   - Sysctl reverted"

    # 2. Limits
    rm -f /etc/security/limits.d/99-vpn.conf
    echo -e "   - Limits reverted"

    # 3. Swap
    if grep -q "/swapfile" /etc/fstab; then
        swapoff /swapfile 2>/dev/null
        sed -i '/\/swapfile/d' /etc/fstab
        rm -f /swapfile
        echo -e "   - Swap removed"
    fi

    # 4. Netplan
    if [ -f /etc/netplan/99-vpn-override.yaml ]; then
        rm -f /etc/netplan/99-vpn-override.yaml
        netplan apply > /dev/null 2>&1
        echo -e "   - Netplan reverted"
    fi

    # 5. DNS
    if [ -f /etc/systemd/resolved.conf ]; then
        rm -f /etc/systemd/resolved.conf
        systemctl restart systemd-resolved
        echo -e "   - DNS Config reverted"
    fi

    echo -e "${GREEN}✔ System restored to near-default state.${NC}"
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
    echo -e "${BOLD}${GREEN}   VPN SERVER OPTIMIZER — V12 PRO${NC}"
    echo -e "${YELLOW}   Added: DNS Picker • UFW Setup • Restore${NC}"
    echo -e "${CYAN}   Telegram : @UnknownZero${NC}"
    echo -e "${CYAN}===========================================${NC}"
    echo -e " ${CYAN}OS:${NC} $OS_NAME | ${CYAN}Kernel:${NC} $KERNEL_BASE"
    echo -e " ${CYAN}RAM:${NC} ${RAM_MB}MB | ${CYAN}Interfaces:${NC} $(echo $PHY_INTERFACES | tr '\n' ' ')"
    echo
    echo -e " ${GREEN}[1]${NC} 🚀 Run Optimization (Custom DNS)"
    echo -e " ${CYAN}[2]${NC} 📊 System Status"
    echo -e " ${CYAN}[3]${NC} 🔄 Reboot"
    echo -e " ${BLUE}[4]${NC} 🔙 Restore Defaults (Undo All)"
    echo -e " ${YELLOW}[5]${NC} 🛡️ Setup UFW Firewall"
    echo -e " ${RED}[0]${NC} ❌ Exit"
    echo
    read -p " Select: " opt

    case $opt in
        1)
            select_dns_menu
            mkdir -p "$BACKUP_DIR"
            log_msg "--- Start V12 Optimization ---"
            check_kernel_bbr
            setup_dns_safe "$DNS1" "$DNS2"
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
            echo -e "\n${CYAN}--- Firewall ---${NC}"
            ufw status verbose
            echo
            read -p "Press Enter..."
            ;;
        3) reboot ;;
        4)
            restore_defaults
            read -p "Press Enter..."
            ;;
        5)
            setup_ufw
            read -p "Press Enter..."
            ;;
        0) exit ;;
        *) echo "Invalid option"; sleep 1 ;;
    esac
done
