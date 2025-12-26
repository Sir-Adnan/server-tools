#!/bin/bash

# رنگ‌ها
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}خطا: لطفا با root اجرا کنید.${NC}"
  exit 1
fi

show_header() {
    clear
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${YELLOW}    ULTRA VPN OPTIMIZER (High Load 1000+ Users)${NC}"
    echo -e "${CYAN}==================================================${NC}"
}

# ۱. تنظیم DNS (ضد نشت و فوق سریع)
setup_dns() {
    echo -e "${BLUE}[*] تنظیم DNS هوشمند...${NC}"
    INTERFACE=$(ip -o link show | awk -F': ' '$2 !~ /lo|docker|virbr/ {print $2; exit}')
    
    # نصب resolvconf اگر وجود ندارد
    apt-get install -y resolvconf > /dev/null 2>&1

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
    echo -e "${GREEN}✅ DNS تنظیم شد.${NC}"
}

# ۲. تنظیمات شبکه برای ۱۰۰۰+ کاربر (Kernel Tuning)
setup_network_ultra() {
    echo -e "${BLUE}[*] اعمال تنظیمات شبکه فوق سنگین...${NC}"
    
    # بارگذاری ماژول‌های لازم برای کانترک (Connection Tracking)
    modprobe nf_conntrack

    cat <<EOL > /etc/sysctl.conf
# فعال‌سازی BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# تنظیمات بحرانی برای ۱۰۰۰+ کاربر
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_slow_start_after_idle = 0

# افزایش ظرفیت جدول ردیابی اتصالات (بسیار مهم برای VPN)
net.netfilter.nf_conntrack_max = 2000000
net.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200

# بافرهای عظیم شبکه
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# امنیت و پایداری
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 20
vm.swappiness = 10
EOL
    sysctl -p
    echo -e "${GREEN}✅ هسته لینوکس برای ترافیک بالا بهینه شد.${NC}"
}

# ۳. تنظیم Swap (جلوگیری از کرش کردن پنل VPN)
setup_swap_2g() {
    if [ $(swapon --show | wc -l) -eq 0 ]; then
        echo -e "${BLUE}[*] ایجاد ۲ گیگابایت سواپ...${NC}"
        fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
}

# ۴. پاک‌سازی لاگ‌ها و فایل‌های اضافه (آزاد کردن فضا)
cleanup_system() {
    echo -e "${BLUE}[*] پاک‌سازی لاگ‌ها و کش سیستم...${NC}"
    # محدود کردن حجم لاگ‌های سیستم به ۵۰ مگابایت
    journalctl --vacuum-size=50M
    # پاک کردن کش پکیج‌ها
    apt-get autoremove -y > /dev/null
    apt-get clean > /dev/null
    # پاک کردن لاگ‌های قدیمی در /var/log
    find /var/log -type f -regex '.*\.gz$' -delete
    find /var/log -type f -regex '.*\.1$' -delete
    echo -e "${GREEN}✅ سیستم پاک‌سازی شد.${NC}"
}

# ۵. افزایش فایل‌های باز (Limit)
setup_limits() {
    cat <<EOL > /etc/security/limits.conf
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
EOL
}

# اجرای منو
while true; do
    show_header
    echo -e "1) ${GREEN}بهینه‌سازی کامل (High Load)${NC}"
    echo -e "2) پاک‌سازی لاگ‌ها و آزاد کردن فضا"
    echo -e "3) مشاهده وضعیت پایداری و کاربر"
    echo -e "E) خروج"
    read -p "انتخاب شما: " choice

    case $choice in
        1)
            setup_dns
            setup_network_ultra
            setup_swap_2g
            setup_limits
            cleanup_system
            echo -e "${YELLOW}بهینه‌سازی تمام شد. حتما سرور را ریبوت کنید: reboot${NC}"
            exit 0
            ;;
        2) cleanup_system; read -p "پایان پاک‌سازی. اینتر بزنید..." ;;
        3) 
            echo -e "${CYAN}تعداد اتصالات فعلی TCP: ${NC}$(ss -ant | wc -l)"
            echo -e "${CYAN}وضعیت BBR: ${NC}$(sysctl net.ipv4.tcp_congestion_control)"
            read -p "اینتر بزنید..."
            ;;
        E|e) exit 0 ;;
    esac
done
