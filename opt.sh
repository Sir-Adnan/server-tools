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
    resolvectl dns "$INTERFACE
