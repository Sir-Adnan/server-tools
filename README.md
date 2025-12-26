# 🚀 VPN Server Optimizer (V4 Production - Gold Edition)

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![System](https://img.shields.io/badge/System-Linux-FCC624?style=for-the-badge&logo=linux)
![Network](https://img.shields.io/badge/Network-BBR%20%2B%20FQ-007EC6?style=for-the-badge&logo=cisco)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

<div align="center">

## 🇮🇷 [برای مشاهده توضیحات به زبان فارسی اینجا کلیک کنید](README_FA.md) 🇮🇷
**[Click here for Persian (Farsi) Version](README_FA.md)**

</div>

---

## 📖 Overview
**VPN Server Optimizer V4** is a production-grade bash script designed to tune Linux servers specifically for high-performance VPN protocols like **Xray, Marzban, Sing-box, and V2Ray**.

Unlike bloated scripts that break system stability, this "Gold Edition" focuses on **safe, reversible, and mathematically calculated** optimizations. It automatically detects hardware resources (RAM) to apply the most efficient configurations for TCP buffers, connection limits, and swap management.

---

## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| 🚀 **Kernel Tuning** | Enables **BBR + FQ** congestion control for maximum throughput and lower latency. |
| 🛡️ **Network Stack** | Optimizes `sysctl` for high concurrency (100k+ connections). |
| ⚡ **Smart Swap** | Auto-detects RAM. Creates Swap only if needed (2G/4G) to prevent OOM kills. |
| 🔓 **Limit Unlock** | Increases `ulimit` open files to **262,144** for systemd and root. |
| 🌐 **DNS Optimization** | Sets Cloudflare & Google DNS via `systemd-resolved` for faster resolving. |
| ⏱️ **Connection Stability** | Tunes `tcp_keepalive` specifically for Xray/V2ray to fix "Connection Closed" errors. |
| 🧹 **Auto Maintenance** | Includes log vacuuming, time syncing (NTP), and package cleanup. |

---

## 📥 Installation

Run the following command as **root** on your server:

```bash
wget -qO opt.sh https://raw.githubusercontent.com/Sir-Adnan/server-tools/refs/heads/main/opt.sh && chmod +x opt.sh && ./opt.sh
```
⚙️ Optimization Details
Here is what happens under the hood when you run the script:

1. TCP & BBR Optimization
Congestion Control: Forces bbr with fq queuing discipline.

TCP Fast Open: Enabled (3) to reduce handshake latency.

Buffers: Increases rmem and wmem max to ~33MB (optimized for 1Gbps+ uplinks).

2. Xray/V2Ray Specific Tuning
Standard Linux timeouts cause ghost connections in VPNs. We adjust the following parameters to prevent client disconnections during idle times:

Properties

net.ipv4.tcp_keepalive_time = 600   # 10 minutes
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5
3. Smart Swap Manager
The script automatically detects your RAM usage and acts accordingly:

RAM ≤ 2GB: Creates 2GB Swap file.

RAM ≤ 4GB: Creates 4GB Swap file.

RAM > 4GB: Skips Swap creation (Preserves NVMe/SSD life).

4. File Descriptors (Limits)
Default Linux limits (1024) are too low for high-load VPN servers.

Hard/Soft Limit: Raised to 262144.

Systemd Global: Applied to all services via /etc/systemd/system.conf.

🖥️ Menu Interface
The script features a user-friendly interactive menu:

🚀 Start Full Optimization: Applies all tweaks automatically.

📊 System Status: Shows current Congestion Control, Queue Algo, Swap, and Ulimits.

🔄 Reboot Server: Quick reboot to apply kernel changes.

⚠️ Requirements
OS: Ubuntu 20.04+, Debian 10+ (Recommended).

Root Access: Must be run as root (sudo -i).

Virtualization: KVM / Xen / VMware (OpenVZ may not support BBR).

📜 Disclaimer
This script modifies system configurations (sysctl, limits, fstab). While tested on production servers, always ensure you have backups before running system-level scripts.
