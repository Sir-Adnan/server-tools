# 🚀 VPN Server Optimizer (V4 Production - Gold Edition)

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![System](https://img.shields.io/badge/System-Linux-FCC624?style=for-the-badge&logo=linux)
![Network](https://img.shields.io/badge/Network-BBR%20%2B%20FQ-007EC6?style=for-the-badge&logo=cisco)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

## 📖 Overview
**VPN Server Optimizer V4** is a production-grade bash script designed to tune Linux servers specifically for high-performance VPN protocols like **Xray, Marzban, Sing-box, and V2Ray**.

Unlike bloated scripts that break system stability, this "Gold Edition" focuses on **safe, reversible, and mathematically calculated** optimizations. It automatically detects hardware resources (RAM) to apply the most efficient configurations for TCP buffers, connection limits, and swap management.

---

## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| 🚀 **Kernel Tuning** | Enables **BBR + FQ** congestion control for maximum throughput and lower latency. |
| 🛡️ **Network Stack** | Optimizes `sysctl.conf` for high concurrency (100k+ connections). |
| ⚡ **Smart Swap** | Auto-detects RAM. Creates Swap only if needed (2G/4G) to prevent OOM kills. |
| 🔓 **Limit Unlock** | Increases `ulimit` open files to **262,144** for systemd and root. |
| 🌐 **DNS Optimization** | Sets Cloudflare (1.1.1.1) & Google DNS via `systemd-resolved` for faster resolving. |
| ⏱️ **Stability** | Tunes `tcp_keepalive` specifically for Xray/V2ray to fix "Connection Closed" errors. |
| 🧹 **Auto Maintenance** | Includes log vacuuming, time syncing (NTP), and package cleanup. |

---

## 📥 Installation

Run the following command as **root** on your server:

```bash
bash <(curl -Ls [https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/opt.sh](https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/opt.sh))
