# 🚀 VPN Server Optimizer (V4 Production - Gold Edition)

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![System](https://img.shields.io/badge/System-Linux-FCC624?style=for-the-badge&logo=linux)
![Network](https://img.shields.io/badge/Network-BBR%20%2B%20FQ-007EC6?style=for-the-badge&logo=cisco)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Telegram](https://img.shields.io/badge/Support-Telegram-blue?style=for-the-badge&logo=telegram&link=https://t.me/UnknownZero)

<div align="center">

[نسخه فارسی (Persian Version)](README.md) 👈

</div>

## 📖 Project Introduction
**VPN Server Optimizer V4** is a production-grade Bash script specifically designed to tune and optimize Linux servers running **Xray, Marzban, Sing-box, and V2Ray** protocols.

Unlike cluttered, legacy scripts that compromise system stability with unnecessary changes, this "Gold Edition" focuses on **safe, engineered, and reversible** optimizations. This tool intelligently detects your server's RAM and applies the most precise settings for TCP buffers and Swap management.

---

## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| 🚀 **Kernel Tuning** | Enables **BBR + FQ** congestion control algorithm for maximum bandwidth and reduced latency. |
| 🛡️ **Network Stack** | Optimizes `sysctl` parameters to handle thousands of concurrent connections (High Concurrency). |
| ⚡ **Smart Swap** | Auto-detects RAM; creates Swap (2GB or 4GB) only if necessary to prevent OOM crashes. |
| 🔓 **Limit Unlock** | Increases Open File Limits (`ulimit`) to **262,144** for both the system and services. |
| 🌐 **DNS Optimization** | Sets Cloudflare and Google DNS on `systemd-resolved` to improve resolution speed. |
| ⏱️ **Connection Stability** | Fine-tunes `tcp_keepalive` to prevent "Connection Closed" errors on V2Ray clients. |
| 🧹 **Auto Maintenance** | Includes Time Synchronization (NTP), log clearing, and removal of unnecessary packages. |

---

## 📥 Installation

Run the following command with **root** privileges in your server terminal:

```bash
wget -qO opt.sh https://raw.githubusercontent.com/Sir-Adnan/server-tools/refs/heads/main/opt.sh && chmod +x opt.sh && ./opt.sh

```

---

## ⚙️ Technical Details & Performance

When you execute the script, the following kernel-level changes are applied:

### 1. TCP & BBR Optimization

* **Congestion Control:** Forces the kernel to use `bbr` with the `fq` queuing discipline.
* **TCP Fast Open:** Enabled (value 3) to reduce initial connection handshake latency.
* **Buffers:** Increases `rmem` and `wmem` to approximately 33MB (Ideal for 1Gbps+ ports).

### 2. Xray/V2Ray Specific Settings

Default Linux timeouts often cause VPN connections to drop. We adjust these values:

```properties
net.ipv4.tcp_keepalive_time = 600   # 10 minutes
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5

```

*Result:* User connections remain active during idle times, preventing unexpected drops.

### 3. Smart Swap Management

The script checks your available RAM:

* **RAM ≤ 2GB:** Creates 2GB Swap.
* **RAM ≤ 4GB:** Creates 4GB Swap.
* **RAM > 4GB:** No Swap created (To preserve NVMe/SSD lifespan and ensure high performance).

### 4. File Descriptors Limits

The default Linux limit (1024) is too low for VPN servers.

* **Hard/Soft Limit:** Increased to `262144`.
* **Systemd Global:** Applies changes to all services via `/etc/systemd/system.conf`.

---

## 🖥️ User Menu

The script features a simple, interactive interface:

1. **🚀 Start Full Optimization:** Initiates the complete optimization process (Zero to Hero).
2. **📊 System Status:** Displays current network algorithm, swap status, and limits.
3. **🔄 Reboot Server:** Quick reboot to apply kernel changes.

---

## ⚠️ Prerequisites

* **OS:** Ubuntu 20.04+ or Debian 10+ (Recommended).
* **Access:** Must be run as `root` (use `sudo -i`).
* **Virtualization:** KVM / VMware / Xen (OpenVZ virtualization may not support BBR).

---

## 📞 Support & Contact

If you have questions or find a bug, you can contact the developer via Telegram:

<a href="https://t.me/UnknownZero">🐦‍🔥 Telegram: @UnknownZero</a>

---

## 📜 Disclaimer

This script modifies system configurations (`sysctl`, `limits`, `fstab`). While tested on production servers, it is recommended to have a backup before running it on critical infrastructure.

<div align="center">

**If you found this script useful, please give the project a ⭐️ (Star)!**

</div>
