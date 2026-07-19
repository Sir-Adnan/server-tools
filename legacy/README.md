> ⚠️ **نسخه Legacy (فریزشده)** — این اسکریپت نسخه ۱ پروژه است، دیگر آپدیت
> نمی‌گیرد و فقط برای سازگاری نگه داشته شده. نسخه ۲ (**ServerTools**) در حال
> توسعه است — [README اصلی](../README.md) را ببینید.
>
> 📥 لینک اجرای نسخه Legacy (مسیر جدید بعد از انتقال به پوشه `legacy/`):
>
> ```bash
> bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/legacy/opt.sh)
> ```

# 🚀 VPN Server Optimizer (opt.sh) — V15.2.0 (Legacy)

اسکریپت **بهینه‌سازی سرور لینوکس برای VPN** (مخصوص استفاده‌های سنگین و تعداد کاربر بالا)  
مناسب برای: **Xray (Reality / TCP / WS / gRPC)** و **Hysteria2 (UDP/QUIC)**

---
## 📋 جدول ویژگی‌ها و امکانات (Features)

| دسته‌بندی | قابلیت | توضیح کوتاه | اثر روی عملکرد |
|---|---|---|---|
| 🌐 شبکه / TCP | ✅ فعال‌سازی BBR | فعال‌سازی BBR در صورت پشتیبانی کرنل + بارگذاری ماژول | 📉 کاهش تأخیر در ازدحام، 📈 پایداری بهتر |
| 🌐 شبکه / Queue | ✅ Qdisc هوشمند | انتخاب خودکار `fq` برای BBR یا `fq_codel` برای fallback | 🎯 کاهش Bufferbloat، 📉 جیتر کمتر |
| 🧠 Sysctl Tuning | ✅ تنظیمات سنگین شبکه | افزایش backlog، بهینه‌سازی SYN backlog، پورت‌رنج، و… | 🚀 افزایش ظرفیت کاربران همزمان |
| 🧠 Buffer Tuning | ✅ بافرهای TCP/UDP | افزایش `rmem/wmem` برای throughput بهتر (با مقدار امن) | 📈 سرعت دانلود/آپلود بهتر |
| 🧩 Conntrack | ✅ کانترک پویا | تنظیم `nf_conntrack_max` بر اساس RAM (با سقف امن) | ✅ تحمل اتصالات زیاد بدون Drop |
| 📡 DNS | ✅ انتخاب DNS آماده | Cloudflare / Google / Quad9 / OpenDNS / Shecan | ⚡ پاسخ DNS سریع‌تر، کاهش Delay |
| 📡 DNS | ✅ DNS سفارشی | امکان وارد کردن DNS دلخواه | 🧩 انعطاف کامل |
| 🛠️ DNS Stack | ✅ سازگاری کامل | پشتیبانی از `systemd-resolved` و `/etc/resolv.conf` | ✅ جلوگیری از تداخل و DNS Leak |
| 📏 MTU | ✅ MTU Optimization | تشخیص MTU امن با DF Ping و جلوگیری از Fragmentation | 📉 پینگ کمتر، ✅ پایداری Reality/TCP |
| 🧠 CPU / IRQ | ✅ irqbalance | تقسیم بار IRQ/softirq بین هسته‌های CPU | 📉 جیتر کمتر زیر فشار |
| 🔧 NIC | ✅ Ring Buffer Tuning | تنظیم RX/TX ring با `ethtool` (Fail-safe) | 📈 throughput بهتر، Drop کمتر |
| 🔧 NIC | ✅ Fail-safe کامل | اول قابلیت NIC بررسی می‌شود، سپس اعمال می‌شود | ✅ بدون ریسک خراب‌کاری |
| 💾 Swap | ✅ ساخت Swap هوشمند | اگر swap فعال نباشد ایجاد می‌شود (سایز امن) | ✅ جلوگیری از OOM در پیک |
| 🔐 Firewall | ✅ UFW اختیاری | نصب/فعال‌سازی UFW، اجازه SSH و پورت‌های دلخواه | 🔒 امنیت بهتر بدون قطع SSH |
| 🧾 Logging | ✅ لاگ‌گیری مقاوم | لاگ در `/var/log` و در صورت محدودیت در `/tmp` | 🧠 عیب‌یابی راحت‌تر |
| 🧾 Rotation | ✅ چرخش لاگ | بر اساس حجم/تعداد/مدت نگهداری | 🧹 جلوگیری از پر شدن دیسک |
| ♻️ Backup | ✅ بکاپ کامل | بکاپ فایل‌های تغییر یافته در مسیر جداگانه | 🛡️ امکان بازگشت سریع |
| ♻️ Rollback | ✅ بازگشت امن | بازگردانی تغییرات به آخرین بکاپ (latest) | 🧯 رفع مشکل در چند ثانیه |
| 🖥️ UI | ✅ ظاهر سازگار | محیط ASCII-only برای ترمینال‌های مشکل‌دار | ✅ بدون `????` و بهم‌ریختگی |
| 📊 Status | ✅ System Status کامل | نمایش OS/CPU/RAM/IP/DNS/BBR/MTU/irqbalance | 🔍 شفافیت کامل وضعیت سرور |

---
## ✨ ویژگی‌ها (Features)

### 🌐 شبکه و TCP/UDP Tuning
- ✅ فعال‌سازی **BBR** (در صورت پشتیبانی کرنل) + انتخاب خودکار **Qdisc** مناسب
- ✅ تنظیمات پیشرفته‌ی `sysctl` برای:
  - افزایش توان پردازش اتصالات همزمان
  - کاهش لگ و بهبود پایداری تحت فشار
  - بهینه‌سازی بافرهای TCP/UDP برای سرعت بهتر
  - افزایش `nf_conntrack_max` بر اساس RAM (با سقف امن)

### 📡 DNS Manager
- ✅ تغییر DNS سرور به یکی از گزینه‌ها:
  - Cloudflare / Google / Quad9 / OpenDNS / Shecan
  - یا DNS دلخواه (Custom)
- ✅ سازگار با:
  - `systemd-resolved` (Drop-in config + resolvectl)
  - یا `resolv.conf` (در سیستم‌های بدون resolved)

### 📏 MTU Optimization (Safe)
- ✅ تشخیص **بهترین MTU قابل‌اعتماد** با تست Ping و جلوگیری از Fragment
- ✅ اعمال MTU به صورت Runtime و در صورت وجود Netplan (Persist)
- 🎯 مفید برای Reality/TCP و کاهش مشکلات قطع و ناپایداری شبکه

### 🧠 CPU Load Balancing (IRQ)
- ✅ نصب/فعال‌سازی `irqbalance`
- 🎯 کمک به تقسیم فشار SoftIRQ روی هسته‌های CPU  
  (روی بعضی VMها اثر کمتره، ولی کم‌ریسک و ارزشمند)

### 🔧 NIC Ring Buffer Tuning (ethtool)
- ✅ تنظیم هوشمند RX/TX Ring Buffers با `ethtool`
- ✅ **Fail-safe**:
  - اول قابلیت NIC بررسی می‌شود (`ethtool -g`)
  - سپس در صورت پشتیبانی تلاش به افزایش انجام می‌گیرد
  - اگر امکان‌پذیر نبود بدون خطا رد می‌شود

### 🧾 Logging + Backup + Rollback
- ✅ لاگ‌گیری امن:
  - تلاش برای `/var/log/...`
  - در صورت محدودیت، انتقال خودکار به `/tmp/...`
- ✅ Rotate لاگ بر اساس حجم/تعداد/زمان
- ✅ بکاپ‌گیری از فایل‌های تغییریافته در:
  - `/root/vpn_optimizer_backups/<RUN_ID>/`
  - و لینک `latest` برای آخرین اجرا
- ✅ Rollback امن به آخرین بکاپ

### 🧰 Firewall (UFW)
- ✅ نصب و پیکربندی UFW (اختیاری)
- ✅ تشخیص پورت SSH و باز گذاشتن آن
- ✅ امکان افزودن پورت‌های اضافی (مثلاً 80/443/UDP…)

### 🖥️ UI تمیز و سازگار
- ✅ رابط کاربری **ASCII-only** (بدون یونیکد/ایموجی داخل خروجی ترمینال)
- ✅ مناسب برای ترمینال‌هایی که یونیکد را خراب نمایش می‌دهند (رفع مشکل `????`)
- ✅ منوی مرتب + Progress Bar ساده و شفاف

---

## ✅ نصب و اجرا

### 📥 روش پیشنهادی (Recommended)
```bash
wget -qO opt.sh "https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/legacy/opt.sh" \
&& chmod +x opt.sh \
&& bash opt.sh
````

> چرا `bash opt.sh`؟ چون در بعضی سرورها mount با `noexec` باعث می‌شود `./opt.sh` اجرا نشود.

### روش معمول

```bash
wget -qO opt.sh "https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/legacy/opt.sh" \
&& chmod +x opt.sh \
&& ./opt.sh
```

---

## 📌 نیازمندی‌ها (Requirements)

* ✅ اجرا با **root**
* ✅ پیشنهاد: Ubuntu/Debian (روی بقیه هم ممکن است کار کند ولی تست اصلی روی این‌هاست)
* ✅ ابزارهای کمکی در صورت نیاز خودکار نصب می‌شوند:

  * `irqbalance`
  * `ethtool`
  * `ufw`

---

## 📊 System Status چه چیزهایی نشان می‌دهد؟

* 🖥️ OS / Kernel / Uptime / Hostname
* 🧠 CPU Model / Cores / Load
* 💾 RAM / Swap
* 🌐 Interface / MTU / IPv4 / IPv6
* 🌍 Public IPv4 / Public IPv6 (با ipify)
* 📡 DNS فعلی و انتخاب‌شده
* 📈 وضعیت TCP / BBR / Qdisc
* ⚙️ وضعیت `irqbalance`

---

## ♻️ Rollback (بازگشت به تنظیمات قبلی)

از منو گزینه‌ی Rollback را بزنید.
این کار فایل‌های تغییر یافته را با **آخرین بکاپ** بازگردانی می‌کند.

---

## 🧯 عیب‌یابی (Troubleshooting)

### ❗ اسکریپت اجرا می‌شود ولی چیزی نشان نمی‌دهد

✅ این دستور را بزنید تا مرحله به مرحله نمایش دهد:

```bash
bash -x opt.sh
```

### 📄 لاگ‌ها کجا هستند؟

* مسیر اصلی:

  * `/var/log/vpn_optimizer.log`
* اگر محدودیت وجود داشته باشد:

  * `/tmp/vpn_optimizer.log`

### 🧩 اگر BBR فعال نشد

* کرنل باید حداقل **4.9** باشد
* بررسی:

```bash
sysctl net.ipv4.tcp_congestion_control
sysctl net.ipv4.tcp_available_congestion_control
```

---

## 🔐 نکته امنیتی

این اسکریپت برای بهینه‌سازی سیستم ساخته شده و جایگزین تنظیمات امنیتی حرفه‌ای نیست.
برای سرورهای عمومی پیشنهاد می‌شود:

* UFW یا فایروال مناسب
* محدودسازی دسترسی SSH (کلید، IP محدود، Fail2ban)

---

## 👤 سازنده

* Creator: **UnknownZero**
* Telegram ID: **@UnknownZero**
