# 🧰 ServerTools

ابزار **بهینه‌سازی حرفه‌ای سرور لینوکس** با مصرف زمان‌اجرای صفر — ساخته‌شده برای
زیرساخت VPN پرترافیک: نودهای Xray/Reality (`marzban-node`، `pg-node`/Pasarguard،
`marznode`)، پنل‌های Marzban/Pasarguard، وایرگارد، x-ui و Hiddify — و همچنین
بهینه‌سازی عمومی هر سرور لینوکسی.

> نسخهٔ پایدار: **v2.4.0** · یک فایل، بدون وابستگی، اجرا به‌عنوان root.
> نسخهٔ ۱ در [`legacy/`](legacy/) فریز شده و دیگر آپدیت نمی‌گیرد.

📖 **[راهنمای کامل صفر تا صد ← docs/GUIDE.md](docs/GUIDE.md)**

## 📥 نصب و اجرا

اجرای مستقیم:

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh)
```

نصب به‌عنوان دستور `st` (پیشنهادی):

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh) --install
```

از این پس فقط `st` را اجرا کنید؛ آپدیت هم با `st --update`.

## ⚡ یک دستور، کل سرور بهینه

کافی است `st` را بزنید و گزینهٔ **۱ (Quick Optimize)** را انتخاب کنید. ابزار
workload سرور را خودکار تشخیص می‌دهد و این لایه‌ها را روی هم اعمال می‌کند:

- **لایهٔ پایه (همیشه):** BBR + fq، صف‌های اتصال و بافرها بر اساس RAM، تایمرها و
  keepalive، سخت‌سازی امن، `tcp_min_snd_mss` (رفع CVE-2019-11479)، و سقف‌های
  file/map.
- **لایهٔ workload (نود VPN):** فورواردینگ IPv4+IPv6، conntrack سایزشده،
  تایم‌اوت‌های بهینه، و رزرو خودکار پورت‌های سرویس.
- **لایهٔ دیتاپث (perf):** پخش پردازش کارت شبکه روی همهٔ هسته‌ها (RPS/RFS/XPS)،
  governor روی `performance`، و THP روی `madvise` — همه بدون قطعی و zero-footprint.
- **تکمیلی:** سواپ (zram یا فایل)، سقف nofile یک‌میلیون، محدودسازی لاگ journald + NTP،
  و انتخاب DNS که واقعاً می‌چسبد.

همه چیز idempotent است: اجرای دوباره امن است و به همان وضعیت می‌رسد.

## 🧭 امکانات (منوی برنامه)

| بخش | چه‌کار می‌کند |
| --- | --- |
| **Optimize** | Quick (خودکار، پیشنهادی) و Custom (انتخاب دستی پروفایل و ماژول‌ها) |
| **Inspect** | System Status کامل · Doctor برای بررسی drift (آیا هنوز اعمال است؟) |
| **Recover** | Rollback آخرین اجرا یا بازگشت کامل به وضعیت اولیه |
| **Secure** | UFW · fail2ban · سخت‌سازی SSH · anti-abuse · محدودسازی API نود |
| **Tools** | پینگ · **اسپیدتست با انتخاب سرور/لوکیشن (Ookla یا HTTP)** · بنچمارک · MSS · **NOTRACK** · **غیرفعال‌سازی کامل IPv6** · Live view · میرور APT · گزارش |
| **Node & Docker** | بکاپ کانفیگ نود · نصب رسمی نودها · سقف فایل کانتینرها |

## ✨ اصول طراحی

| اصل | توضیح |
| --- | --- |
| مصرف صفر ⚡ | «یک‌بار اجرا»: کرنل را تنظیم می‌کند و خارج می‌شود. هیچ daemon/cron/telemetry. چه ۱۰۰ کاربر چه ۱۰۰هزار، سهم ابزار از CPU/RAM صفر است. |
| ظرفیت‌محور 📊 | conntrack و بافرها بر اساس تیر یا **تعداد واقعی کاربر** (`--users`)، با تخمین RAM و هشدار صادقانه پیش از اعمال. |
| بی‌رگرسیون 🛡️ | کلیدهای ظرفیت به‌صورت سقفی تنظیم می‌شوند: هرگز زیر مقدار خودِ کرنل مدرن نمی‌روند. |
| رول‌بک واقعی ♻️ | هر تغییر پیش از اعمال در manifest ثبت و نسخهٔ دست‌نخوردهٔ هر فایل برای همیشه نگه داشته می‌شود. |
| گزارش صادقانه ✅ | هیچ «OK» دروغین: هر مرحله وضعیت واقعی‌اش (OK/WARN/FAILED) را نشان می‌دهد و DNS و بقیه بعد از اعمال واقعاً verify می‌شوند. |
| کیفیت تست‌شده 🧪 | لینت ShellCheck + shfmt در CI و تست بوت روی Ubuntu 20.04/22.04/24.04 و Debian 11/12. |

## ⌨️ گزینه‌های CLI

```text
--status              گزارش کامل وضعیت و خروج
--auto                بهینه‌سازی غیرتعاملی (پایه + پروفایل تشخیص‌داده‌شده)
      --profile NAME  general | vpn-node | wireguard | panel | full
      --tier S|M|L|XL --users N   --dns cloudflare|ip1,ip2
      --no-swap  --no-limits  --no-extras  --no-perf
--dry-run             نمایش پلن و diff دقیق sysctl، بدون اعمال هیچ تغییری
--verify              Doctor: آیا همه‌چیز هنوز اعمال است؟ (تشخیص drift)
--report              گزارش متنی کامل برای تیکت/پشتیبانی
--rollback            بازگردانی آخرین اجرای ثبت‌شده
--rollback-original   بازگشت کامل به وضعیت قبل از اولین اجرا
--install / --update  نصب/آپدیت خودکار دستور st
--json                خروجی ماشین‌خوان (برای --verify)
--no-color · --debug · -v · -h
```

کدهای خروج (برای Ansible/CI): `0` موفق · `1` شکست حداقل یک مرحله · `2` خطای دستور ·
`3` اعمال شد ولی با هشدار یا drift.

نمونه برای مدیریت چند نود:

```bash
st --auto --profile vpn-node --users 10000 --dns cloudflare
st --verify --json     # بررسی drift شبانه از automation خودتان
```

## 📚 مستندات

[📖 راهنمای کامل](docs/GUIDE.md) ·
[معماری](docs/ARCHITECTURE.md) ·
[پروفایل‌ها](docs/PROFILES.md) ·
[مشخصات sysctl](docs/SYSCTL.md) ·
[رول‌بک](docs/ROLLBACK.md) ·
[❓ سوالات پرتکرار](docs/FAQ.md) ·
[تغییرات](CHANGELOG.md)

## 🏗️ ساختار مخزن

```text
src/       سورس ماژولار (core/ + modules/ + menu + main)
build.sh   کامپایل src/ به یک فایل واحد
dist/      خروجی build (فایلی که کاربر نهایی اجرا می‌کند)
docs/      مستندات و مشخصات فنی
tests/     تست‌های smoke
legacy/    نسخهٔ ۱ (فریزشده)
```

## 🛠️ توسعه

```bash
./build.sh        # ساخت dist/server-tools.sh
make lint         # shellcheck + shfmt
./tests/smoke.sh  # تست سریع بدون نیاز به root
```

اصول کدنویسی در [CLAUDE.md](CLAUDE.md) ثبت شده‌اند: بدون وابستگی جدید، بدون
`|| true` بی‌دلیل، ثبت هر تغییر فایل در manifest پیش از اعمال، و اینکه `dist/`
تولیدی است (مستقیم ویرایش نمی‌شود — `src/` را تغییر دهید و `./build.sh` بزنید).

## 👤 سازنده

- سازنده: **UnknownZero** — تلگرام: **@UnknownZero**
- مجوز: [MIT](LICENSE)

*English documentation: [README_en.md](README_en.md)*
