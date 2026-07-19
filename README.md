# 🧰 ServerTools

ابزار **بهینه‌سازی سرور لینوکس** — ساخته‌شده برای سرورهای زیرساخت VPN
(نودهای Xray/Reality مثل `marzban-node` و `pg-node`، پنل‌های Marzban/Pasarguard،
WireGuard و x-ui) و همچنین بهینه‌سازی عمومی هر سرور لینوکسی.

> 🚧 **وضعیت:** نسخه ۲ در حال توسعه است (فاز ۱ و ۲ کامل — هسته + ماژول‌های بهینه‌سازی).
> نسخه پایدار قدیمی در پوشه [`legacy/`](legacy/) نگهداری می‌شود و دیگر آپدیت نمی‌گیرد.

---

## ✨ اصول طراحی v2

| اصل | توضیح |
| --- | --- |
| ⚡ **مصرف صفر** | ابزار one-shot است: تنظیمات را در کرنل اعمال می‌کند و خارج می‌شود. هیچ daemon، هیچ cron، هیچ telemetry. چه ۱۰۰ کاربر متصل باشد چه ۱۰۰هزار، سهم ServerTools از CPU/RAM صفر است. |
| 🧱 **بهینه‌سازی لایه‌ای** | لایه پایه (همیشه، کل سرور) + لایه تخصصی (نود VPN / پنل / عمومی — با تشخیص خودکار یا انتخاب دستی) + لایه اختیاری (فایروال، امنیت SSH و…). |
| 📊 **ظرفیت‌محور** | تنظیمات conntrack و بافرها بر اساس Capacity Tier (تا +100k کاربر همزمان) با نمایش تخمین مصرف RAM کرنل قبل از اعمال. |
| ♻️ **رول‌بک واقعی** | هر تغییر در manifest ثبت می‌شود؛ نسخه دست‌نخورده (original) هر فایل برای همیشه نگه داشته می‌شود. |
| 🧪 **کیفیت تست‌شده** | ShellCheck + shfmt در CI، تست بوت روی Ubuntu 20.04/22.04/24.04 و Debian 11/12. |

## 📥 نصب و اجرا

### نسخه ۲ (پیش‌نمایش توسعه)

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh)
```

پس از انتشار اولین نسخه پایدار، لینک توصیه‌شده از GitHub Releases (همراه با checksum) خواهد بود:

```bash
bash <(curl -fsSL4 https://github.com/Sir-Adnan/server-tools/releases/latest/download/server-tools.sh)
```

### نسخه قدیمی (Legacy — V15.2.0، فریزشده)

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/legacy/opt.sh)
```

> ⚠️ مسیر قبلی `main/opt.sh` به `main/legacy/opt.sh` منتقل شده است.

### نصب به‌عنوان دستور `st` (پیشنهادی)

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh) --install
```

از این به بعد کافیست `st` را اجرا کنید؛ آپدیت هم با `st --update`.

### گزینه‌های CLI (نسخه ۲)

```text
--status      نمایش گزارش کامل وضعیت سیستم و خروج
--auto        بهینه‌سازی غیرتعاملی (لایه پایه + پروفایل تشخیص‌داده‌شده)
                --profile NAME  --tier S|M|L|XL  --dns cloudflare|ip1,ip2
                --no-swap  --no-limits  --no-extras
--rollback    بازگردانی آخرین اجرای ثبت‌شده و خروج
--install     نصب به‌عنوان دستور st
--update      آپدیت خودکار از آخرین Release (با تأیید SHA-256)
--no-color    خروجی بدون رنگ · --debug لاگ کامل · -v نسخه · -h راهنما
```

نمونه برای مدیریت چند نود (Ansible/اسکریپت):

```bash
st --auto --profile vpn-node --tier L --dns cloudflare
```

## 🗺️ نقشه راه

- [x] **فاز ۱** — اسکلت پروژه، هسته (UI/لاگ/State/Backup/Detect)، سیستم Build، CI
- [x] **فاز ۲** — ماژول‌های بهینه‌سازی (sysctl / DNS / Swap / Limits) + پروفایل‌ها + Capacity Tier
- [x] **فاز ۳** — امنیت (UFW / fail2ban / SSH)، تنظیمات VPN-aware (MSS clamp، Docker+UFW)، ابزارهای تست شبکه
- [x] **فاز ۴** — حالت `--auto` غیرتعاملی، دستور `st`، self-update
- [ ] **انتشار v2.0.0** — پس از تست روی سرور واقعی (معیارها در ROADMAP)

جزئیات کامل فازها، ایده‌های آینده و معیارهای انتشار: [ROADMAP.md](ROADMAP.md)

مشخصات فنی هر فاز در [docs/](docs/) ثبت شده است:
[ARCHITECTURE](docs/ARCHITECTURE.md) ·
[PROFILES](docs/PROFILES.md) ·
[SYSCTL](docs/SYSCTL.md) ·
[ROLLBACK](docs/ROLLBACK.md) ·
[FAQ فارسی](docs/FAQ.md)

## 🏗️ ساختار مخزن

```text
src/            سورس ماژولار (core/ + modules/ + menu + main)
build.sh        کامپایل src/ به یک فایل واحد
dist/           خروجی build — فایلی که کاربر نهایی اجرا می‌کند
docs/           مستندات معماری و مشخصات فنی
tests/          تست‌های smoke
legacy/         نسخه ۱ (فریزشده، بدون آپدیت)
```

## 🛠️ توسعه

```bash
./build.sh        # ساخت dist/server-tools.sh
make lint         # shellcheck + shfmt
./tests/smoke.sh  # تست سریع بدون نیاز به root
```

قوانین کدنویسی و اصول پروژه در [CLAUDE.md](CLAUDE.md) ثبت شده‌اند — از جمله:
هیچ وابستگی جدید، هیچ `|| true` بی‌دلیل، ثبت هر تغییر فایل در manifest قبل از اعمال.

## 👤 سازنده

- Creator: **UnknownZero** — Telegram: **@UnknownZero**
- License: [MIT](LICENSE)

*English documentation: [README_en.md](README_en.md)*
