# 🧰 ServerTools

ابزار **بهینه‌سازی حرفه‌ای سرور لینوکس** — ساخته‌شده برای سرورهای زیرساخت VPN
(نودهای Xray/Reality مثل `marzban-node` و `pg-node`، پنل‌های Marzban/Pasarguard،
وایرگارد، x-ui، Hiddify و…) و همچنین بهینه‌سازی عمومی هر سرور لینوکسی.

> وضعیت 🚧: نسخه ۲ در حال توسعه است (فازهای ۱ تا ۴ کامل).
> نسخه قدیمی در پوشه [`legacy/`](legacy/) فریز شده و دیگر آپدیت نمی‌گیرد.

📖 **[راهنمای کامل استفاده از صفر تا صد ← docs/GUIDE.md](docs/GUIDE.md)**

## ✨ اصول طراحی

| اصل | توضیح |
| --- | --- |
| مصرف صفر ⚡ | ابزار «یک‌بار اجرا» است: تنظیمات را در کرنل اعمال می‌کند و خارج می‌شود. هیچ daemon، هیچ cron، هیچ telemetry. چه ۱۰۰ کاربر متصل باشد چه ۱۰۰هزار، سهم ابزار از CPU/RAM صفر است. |
| بهینه‌سازی لایه‌ای 🧱 | لایه پایه (همیشه، کل سرور) + لایه تخصصی (نود VPN / پنل / وایرگارد — با تشخیص خودکار یا انتخاب دستی) + لایه اختیاری (فایروال، امنیت SSH و…). |
| ظرفیت‌محور 📊 | سایز conntrack و بافرها بر اساس تیر ظرفیت یا **تعداد واقعی کاربر** (`--users`)، با نمایش تخمین مصرف RAM و هشدار صادقانه قبل از اعمال. |
| رول‌بک واقعی ♻️ | هر تغییر در manifest ثبت می‌شود؛ نسخه دست‌نخورده (original) هر فایل برای همیشه نگه داشته می‌شود. |
| کیفیت تست‌شده 🧪 | لینت ShellCheck + shfmt در CI، تست بوت روی Ubuntu 20.04/22.04/24.04 و Debian 11/12. |

## 📥 نصب و اجرا

اجرای مستقیم (نسخه ۲):

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh)
```

نصب به‌عنوان دستور `st` (پیشنهادی):

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/dist/server-tools.sh) --install
```

از این به بعد کافی است `st` را اجرا کنید؛ آپدیت هم با `st --update`.

نسخه قدیمی (Legacy — فریزشده):

```bash
bash <(curl -fsSL4 https://raw.githubusercontent.com/Sir-Adnan/server-tools/main/legacy/opt.sh)
```

> توجه ⚠️: مسیر قبلی `main/opt.sh` به `main/legacy/opt.sh` منتقل شده است.

## ⌨️ گزینه‌های CLI

```text
--status      نمایش گزارش کامل وضعیت سیستم و خروج
--auto        بهینه‌سازی غیرتعاملی (لایه پایه + پروفایل تشخیص‌داده‌شده)
                --profile NAME   --tier S|M|L|XL   --users N
                --dns cloudflare|ip1,ip2   --no-swap  --no-limits  --no-extras
--dry-run     نمایش پلن و diff دقیق sysctl بدون اعمال هیچ تغییری
--verify      بررسی اینکه همه‌ی تنظیمات هنوز واقعاً اعمال هستند (Doctor)
--report      گزارش متنی کامل برای تیکت/پشتیبانی (چاپ + ذخیره)
--rollback    بازگردانی آخرین اجرای ثبت‌شده و خروج
--rollback-original   بازگشت کامل به وضعیت قبل از اولین اجرای ابزار
--install     نصب به‌عنوان دستور st
--update      آپدیت خودکار از آخرین Release (با تأیید SHA-256)
--json        خروجی ماشین‌خوان (برای --verify)
--no-color    خروجی بدون رنگ · --debug لاگ کامل · -v نسخه · -h راهنما
```

کدهای خروج (برای Ansible و CI): مقدار `0` یعنی همه‌چیز موفق، `1` یعنی حداقل یک مرحله شکست خورد، `2` یعنی خطای دستور، و `3` یعنی اعمال شد ولی با هشدار یا drift.

نمونه برای مدیریت چند نود (Ansible/اسکریپت):

```bash
st --auto --profile vpn-node --users 10000 --dns cloudflare
```

جزئیات کامل فازها، ایده‌های آینده و معیارهای انتشار در [ROADMAP.md](ROADMAP.md) است.

مستندات فنی:
[📖 راهنمای کامل](docs/GUIDE.md) ·
[معماری](docs/ARCHITECTURE.md) ·
[پروفایل‌ها](docs/PROFILES.md) ·
[مشخصات sysctl](docs/SYSCTL.md) ·
[رول‌بک](docs/ROLLBACK.md) ·
[❓ سوالات پرتکرار](docs/FAQ.md)

## 🏗️ ساختار مخزن

```text
src/            سورس ماژولار (core/ + modules/ + menu + main)
build.sh        کامپایل src/ به یک فایل واحد
dist/           خروجی build — فایلی که کاربر نهایی اجرا می‌کند
docs/           مستندات، راهنمای فارسی و مشخصات فنی
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

- سازنده: **UnknownZero** — تلگرام: **@UnknownZero**
- مجوز: [MIT](LICENSE)

*English documentation: [README_en.md](README_en.md)*
