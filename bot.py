import os
import re
import io
import json
import time
import random
import string
import hashlib
import difflib
import threading

import requests
import schedule
import numpy as np
import cv2
import telebot
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")  # ixtiyoriy
ADMIN_ID = os.getenv("ADMIN_ID")  # sizning shaxsiy Telegram ID'ingiz

if not TOKEN:
    raise RuntimeError("BOT_TOKEN topilmadi. .env faylida BOT_TOKEN=... deb yozing.")

bot = telebot.TeleBot(TOKEN)

DATA_FILE = "data.json"

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "instagram.com", "telegram.org",
    "youtube.com", "whatsapp.com", "paypal.com", "apple.com",
    "microsoft.com", "amazon.com", "netflix.com", "binance.com",
    "click.uz", "payme.uz", "humo.uz", "uzcard.uz", "mail.ru",
]

DAILY_TIPS = [
    "🔐 Har bir akkaunt uchun alohida parol ishlating — bittasi sizib chiqsa, qolganlari xavfsiz qoladi.",
    "📱 Muhim akkauntlaringizda (Telegram, email, bank) 2FA'ni albatta yoqing.",
    "🔗 Noma'lum havolalarni bosishdan oldin, uni /check orqali tekshiring.",
    "📥 Noma'lum manbadan APK yoki fayl yuklamang, hatto tanishingiz yuborgan bo'lsa ham avval so'rang.",
    "🕵️ Wi-Fi ochiq (parolsiz) tarmoqlarda bank ilovalariga kirmang.",
    "🔄 Dastur va operatsion tizimni doim yangilab turing — yangilanishlar ko'pincha xavfsizlik teshiklarini yopadi.",
    "🎣 Fishing xabarlar shoshiltiradi ('hisobingiz bloklanadi!'). Shoshilmang, avval tekshiring.",
]


# ================== Ma'lumotlarni saqlash (JSON) ==================
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"users": {}, "subscribers": []}


def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def bump_stat(user_id: int, field: str):
    data = load_data()
    uid = str(user_id)
    if uid not in data["users"]:
        data["users"][uid] = {}
    data["users"][uid][field] = data["users"][uid].get(field, 0) + 1
    save_data(data)


# ================== /start ==================
@bot.message_handler(commands=['start'])
def send_welcome(message):
    text = (
        "Salom! 🛡️ **CyberGuard** kiberxavfsizlik botiga xush kelibsiz.\n\n"
        "Buyruqlar:\n"
        "/check <havola> — Havolani VirusTotal orqali tekshirish\n"
        "/domaincheck <domen> — Domen fishingga o'xshaydimi\n"
        "/ipcheck <ip/domen> — IP manzil obro'sini tekshirish\n"
        "/password — Kuchli parol generatsiya qilish\n"
        "/passcheck <parol> — Parol sizib chiqqanmi tekshirish\n"
        "/2fa — Ikki bosqichli tasdiqlash qo'llanmasi\n"
        "/subscribe — Kunlik xavfsizlik maslahatiga obuna bo'lish\n"
        "/unsubscribe — Obunani bekor qilish\n"
        "/stats — Statistikangiz\n"
        "/emergency — Telefon buzib kirilsa nima qilish\n\n"
        "📎 QR-kod rasm yuboring — men ichidagi havolani tekshiraman\n"
        "📄 Fayl (APK/DOC va h.k.) yuboring — VirusTotal orqali tekshiraman"
    )
    bot.reply_to(message, text, parse_mode="Markdown")


@bot.message_handler(commands=['help'])
def help_command(message):
    bot.reply_to(message, "Buyruqlar ro'yxati uchun /start ni bosing.")


# ================== /check (VirusTotal URL) ==================
@bot.message_handler(commands=['check'])
def check_url(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "Foydalanish: `/check https://example.com`", parse_mode="Markdown")
        return
    url = parts[1].strip()
    result_text = analyze_url_with_vt(url)
    bump_stat(message.from_user.id, "url_checks")
    bot.reply_to(message, result_text, parse_mode="Markdown")


def analyze_url_with_vt(url: str) -> str:
    if not VT_API_KEY:
        return ("⚠️ VirusTotal API kaliti sozlanmagan. `.env` fayliga "
                "`VIRUSTOTAL_API_KEY=...` qo'shing.")
    try:
        headers = {"x-apikey": VT_API_KEY}
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers, data={"url": url}, timeout=15,
        )
        submit.raise_for_status()
        analysis_id = submit.json()["data"]["id"]

        result = None
        for _ in range(6):
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers, timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()["data"]["attributes"]
            if data["status"] == "completed":
                result = data["stats"]
                break
            time.sleep(3)

        if not result:
            return "⏱️ Tahlil hali tugamadi, birozdan keyin qayta urinib ko'ring."

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)
        harmless = result.get("harmless", 0)

        if malicious > 0 or suspicious > 0:
            verdict = f"🚨 **XAVFLI!** {malicious} antivirus zararli, {suspicious} ta shubhali deb belgiladi."
        else:
            verdict = f"✅ Xavfsiz ko'rinadi ({harmless} antivirus tekshirdi, hech narsa topilmadi)."

        return f"Natija: {url}\n\n{verdict}"
    except requests.exceptions.RequestException as e:
        return f"❌ Tekshirishda xatolik yuz berdi: {e}"


# ================== /domaincheck ==================
@bot.message_handler(commands=['domaincheck'])
def check_domain(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "Foydalanish: `/domaincheck gooogle.com`", parse_mode="Markdown")
        return
    domain = parts[1].strip()
    result_text = analyze_domain(domain)
    bump_stat(message.from_user.id, "domain_checks")
    bot.reply_to(message, result_text, parse_mode="Markdown")


def analyze_domain(domain: str) -> str:
    domain = domain.lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    if domain in POPULAR_DOMAINS:
        return f"✅ `{domain}` — mashhur, asl domen."

    matches = difflib.get_close_matches(domain, POPULAR_DOMAINS, n=3, cutoff=0.75)
    if matches:
        return (f"🚨 **DIQQAT!** `{domain}` quyidagi original domenlarga juda o'xshaydi:\n"
                + "\n".join(f"- {m}" for m in matches)
                + "\n\nBu fishing (taqlid) sayt bo'lishi mumkin!")
    return (f"ℹ️ `{domain}` ma'lum brendlarga o'xshamayapti, lekin baribir ehtiyot bo'ling "
            "va `/check` orqali havolani ham tekshiring.")


# ================== /ipcheck ==================
@bot.message_handler(commands=['ipcheck'])
def check_ip(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "Foydalanish: `/ipcheck 8.8.8.8`", parse_mode="Markdown")
        return

    target = parts[1].strip()
    bump_stat(message.from_user.id, "ip_checks")

    try:
        geo = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,isp,org,proxy,hosting,query", timeout=10).json()
    except requests.exceptions.RequestException as e:
        bot.reply_to(message, f"❌ Xatolik: {e}")
        return

    if geo.get("status") != "success":
        error_text = geo.get('message', "noma'lum xato")
        bot.reply_to(message, f"❌ Ma'lumot topilmadi: {error_text}")
        return

    lines = [
        f"🌍 IP: `{geo.get('query')}`",
        f"Davlat: {geo.get('country')}, Shahar: {geo.get('city')}",
        f"Provayder: {geo.get('isp')}",
        f"Tashkilot: {geo.get('org')}",
    ]
    if geo.get("proxy"):
        lines.append("⚠️ Bu VPN/Proksi server sifatida belgilangan.")
    if geo.get("hosting"):
        lines.append("⚠️ Bu hosting/server IP (oddiy foydalanuvchi emas, server bo'lishi mumkin).")

    if ABUSEIPDB_API_KEY:
        try:
            abuse = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": target, "maxAgeInDays": 90},
                timeout=10,
            ).json()
            score = abuse.get("data", {}).get("abuseConfidenceScore")
            if score is not None:
                lines.append(f"🚨 AbuseIPDB xavf balli: {score}/100")
        except requests.exceptions.RequestException:
            pass

    bot.reply_to(message, "\n".join(lines), parse_mode="Markdown")


# ================== /password ==================
@bot.message_handler(commands=['password'])
def generate_password(message):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = "".join(random.choice(chars) for _ in range(16))
    bot.reply_to(message, f"🔐 Siz uchun maxsus xavfsiz parol:\n`{pwd}`\n\nUni hech qachon hech kimga bermang!", parse_mode="Markdown")


# ================== /passcheck ==================
def password_strength_score(pwd: str):
    score = 0
    tips = []
    if len(pwd) >= 12:
        score += 2
    elif len(pwd) >= 8:
        score += 1
    else:
        tips.append("Parol kamida 12 ta belgidan iborat bo'lsin.")
    if re.search(r"[a-z]", pwd):
        score += 1
    else:
        tips.append("Kichik harflar qo'shing.")
    if re.search(r"[A-Z]", pwd):
        score += 1
    else:
        tips.append("Katta harflar qo'shing.")
    if re.search(r"\d", pwd):
        score += 1
    else:
        tips.append("Raqamlar qo'shing.")
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", pwd):
        score += 1
    else:
        tips.append("Maxsus belgilar (!@#$% kabi) qo'shing.")
    return score, tips


@bot.message_handler(commands=['passcheck'])
def check_password(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "Foydalanish: `/passcheck MyParolim123!`", parse_mode="Markdown")
        return

    try:
        bot.delete_message(message.chat.id, message.message_id)
    except Exception:
        pass

    pwd = parts[1].strip()
    score, tips = password_strength_score(pwd)
    bump_stat(message.from_user.id, "pass_checks")

    sha1 = hashlib.sha1(pwd.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    breached_count = None
    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=10)
        resp.raise_for_status()
        for line in resp.text.splitlines():
            h, count = line.split(":")
            if h == suffix:
                breached_count = int(count)
                break
        if breached_count is None:
            breached_count = 0
    except requests.exceptions.RequestException:
        breached_count = None

    lines = [f"🔐 Parol kuchi: {score}/6"]
    if tips:
        lines.append("Tavsiyalar:\n- " + "\n- ".join(tips))
    if breached_count is None:
        lines.append("⚠️ Sizib chiqqan parollar bazasini tekshirib bo'lmadi (tarmoq xatosi).")
    elif breached_count > 0:
        lines.append(f"🚨 Bu parol {breached_count} marta ma'lumotlar sizib chiqishida uchragan! DARHOL almashtiring.")
    else:
        lines.append("✅ Bu parol ma'lum sizib chiqishlar bazasida topilmadi.")

    bot.reply_to(message, "\n\n".join(lines))


# ================== /2fa ==================
@bot.message_handler(commands=['2fa'])
def two_fa_guide(message):
    text = (
        "🔒 **Ikki bosqichli tasdiqlash (2FA) nima va qanday yoqiladi:**\n\n"
        "2FA — parolga qo'shimcha himoya qatlami. Parolingizni bilib olishsa ham, "
        "ikkinchi kod bo'lmasa hisobingizga kira olmaydi.\n\n"
        "**Telegram'da yoqish:**\n"
        "Sozlamalar → Privacy and Security → Two-Step Verification → parol o'rnating\n\n"
        "**Google'da yoqish:**\n"
        "myaccount.google.com → Security → 2-Step Verification\n\n"
        "**Tavsiya:** SMS o'rniga Google Authenticator yoki Authy kabi ilovalardan foydalaning — "
        "SIM karta almashtirilib qolish xavfi yo'q."
    )
    bot.reply_to(message, text, parse_mode="Markdown")


# ================== /subscribe /unsubscribe ==================
@bot.message_handler(commands=['subscribe'])
def subscribe(message):
    data = load_data()
    if message.chat.id not in data["subscribers"]:
        data["subscribers"].append(message.chat.id)
        save_data(data)
    bot.reply_to(message, "✅ Kunlik xavfsizlik maslahatlariga obuna bo'ldingiz!")


@bot.message_handler(commands=['unsubscribe'])
def unsubscribe(message):
    data = load_data()
    if message.chat.id in data["subscribers"]:
        data["subscribers"].remove(message.chat.id)
        save_data(data)
    bot.reply_to(message, "❌ Obuna bekor qilindi.")


def send_daily_tip():
    data = load_data()
    tip = random.choice(DAILY_TIPS)
    for chat_id in data.get("subscribers", []):
        try:
            bot.send_message(chat_id, f"💡 Kunlik maslahat:\n\n{tip}")
        except Exception:
            pass


def scheduler_loop():
    schedule.every().day.at("09:00").do(send_daily_tip)
    while True:
        schedule.run_pending()
        time.sleep(30)


# ================== /stats ==================
@bot.message_handler(commands=['stats'])
def show_stats(message):
    data = load_data()
    user = data["users"].get(str(message.from_user.id), {})
    lines = [
        "📊 **Sizning statistikangiz:**",
        f"Havola tekshirishlar: {user.get('url_checks', 0)}",
        f"Domen tekshirishlar: {user.get('domain_checks', 0)}",
        f"IP tekshirishlar: {user.get('ip_checks', 0)}",
        f"Parol tekshirishlar: {user.get('pass_checks', 0)}",
        f"QR skanerlar: {user.get('qr_checks', 0)}",
        f"Fayl tekshirishlar: {user.get('file_checks', 0)}",
    ]
    bot.reply_to(message, "\n".join(lines), parse_mode="Markdown")


# ================== QR-kod skaneri (rasm yuborilsa) ==================
@bot.message_handler(content_types=['photo'])
def handle_qr_photo(message):
    try:
        file_info = bot.get_file(message.photo[-1].file_id)
        file_bytes = bot.download_file(file_info.file_path)

        img_array = np.frombuffer(file_bytes, dtype=np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)

        if not data:
            bot.reply_to(message, "ℹ️ Rasmda QR-kod topilmadi.")
            return

        bump_stat(message.from_user.id, "qr_checks")
        bot.reply_to(message, f"📷 QR-koddan topildi:\n`{data}`\n\nTekshirilmoqda...", parse_mode="Markdown")

        if data.startswith("http"):
            domain_result = analyze_domain(data)
            vt_result = analyze_url_with_vt(data)
            bot.reply_to(message, f"{domain_result}\n\n{vt_result}", parse_mode="Markdown")
        else:
            bot.reply_to(message, "Bu havola emas, shuning uchun qo'shimcha tekshirish o'tkazilmadi.")
    except Exception as e:
        bot.reply_to(message, f"❌ QR-kodni o'qishda xatolik: {e}")


# ================== Fayl tekshirish (hash orqali VirusTotal) ==================
@bot.message_handler(content_types=['document'])
def handle_file(message):
    if not VT_API_KEY:
        bot.reply_to(message, "⚠️ VirusTotal API kaliti sozlanmagan.")
        return

    bot.reply_to(message, "🔍 Fayl tekshirilmoqda, biroz kuting...")

    try:
        file_info = bot.get_file(message.document.file_id)
        file_bytes = bot.download_file(file_info.file_path)

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        bump_stat(message.from_user.id, "file_checks")

        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=15)

        if resp.status_code == 404:
            bot.reply_to(
                message,
                "ℹ️ Bu fayl VirusTotal bazasida topilmadi (hech kim oldin tekshirmagan). "
                "Uni virustotal.com saytiga qo'lda yuklab, to'liq tekshirishingiz mumkin."
            )
            return

        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious > 0 or suspicious > 0:
            verdict = f"🚨 **XAVFLI FAYL!** {malicious} antivirus zararli, {suspicious} ta shubhali deb belgiladi."
        else:
            verdict = f"✅ Fayl xavfsiz ko'rinadi ({harmless} antivirus tekshirdi)."

        bot.reply_to(message, f"📄 Fayl: {message.document.file_name}\nSHA256: `{sha256}`\n\n{verdict}", parse_mode="Markdown")
    except requests.exceptions.RequestException as e:
        bot.reply_to(message, f"❌ Tekshirishda xatolik: {e}")


# ================== /emergency ==================
@bot.message_handler(commands=['emergency'])
def emergency_guide(message):
    guide = (
        "🚨 **FAVQULODDA YO'RIQNOMA (Telefoningiz buzib kirilsa):**\n\n"
        "1. **Internetni o'chiring:** Wi-Fi va Mobile Data'ni darhol uzing.\n"
        "2. **Shubhali ilovalarni o'chiring:** So'nggi o'rnatilgan noma'lum APK'larni qidirib toping va o'chiring.\n"
        "3. **Sessiyalarni yoping:** Telegram/Boshqa ilovalar sozlamalaridan barcha begona qurilmalarni 'Exit' qiling.\n"
        "4. **Parollarni o'zgartiring:** Muhim akkauntlaringiz parolini boshqa qurilmadan turib o'zgartiring."
    )
    bot.reply_to(message, guide, parse_mode="Markdown")


# ================== Guruh himoyasi ==================
@bot.message_handler(func=lambda m: m.chat.type in ("group", "supergroup") and m.text, content_types=['text'])
def group_protection(message):
    text = message.text.lower()
    urls = re.findall(r"(?:https?://|www\.)[^\s]+", text)

    for url in urls:
        domain = re.sub(r"^https?://", "", url).split("/")[0].replace("www.", "")
        if difflib.get_close_matches(domain, POPULAR_DOMAINS, n=1, cutoff=0.75) and domain not in POPULAR_DOMAINS:
            try:
                bot.delete_message(message.chat.id, message.message_id)
                bot.send_message(
                    message.chat.id,
                    f"🚨 @{message.from_user.username or message.from_user.first_name} yuborgan havola "
                    f"fishing (taqlid) domenga o'xshaganligi uchun o'chirildi: `{domain}`",
                    parse_mode="Markdown",
                )
            except Exception:
                bot.reply_to(message, f"⚠️ Diqqat: `{domain}` fishing bo'lishi mumkin, lekin men bu guruhda "
                                       "xabarlarni o'chirish huquqiga ega emasman (admin qiling).", parse_mode="Markdown")
            return


# ================== Oddiy shaxsiy xabarlar ==================
@bot.message_handler(func=lambda m: m.chat.type == "private", content_types=['text'])
def analyze_text(message):
    text = message.text.lower()
    if "http" in text or "t.me" in text or ".apk" in text:
        bot.reply_to(
            message,
            "⚠️ Xabaringizda havola/fayl bor ko'rinadi. Uni `/check <havola>` yoki "
            "`/domaincheck <domen>` orqali tekshirib ko'ring."
        )
    else:
        bot.reply_to(message, "ℹ️ Buyruqlar ro'yxati uchun /start ni bosing.")


if __name__ == "__main__":
    threading.Thread(target=scheduler_loop, daemon=True).start()
    print("CyberGuard boti (kengaytirilgan versiya) ishga tushdi...")
    bot.infinity_polling()
