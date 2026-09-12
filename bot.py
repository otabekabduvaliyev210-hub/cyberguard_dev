import os
import re
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
from telebot import types
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ADMIN_ID = os.getenv("ADMIN_ID")

if not TOKEN:
    raise RuntimeError("BOT_TOKEN topilmadi. .env faylida BOT_TOKEN=... deb yozing.")

bot = telebot.TeleBot(TOKEN, parse_mode="Markdown")

DATA_FILE = "data.json"

# Foydalanuvchi qaysi buyruq uchun matn/rasm kutayotganini saqlaymiz
user_state = {}

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "instagram.com", "telegram.org",
    "youtube.com", "whatsapp.com", "paypal.com", "apple.com",
    "microsoft.com", "amazon.com", "netflix.com", "binance.com",
    "click.uz", "payme.uz", "humo.uz", "uzcard.uz", "mail.ru",
]

BTN_CHECK = "🔗 Havola tekshirish"
BTN_DOMAIN = "🌐 Domen tekshirish"
BTN_IP = "🌍 IP tekshirish"
BTN_GENPASS = "🔐 Parol yaratish"
BTN_PASSCHECK = "🔓 Parol tekshirish"
BTN_2FA = "🛡 2FA qo'llanma"
BTN_STATS = "📊 Statistika"
BTN_SUB = "🔔 Kunlik maslahat"
BTN_EMERGENCY = "🚨 Favqulodda yordam"

DAILY_TIPS = [
    "🔐 Har bir akkaunt uchun alohida parol ishlating — bittasi sizib chiqsa, qolganlari xavfsiz qoladi.",
    "📱 Muhim akkauntlaringizda (Telegram, email, bank) 2FA'ni albatta yoqing.",
    "🔗 Noma'lum havolalarni bosishdan oldin, uni /check orqali tekshiring.",
    "📥 Noma'lum manbadan APK yoki fayl yuklamang, hatto tanishingiz yuborgan bo'lsa ham avval so'rang.",
    "🕵️ Wi-Fi ochiq (parolsiz) tarmoqlarda bank ilovalariga kirmang.",
    "🔄 Dastur va operatsion tizimni doim yangilab turing.",
    "🎣 Fishing xabarlar shoshiltiradi ('hisobingiz bloklanadi!'). Shoshilmang, avval tekshiring.",
]


# ================== Ma'lumotlarni saqlash ==================
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


# ================== Asosiy menyu (Inline Keyboard) ==================
def main_menu():
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton("🔗 Havola tekshirish", callback_data="menu_check"),
        types.InlineKeyboardButton("🌐 Domen tekshirish", callback_data="menu_domain"),
    )
    kb.add(
        types.InlineKeyboardButton("🌍 IP tekshirish", callback_data="menu_ip"),
        types.InlineKeyboardButton("🔐 Parol yaratish", callback_data="menu_genpass"),
    )
    kb.add(
        types.InlineKeyboardButton("🔓 Parol tekshirish", callback_data="menu_passcheck"),
        types.InlineKeyboardButton("🛡 2FA qo'llanma", callback_data="menu_2fa"),
    )
    kb.add(
        types.InlineKeyboardButton("📊 Statistika", callback_data="menu_stats"),
        types.InlineKeyboardButton("🔔 Kunlik maslahat", callback_data="menu_sub"),
    )
    kb.add(
        types.InlineKeyboardButton("🚨 Favqulodda yordam", callback_data="menu_emergency"),
    )
    return kb


def main_menu_keyboard():
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    kb.add(types.KeyboardButton(BTN_CHECK), types.KeyboardButton(BTN_DOMAIN))
    kb.add(types.KeyboardButton(BTN_IP), types.KeyboardButton(BTN_GENPASS))
    kb.add(types.KeyboardButton(BTN_PASSCHECK), types.KeyboardButton(BTN_2FA))
    kb.add(types.KeyboardButton(BTN_STATS), types.KeyboardButton(BTN_SUB))
    kb.add(types.KeyboardButton(BTN_EMERGENCY))
    return kb


def back_button():
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton("⬅️ Bosh menyu", callback_data="menu_home"))
    return kb


# ================== /start ==================
@bot.message_handler(commands=['start'])
def send_welcome(message):
    user_state.pop(message.from_user.id, None)
    text = (
        "🛡️ *CyberGuard* — kiberxavfsizlik yordamchingiz\n\n"
        "Pastdagi menyudan kerakli bo'limni tanlang 👇\n\n"
        "📎 Shuningdek, istalgan vaqtda QR-kod rasm yoki fayl (APK/DOC) yuborsangiz, "
        "men uni avtomatik tekshiraman."
    )
    bot.send_message(message.chat.id, text, reply_markup=main_menu_keyboard())


@bot.message_handler(commands=['help'])
def help_command(message):
    bot.reply_to(message, "Buyruqlar ro'yxati uchun /start ni bosing.")


@bot.message_handler(commands=['menu'])
def menu_command(message):
    user_state.pop(message.from_user.id, None)
    bot.send_message(message.chat.id, "🏠 Bosh menyu:", reply_markup=main_menu_keyboard())


# ================== Callback (tugmalar) ==================
@bot.callback_query_handler(func=lambda call: True)
def handle_callback(call):
    uid = call.from_user.id
    chat_id = call.message.chat.id

    if call.data == "menu_home":
        user_state.pop(uid, None)
        bot.edit_message_text("🏠 Bosh menyu:", chat_id, call.message.message_id, reply_markup=main_menu())
        return

    if call.data == "menu_check":
        user_state[uid] = "await_url"
        bot.edit_message_text(
            "🔗 Tekshirmoqchi bo'lgan havolani yuboring (masalan: https://example.com)",
            chat_id, call.message.message_id, reply_markup=back_button()
        )

    elif call.data == "menu_domain":
        user_state[uid] = "await_domain"
        bot.edit_message_text(
            "🌐 Tekshirmoqchi bo'lgan domenni yuboring (masalan: gooogle.com)",
            chat_id, call.message.message_id, reply_markup=back_button()
        )

    elif call.data == "menu_ip":
        user_state[uid] = "await_ip"
        bot.edit_message_text(
            "🌍 Tekshirmoqchi bo'lgan IP manzil yoki domenni yuboring (masalan: 8.8.8.8)",
            chat_id, call.message.message_id, reply_markup=back_button()
        )

    elif call.data == "menu_genpass":
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = "".join(random.choice(chars) for _ in range(16))
        bot.edit_message_text(
            f"🔐 Siz uchun yangi xavfsiz parol:\n\n`{pwd}`\n\n⚠️ Uni hech kimga bermang!",
            chat_id, call.message.message_id, reply_markup=back_button()
        )

    elif call.data == "menu_passcheck":
        user_state[uid] = "await_password"
        bot.edit_message_text(
            "🔓 Tekshirmoqchi bo'lgan parolingizni yuboring.\n\n"
            "⚠️ Xabaringiz tekshirilgandan so'ng darhol o'chiriladi.",
            chat_id, call.message.message_id, reply_markup=back_button()
        )

    elif call.data == "menu_2fa":
        text = (
            "🛡 *Ikki bosqichli tasdiqlash (2FA)*\n\n"
            "Parolga qo'shimcha himoya qatlami — parolingizni bilib olishsa ham, "
            "ikkinchi kod bo'lmasa hisobingizga kira olmaydi.\n\n"
            "*Telegram'da:* Sozlamalar → Privacy and Security → Two-Step Verification\n"
            "*Google'da:* myaccount.google.com → Security → 2-Step Verification\n\n"
            "💡 SMS o'rniga Google Authenticator yoki Authy'dan foydalaning."
        )
        bot.edit_message_text(text, chat_id, call.message.message_id)

    elif call.data == "menu_stats":
        data = load_data()
        user = data["users"].get(str(uid), {})
        text = (
            "📊 *Sizning statistikangiz*\n\n"
            f"🔗 Havola tekshirishlar: {user.get('url_checks', 0)}\n"
            f"🌐 Domen tekshirishlar: {user.get('domain_checks', 0)}\n"
            f"🌍 IP tekshirishlar: {user.get('ip_checks', 0)}\n"
            f"🔓 Parol tekshirishlar: {user.get('pass_checks', 0)}\n"
            f"📷 QR skanerlar: {user.get('qr_checks', 0)}\n"
            f"📄 Fayl tekshirishlar: {user.get('file_checks', 0)}"
        )
        bot.edit_message_text(text, chat_id, call.message.message_id)

    elif call.data == "menu_sub":
        data = load_data()
        is_sub = chat_id in data["subscribers"]
        kb = types.InlineKeyboardMarkup()
        if is_sub:
            kb.add(types.InlineKeyboardButton("❌ Obunani bekor qilish", callback_data="unsub_now"))
        else:
            kb.add(types.InlineKeyboardButton("✅ Obuna bo'lish", callback_data="sub_now"))
        kb.add(types.InlineKeyboardButton("⬅️ Bosh menyu", callback_data="menu_home"))
        status = "✅ Hozir obunasiz" if is_sub else "❌ Hozir obuna emassiz"
        bot.edit_message_text(
            f"🔔 *Kunlik xavfsizlik maslahati*\n\nHar kuni soat 09:00 da maslahat yuboriladi.\n\n{status}",
            chat_id, call.message.message_id, reply_markup=kb
        )

    elif call.data == "sub_now":
        data = load_data()
        if chat_id not in data["subscribers"]:
            data["subscribers"].append(chat_id)
            save_data(data)
        bot.edit_message_text("✅ Obuna bo'ldingiz!", chat_id, call.message.message_id)

    elif call.data == "unsub_now":
        data = load_data()
        if chat_id in data["subscribers"]:
            data["subscribers"].remove(chat_id)
            save_data(data)
        bot.edit_message_text("❌ Obuna bekor qilindi.", chat_id, call.message.message_id)

    elif call.data == "menu_emergency":
        text = (
            "🚨 *FAVQULODDA YO'RIQNOMA*\n\n"
            "1️⃣ Internetni o'chiring (Wi-Fi va Mobile Data)\n"
            "2️⃣ Shubhali/noma'lum APK'larni o'chiring\n"
            "3️⃣ Barcha begona qurilma sessiyalarini yoping\n"
            "4️⃣ Parollarni boshqa qurilmadan turib o'zgartiring"
        )
        bot.edit_message_text(text, chat_id, call.message.message_id)

    bot.answer_callback_query(call.id)


# ================== VirusTotal URL tahlili ==================
def analyze_url_with_vt(url: str) -> str:
    if not VT_API_KEY:
        return "⚠️ VirusTotal API kaliti sozlanmagan."
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
            notify_admin(f"Havola zararli deb topildi:\nLink: {url}\n\nZararli: {malicious}, Shubhali: {suspicious}")
            return f"🚨 *XAVFLI!*\n{malicious} antivirus zararli, {suspicious} ta shubhali deb belgiladi.\n\n⛔️ Bu havolani ochmang!"
        return f"✅ *Xavfsiz ko'rinadi*\n({harmless} antivirus tekshirdi, hech narsa topilmadi)"
    except requests.exceptions.RequestException as e:
        return f"❌ Xatolik: {e}"


def analyze_domain(domain: str) -> str:
    domain = domain.lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    if domain in POPULAR_DOMAINS:
        return f"✅ `{domain}` — mashhur, asl domen."

    matches = difflib.get_close_matches(domain, POPULAR_DOMAINS, n=3, cutoff=0.75)
    if matches:
        notify_admin(f"Fishing domen aniqlandi: {domain} (taqlid qilingan: {', '.join(matches)})")
        return (f"🚨 *DIQQAT!* `{domain}` quyidagilarga o'xshaydi:\n"
                + "\n".join(f"• {m}" for m in matches)
                + "\n\nBu fishing sayt bo'lishi mumkin! ⛔️ Ochmang.")
    return f"ℹ️ `{domain}` ma'lum brendlarga o'xshamayapti, lekin ehtiyot bo'ling."


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
        tips.append("Maxsus belgilar qo'shing.")
    return score, tips


# ================== Kutilayotgan matn xabarlarni qayta ishlash ==================
@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text and not m.text.startswith('/'), content_types=['text'])
def handle_stateful_text(message):
    uid = message.from_user.id
    state = user_state.get(uid)
    text_in = message.text.strip()

    # ---- Pastdagi menyu tugmalari ----
    if text_in == BTN_CHECK:
        user_state[uid] = "await_url"
        bot.reply_to(message, "🔗 Tekshirmoqchi bo'lgan havolani yuboring (masalan: https://example.com)")
        return

    if text_in == BTN_DOMAIN:
        user_state[uid] = "await_domain"
        bot.reply_to(message, "🌐 Tekshirmoqchi bo'lgan domenni yuboring (masalan: gooogle.com)")
        return

    if text_in == BTN_IP:
        user_state[uid] = "await_ip"
        bot.reply_to(message, "🌍 Tekshirmoqchi bo'lgan IP yoki domenni yuboring (masalan: 8.8.8.8)")
        return

    if text_in == BTN_GENPASS:
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = "".join(random.choice(chars) for _ in range(16))
        bot.reply_to(message, f"🔐 Siz uchun yangi xavfsiz parol:\n\n`{pwd}`\n\n⚠️ Uni hech kimga bermang!")
        return

    if text_in == BTN_PASSCHECK:
        user_state[uid] = "await_password"
        bot.reply_to(message, "🔓 Tekshirmoqchi bo'lgan parolingizni yuboring.\n\n⚠️ Xabaringiz tekshirilgach darhol o'chiriladi.")
        return

    if text_in == BTN_2FA:
        text = (
            "🛡 *Ikki bosqichli tasdiqlash (2FA)*\n\n"
            "Parolga qo'shimcha himoya qatlami — parolingizni bilib olishsa ham, "
            "ikkinchi kod bo'lmasa hisobingizga kira olmaydi.\n\n"
            "*Telegram'da:* Sozlamalar → Privacy and Security → Two-Step Verification\n"
            "*Google'da:* myaccount.google.com → Security → 2-Step Verification\n\n"
            "💡 SMS o'rniga Google Authenticator yoki Authy'dan foydalaning."
        )
        bot.reply_to(message, text)
        return

    if text_in == BTN_STATS:
        data = load_data()
        user = data["users"].get(str(uid), {})
        text = (
            "📊 *Sizning statistikangiz*\n\n"
            f"🔗 Havola tekshirishlar: {user.get('url_checks', 0)}\n"
            f"🌐 Domen tekshirishlar: {user.get('domain_checks', 0)}\n"
            f"🌍 IP tekshirishlar: {user.get('ip_checks', 0)}\n"
            f"🔓 Parol tekshirishlar: {user.get('pass_checks', 0)}\n"
            f"📷 QR skanerlar: {user.get('qr_checks', 0)}\n"
            f"📄 Fayl tekshirishlar: {user.get('file_checks', 0)}"
        )
        bot.reply_to(message, text)
        return

    if text_in == BTN_SUB:
        data = load_data()
        is_sub = message.chat.id in data["subscribers"]
        kb = types.InlineKeyboardMarkup()
        if is_sub:
            kb.add(types.InlineKeyboardButton("❌ Obunani bekor qilish", callback_data="unsub_now"))
        else:
            kb.add(types.InlineKeyboardButton("✅ Obuna bo'lish", callback_data="sub_now"))
        status = "✅ Hozir obunasiz" if is_sub else "❌ Hozir obuna emassiz"
        bot.send_message(
            message.chat.id,
            f"🔔 *Kunlik xavfsizlik maslahati*\n\nHar kuni soat 09:00 da maslahat yuboriladi.\n\n{status}",
            reply_markup=kb
        )
        return

    if text_in == BTN_EMERGENCY:
        text = (
            "🚨 *FAVQULODDA YO'RIQNOMA*\n\n"
            "1️⃣ Internetni o'chiring (Wi-Fi va Mobile Data)\n"
            "2️⃣ Shubhali/noma'lum APK'larni o'chiring\n"
            "3️⃣ Barcha begona qurilma sessiyalarini yoping\n"
            "4️⃣ Parollarni boshqa qurilmadan turib o'zgartiring"
        )
        bot.reply_to(message, text)
        return

    if state == "await_url":
        user_state.pop(uid, None)
        bot.reply_to(message, "🔍 Tekshirilmoqda...")
        result = analyze_url_with_vt(message.text.strip())
        bump_stat(uid, "url_checks")
        bot.send_message(message.chat.id, result)
        return

    if state == "await_domain":
        user_state.pop(uid, None)
        result = analyze_domain(message.text.strip())
        bump_stat(uid, "domain_checks")
        bot.send_message(message.chat.id, result)
        return

    if state == "await_ip":
        user_state.pop(uid, None)
        target = message.text.strip()
        bump_stat(uid, "ip_checks")
        try:
            geo = requests.get(
                f"http://ip-api.com/json/{target}?fields=status,message,country,city,isp,org,proxy,hosting,query",
                timeout=10
            ).json()
        except requests.exceptions.RequestException as e:
            bot.send_message(message.chat.id, f"❌ Xatolik: {e}")
            return

        if geo.get("status") != "success":
            error_text = geo.get('message', "noma'lum xato")
            bot.send_message(message.chat.id, f"❌ Ma'lumot topilmadi: {error_text}")
            return

        lines = [
            f"🌍 IP: `{geo.get('query')}`",
            f"Davlat: {geo.get('country')}, Shahar: {geo.get('city')}",
            f"Provayder: {geo.get('isp')}",
        ]
        if geo.get("proxy"):
            lines.append("⚠️ VPN/Proksi server sifatida belgilangan.")
        if geo.get("hosting"):
            lines.append("⚠️ Bu hosting/server IP.")

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

        bot.send_message(message.chat.id, "\n".join(lines))
        return

    if state == "await_password":
        user_state.pop(uid, None)
        pwd = message.text.strip()
        try:
            bot.delete_message(message.chat.id, message.message_id)
        except Exception:
            pass

        score, tips = password_strength_score(pwd)
        bump_stat(uid, "pass_checks")

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
            lines.append("Tavsiyalar:\n• " + "\n• ".join(tips))
        if breached_count is None:
            lines.append("⚠️ Bazani tekshirib bo'lmadi.")
        elif breached_count > 0:
            lines.append(f"🚨 Bu parol {breached_count} marta sizib chiqishda uchragan! DARHOL almashtiring.")
        else:
            lines.append("✅ Bu parol ma'lum sizib chiqishlar bazasida topilmadi.")

        bot.send_message(message.chat.id, "\n\n".join(lines))
        return

    # Holat yo'q bo'lsa — oddiy javob
    text = message.text.lower()
    if "http" in text or "t.me" in text or ".apk" in text:
        bot.reply_to(message, "⚠️ Havola/fayl ko'ryapman. Asosiy menyudan tegishli bo'limni tanlang: /menu")
    else:
        bot.reply_to(message, "🏠 Asosiy menyu uchun /menu ni bosing.", reply_markup=main_menu())


def send_daily_tip():
    data = load_data()
    tip = random.choice(DAILY_TIPS)
    for chat_id in data.get("subscribers", []):
        try:
            bot.send_message(chat_id, f"💡 *Kunlik maslahat*\n\n{tip}")
        except Exception:
            pass


def scheduler_loop():
    schedule.every().day.at("09:00").do(send_daily_tip)
    while True:
        schedule.run_pending()
        time.sleep(30)


# ================== Adminga zudlik bilan xabar berish ==================
def notify_admin(text: str):
    if not ADMIN_ID:
        return
    try:
        bot.send_message(int(ADMIN_ID), f"🚨 *XAVFSIZLIK OGOHLANTIRISHI*\n\n{text}")
    except Exception:
        pass


# ================== QR-kod skaneri ==================
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
        bot.reply_to(message, f"📷 QR-koddan topildi:\n`{data}`\n\n🔍 Tekshirilmoqda...")

        if data.startswith("http"):
            domain_result = analyze_domain(data)
            vt_result = analyze_url_with_vt(data)
            bot.send_message(message.chat.id, f"{domain_result}\n\n{vt_result}")
        else:
            bot.send_message(message.chat.id, "Bu havola emas, qo'shimcha tekshirish o'tkazilmadi.")
    except Exception as e:
        bot.reply_to(message, f"❌ QR-kodni o'qishda xatolik: {e}")


# ================== Fayl tekshirish ==================
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
            bot.send_message(
                message.chat.id,
                "ℹ️ Bu fayl VirusTotal bazasida topilmadi. virustotal.com'ga qo'lda yuklab tekshirishingiz mumkin.",
                reply_markup=back_button()
            )
            return

        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious > 0 or suspicious > 0:
            verdict = f"🚨 *XAVFLI FAYL!*\n{malicious} antivirus zararli, {suspicious} ta shubhali deb belgiladi.\n\n⛔️ Bu faylni OCHMANG, darhol o'chiring!"
            username = message.from_user.username or message.from_user.first_name
            notify_admin(
                f"Foydalanuvchi @{username} zararli fayl yubordi/tekshirdi:\n"
                f"Fayl: {message.document.file_name}\nSHA256: `{sha256}`\n"
                f"Zararli: {malicious}, Shubhali: {suspicious}"
            )
        else:
            verdict = f"✅ Fayl xavfsiz ko'rinadi ({harmless} antivirus tekshirdi)."

        bot.send_message(
            message.chat.id,
            f"📄 Fayl: {message.document.file_name}\nSHA256: `{sha256}`\n\n{verdict}",
            reply_markup=back_button()
        )
    except requests.exceptions.RequestException as e:
        bot.reply_to(message, f"❌ Xatolik: {e}")


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
                    f"fishing domenga o'xshaganligi uchun o'chirildi: `{domain}`",
                )
            except Exception:
                bot.reply_to(message, f"⚠️ Diqqat: `{domain}` fishing bo'lishi mumkin (men admin emasman).")
            return


if __name__ == "__main__":
    threading.Thread(target=scheduler_loop, daemon=True).start()
    print("CyberGuard boti (zamonaviy versiya) ishga tushdi...")
    bot.infinity_polling()
