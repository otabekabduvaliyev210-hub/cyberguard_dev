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
from fpdf import FPDF

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ADMIN_ID = os.getenv("ADMIN_ID")
WEBAPP_URL = os.getenv("WEBAPP_URL")
NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY")
OCRSPACE_API_KEY = os.getenv("OCRSPACE_API_KEY")

if not TOKEN:
    raise RuntimeError("BOT_TOKEN topilmadi. .env faylida BOT_TOKEN=... deb yozing.")

bot = telebot.TeleBot(TOKEN, parse_mode="Markdown")

DATA_FILE = "data.json"
user_state = {}
last_report = {}  # uid -> (title, [lines])  -- PDF hisobot uchun

POPULAR_DOMAINS = [
    "google.com", "facebook.com", "instagram.com", "telegram.org",
    "youtube.com", "whatsapp.com", "paypal.com", "apple.com",
    "microsoft.com", "amazon.com", "netflix.com", "binance.com",
    "click.uz", "payme.uz", "humo.uz", "uzcard.uz", "mail.ru",
]

PHISH_KEYWORDS = [
    "hisobingiz bloklandi", "hisobingiz bloklanadi", "karta blocklandi",
    "yutuqingizni oling", "sovg'angizni oling", "bonus", "aksiya tugaydi",
    "shoshiling", "darhol", "kodni yuboring", "parolni yuboring",
    "tasdiqlash kodi", "bank kartangiz", "hisobingizga kiring",
    "заблокирован", "приз", "бонус", "срочно", "код подтверждения",
    "your account is blocked", "claim your prize", "verify now", "urgent",
    "click here", "send code", "confirm your password",
]

LANGS = {"uz": "🇺🇿 O'zbekcha", "ru": "🇷🇺 Русский", "en": "🇬🇧 English"}

BUTTONS = {
    "webapp":   {"uz": "🧩 Mini-ilovani ochish", "ru": "🧩 Открыть Mini App", "en": "🧩 Open Mini App"},
    "check":    {"uz": "🔗 Havola tekshirish", "ru": "🔗 Проверить ссылку", "en": "🔗 Check link"},
    "domain":   {"uz": "🌐 Domen tekshirish", "ru": "🌐 Проверить домен", "en": "🌐 Check domain"},
    "ip":       {"uz": "🌍 IP tekshirish", "ru": "🌍 Проверить IP", "en": "🌍 Check IP"},
    "genpass":  {"uz": "🔐 Parol yaratish", "ru": "🔐 Создать пароль", "en": "🔐 Generate password"},
    "passcheck":{"uz": "🔓 Parol tekshirish", "ru": "🔓 Проверить пароль", "en": "🔓 Check password"},
    "phone":    {"uz": "📞 Raqam tekshirish", "ru": "📞 Проверить номер", "en": "📞 Check phone"},
    "sms":      {"uz": "✉️ SMS tahlil qilish", "ru": "✉️ Анализ SMS", "en": "✉️ Analyze SMS"},
    "2fa":      {"uz": "🛡 2FA qo'llanma", "ru": "🛡 Инструкция 2FA", "en": "🛡 2FA guide"},
    "stats":    {"uz": "📊 Statistika", "ru": "📊 Статистика", "en": "📊 Stats"},
    "sub":      {"uz": "🔔 Kunlik maslahat", "ru": "🔔 Совет дня", "en": "🔔 Daily tip"},
    "emergency":{"uz": "🚨 Favqulodda yordam", "ru": "🚨 Экстренная помощь", "en": "🚨 Emergency help"},
    "lang":     {"uz": "🌐 Til / Язык / Language", "ru": "🌐 Til / Язык / Language", "en": "🌐 Til / Язык / Language"},
}

# Matn (tugma) -> action, barcha tillar bo'yicha
ACTION_BY_LABEL = {}
for _action, _langs in BUTTONS.items():
    for _lbl in _langs.values():
        ACTION_BY_LABEL[_lbl] = _action

MSG = {
    "welcome": {
        "uz": "🛡️ *CyberGuard* — kiberxavfsizlik yordamchingiz\n\nPastdagi menyudan kerakli bo'limni tanlang 👇\n\n📎 QR-kod, skrinshot yoki fayl (APK/DOC) yuborsangiz, avtomatik tekshiraman.",
        "ru": "🛡️ *CyberGuard* — ваш помощник по кибербезопасности\n\nВыберите раздел в меню ниже 👇\n\n📎 Отправьте QR-код, скриншот или файл (APK/DOC) — проверю автоматически.",
        "en": "🛡️ *CyberGuard* — your cybersecurity assistant\n\nChoose an option from the menu below 👇\n\n📎 Send a QR code, screenshot, or file (APK/DOC) and I'll check it automatically.",
    },
    "menu_title": {"uz": "🏠 Bosh menyu:", "ru": "🏠 Главное меню:", "en": "🏠 Main menu:"},
    "prompt_check": {
        "uz": "🔗 Tekshirmoqchi bo'lgan havolani yuboring (masalan: https://example.com)",
        "ru": "🔗 Отправьте ссылку для проверки (например: https://example.com)",
        "en": "🔗 Send the link you want to check (e.g. https://example.com)",
    },
    "prompt_domain": {
        "uz": "🌐 Tekshirmoqchi bo'lgan domenni yuboring (masalan: gooogle.com)",
        "ru": "🌐 Отправьте домен для проверки (например: gooogle.com)",
        "en": "🌐 Send the domain to check (e.g. gooogle.com)",
    },
    "prompt_ip": {
        "uz": "🌍 Tekshirmoqchi bo'lgan IP yoki domenni yuboring (masalan: 8.8.8.8)",
        "ru": "🌍 Отправьте IP или домен (например: 8.8.8.8)",
        "en": "🌍 Send an IP or domain (e.g. 8.8.8.8)",
    },
    "prompt_pass": {
        "uz": "🔓 Tekshirmoqchi bo'lgan parolingizni yuboring.\n⚠️ Xabaringiz tekshirilgach darhol o'chiriladi.",
        "ru": "🔓 Отправьте пароль для проверки.\n⚠️ Сообщение будет удалено сразу после проверки.",
        "en": "🔓 Send the password to check.\n⚠️ Your message will be deleted right after checking.",
    },
    "prompt_phone": {
        "uz": "📞 Tekshirmoqchi bo'lgan telefon raqamni xalqaro formatda yuboring (masalan: +998901234567)",
        "ru": "📞 Отправьте номер телефона в международном формате (например: +998901234567)",
        "en": "📞 Send the phone number in international format (e.g. +998901234567)",
    },
    "prompt_sms": {
        "uz": "✉️ Shubhali deb o'ylagan SMS/xabar matnini to'liq yuboring.",
        "ru": "✉️ Отправьте полный текст подозрительного SMS/сообщения.",
        "en": "✉️ Send the full text of the suspicious SMS/message.",
    },
    "genpass_result": {
        "uz": "🔐 Siz uchun yangi xavfsiz parol:\n\n`{pwd}`\n\n⚠️ Uni hech kimga bermang!",
        "ru": "🔐 Ваш новый надёжный пароль:\n\n`{pwd}`\n\n⚠️ Никому его не сообщайте!",
        "en": "🔐 Your new secure password:\n\n`{pwd}`\n\n⚠️ Don't share it with anyone!",
    },
    "vt_no_key": {
        "uz": "⚠️ VirusTotal API kaliti sozlanmagan.",
        "ru": "⚠️ API-ключ VirusTotal не настроен.",
        "en": "⚠️ VirusTotal API key is not configured.",
    },
    "vt_malicious": {
        "uz": "🚨 *XAVFLI!*\n{mal} antivirus zararli, {sus} ta shubhali deb belgiladi.\n\n⛔️ Bu havolani ochmang!",
        "ru": "🚨 *ОПАСНО!*\n{mal} антивирусов пометили как вредоносное, {sus} — как подозрительное.\n\n⛔️ Не открывайте эту ссылку!",
        "en": "🚨 *DANGEROUS!*\n{mal} engines flagged it malicious, {sus} suspicious.\n\n⛔️ Do not open this link!",
    },
    "vt_safe": {
        "uz": "✅ *Xavfsiz ko'rinadi*\n({harm} antivirus tekshirdi, hech narsa topilmadi)",
        "ru": "✅ *Похоже, безопасно*\n(проверено {harm} антивирусами, ничего не найдено)",
        "en": "✅ *Looks safe*\n(checked by {harm} engines, nothing found)",
    },
    "vt_pending": {
        "uz": "⏱️ Tahlil hali tugamadi, birozdan keyin qayta urinib ko'ring.",
        "ru": "⏱️ Анализ ещё не завершён, попробуйте позже.",
        "en": "⏱️ Analysis not finished yet, try again shortly.",
    },
    "generic_error": {"uz": "❌ Xatolik: {err}", "ru": "❌ Ошибка: {err}", "en": "❌ Error: {err}"},
    "domain_known": {
        "uz": "✅ `{d}` — mashhur, asl domen.",
        "ru": "✅ `{d}` — известный, настоящий домен.",
        "en": "✅ `{d}` — a known, genuine domain.",
    },
    "domain_phish": {
        "uz": "🚨 *DIQQAT!* `{d}` quyidagilarga o'xshaydi:\n{m}\n\nBu fishing sayt bo'lishi mumkin! ⛔️ Ochmang.",
        "ru": "🚨 *ВНИМАНИЕ!* `{d}` похож на:\n{m}\n\nВозможно, это фишинговый сайт! ⛔️ Не открывайте.",
        "en": "🚨 *WARNING!* `{d}` looks similar to:\n{m}\n\nThis may be a phishing site! ⛔️ Don't open it.",
    },
    "domain_unknown": {
        "uz": "ℹ️ `{d}` ma'lum brendlarga o'xshamayapti, lekin ehtiyot bo'ling.",
        "ru": "ℹ️ `{d}` не похож на известные бренды, но будьте осторожны.",
        "en": "ℹ️ `{d}` doesn't resemble known brands, but stay cautious.",
    },
    "ip_not_found": {
        "uz": "❌ Ma'lumot topilmadi: {err}",
        "ru": "❌ Информация не найдена: {err}",
        "en": "❌ No information found: {err}",
    },
    "ip_vpn": {"uz": "⚠️ VPN/Proksi server sifatida belgilangan.", "ru": "⚠️ Отмечен как VPN/прокси.", "en": "⚠️ Flagged as VPN/proxy."},
    "ip_hosting": {"uz": "⚠️ Bu hosting/server IP.", "ru": "⚠️ Это хостинг/серверный IP.", "en": "⚠️ This is a hosting/server IP."},
    "ip_abuse": {"uz": "🚨 AbuseIPDB xavf balli: {score}/100", "ru": "🚨 Балл риска AbuseIPDB: {score}/100", "en": "🚨 AbuseIPDB risk score: {score}/100"},
    "pass_score": {"uz": "🔐 Parol kuchi: {s}/6", "ru": "🔐 Надёжность пароля: {s}/6", "en": "🔐 Password strength: {s}/6"},
    "pass_tips_label": {"uz": "Tavsiyalar:", "ru": "Рекомендации:", "en": "Tips:"},
    "tip_len": {"uz": "Parol kamida 12 ta belgidan iborat bo'lsin.", "ru": "Пароль должен быть не менее 12 символов.", "en": "Password should be at least 12 characters."},
    "tip_lower": {"uz": "Kichik harflar qo'shing.", "ru": "Добавьте строчные буквы.", "en": "Add lowercase letters."},
    "tip_upper": {"uz": "Katta harflar qo'shing.", "ru": "Добавьте заглавные буквы.", "en": "Add uppercase letters."},
    "tip_digit": {"uz": "Raqamlar qo'shing.", "ru": "Добавьте цифры.", "en": "Add digits."},
    "tip_special": {"uz": "Maxsus belgilar qo'shing.", "ru": "Добавьте спецсимволы.", "en": "Add special characters."},
    "breach_err": {"uz": "⚠️ Bazani tekshirib bo'lmadi.", "ru": "⚠️ Не удалось проверить базу.", "en": "⚠️ Could not check the database."},
    "breach_found": {"uz": "🚨 Bu parol {c} marta sizib chiqishda uchragan! DARHOL almashtiring.", "ru": "🚨 Этот пароль встречался в утечках {c} раз! Срочно смените его.", "en": "🚨 This password has appeared in breaches {c} times! Change it immediately."},
    "breach_clean": {"uz": "✅ Bu parol ma'lum sizib chiqishlar bazasida topilmadi.", "ru": "✅ Пароль не найден в известных утечках.", "en": "✅ This password wasn't found in known breaches."},
    "2fa_text": {
        "uz": "🛡 *Ikki bosqichli tasdiqlash (2FA)*\n\n*Telegram'da:* Sozlamalar → Privacy and Security → Two-Step Verification\n*Google'da:* myaccount.google.com → Security → 2-Step Verification\n\n💡 SMS o'rniga Google Authenticator yoki Authy'dan foydalaning.",
        "ru": "🛡 *Двухфакторная аутентификация (2FA)*\n\n*В Telegram:* Настройки → Приватность → Двухэтапная проверка\n*В Google:* myaccount.google.com → Безопасность → Двухэтапная аутентификация\n\n💡 Вместо SMS используйте Google Authenticator или Authy.",
        "en": "🛡 *Two-Factor Authentication (2FA)*\n\n*Telegram:* Settings → Privacy and Security → Two-Step Verification\n*Google:* myaccount.google.com → Security → 2-Step Verification\n\n💡 Use Google Authenticator or Authy instead of SMS.",
    },
    "emergency_text": {
        "uz": "🚨 *FAVQULODDA YO'RIQNOMA*\n\n1️⃣ Internetni o'chiring\n2️⃣ Shubhali APK'larni o'chiring\n3️⃣ Begona sessiyalarni yoping\n4️⃣ Parollarni almashtiring",
        "ru": "🚨 *ЭКСТРЕННАЯ ИНСТРУКЦИЯ*\n\n1️⃣ Отключите интернет\n2️⃣ Удалите подозрительные APK\n3️⃣ Завершите чужие сессии\n4️⃣ Смените пароли",
        "en": "🚨 *EMERGENCY GUIDE*\n\n1️⃣ Turn off the internet\n2️⃣ Remove suspicious APKs\n3️⃣ Close unfamiliar sessions\n4️⃣ Change your passwords",
    },
    "stats_header": {"uz": "📊 *Sizning statistikangiz*", "ru": "📊 *Ваша статистика*", "en": "📊 *Your stats*"},
    "sub_header": {"uz": "🔔 *Kunlik xavfsizlik maslahati*\n\nHar kuni soat 09:00 da maslahat yuboriladi.", "ru": "🔔 *Совет дня по безопасности*\n\nСовет отправляется каждый день в 09:00.", "en": "🔔 *Daily security tip*\n\nA tip is sent every day at 09:00."},
    "sub_on": {"uz": "✅ Hozir obunasiz", "ru": "✅ Вы подписаны", "en": "✅ You're subscribed"},
    "sub_off": {"uz": "❌ Hozir obuna emassiz", "ru": "❌ Вы не подписаны", "en": "❌ You're not subscribed"},
    "sub_btn_on": {"uz": "✅ Obuna bo'lish", "ru": "✅ Подписаться", "en": "✅ Subscribe"},
    "sub_btn_off": {"uz": "❌ Obunani bekor qilish", "ru": "❌ Отписаться", "en": "❌ Unsubscribe"},
    "sub_done": {"uz": "✅ Obuna bo'ldingiz!", "ru": "✅ Вы подписались!", "en": "✅ Subscribed!"},
    "unsub_done": {"uz": "❌ Obuna bekor qilindi.", "ru": "❌ Подписка отменена.", "en": "❌ Unsubscribed."},
    "lang_prompt": {"uz": "🌐 Tilni tanlang:", "ru": "🌐 Выберите язык:", "en": "🌐 Choose a language:"},
    "lang_set": {"uz": "✅ Til o'zbekchaga o'zgartirildi.", "ru": "✅ Язык изменён на русский.", "en": "✅ Language set to English."},
    "phone_no_key": {
        "uz": "⚠️ Telefon tekshirish xizmati sozlanmagan (NUMVERIFY_API_KEY yo'q). Bepul kalitni numverify.com'dan olishingiz mumkin.",
        "ru": "⚠️ Сервис проверки номеров не настроен (нет NUMVERIFY_API_KEY). Бесплатный ключ можно получить на numverify.com.",
        "en": "⚠️ Phone check service isn't configured (missing NUMVERIFY_API_KEY). Get a free key at numverify.com.",
    },
    "phone_invalid": {"uz": "❌ Raqam noto'g'ri yoki topilmadi.", "ru": "❌ Номер неверен или не найден.", "en": "❌ Number is invalid or not found."},
    "pdf_btn": {"uz": "📄 PDF hisobot", "ru": "📄 PDF-отчёт", "en": "📄 PDF report"},
    "pdf_caption": {"uz": "📄 Hisobotingiz tayyor.", "ru": "📄 Ваш отчёт готов.", "en": "📄 Your report is ready."},
    "qr_not_found": {"uz": "ℹ️ Rasmda QR-kod topilmadi, matn izlanmoqda...", "ru": "ℹ️ QR-код не найден, ищу текст...", "en": "ℹ️ No QR code found, looking for text..."},
    "ocr_no_key": {"uz": "ℹ️ Rasmda QR-kod topilmadi (matn o'qish uchun OCRSPACE_API_KEY sozlanmagan).", "ru": "ℹ️ QR-код не найден (для распознавания текста нужен OCRSPACE_API_KEY).", "en": "ℹ️ No QR code found (OCRSPACE_API_KEY needed for text recognition)."},
    "ocr_empty": {"uz": "ℹ️ Rasmda QR-kod ham, o'qiladigan matn ham topilmadi.", "ru": "ℹ️ Не найден ни QR-код, ни читаемый текст.", "en": "ℹ️ Neither a QR code nor readable text was found."},
    "sms_header": {"uz": "✉️ *SMS tahlili natijasi*", "ru": "✉️ *Результат анализа SMS*", "en": "✉️ *SMS analysis result*"},
    "sms_high": {"uz": "🚨 Yuqori xavf — bu fishing/firibgarlik xabari bo'lishi mumkin!", "ru": "🚨 Высокий риск — возможно, это фишинговое/мошенническое сообщение!", "en": "🚨 High risk — this may be a phishing/scam message!"},
    "sms_low": {"uz": "✅ Shubhali belgilar topilmadi.", "ru": "✅ Подозрительных признаков не найдено.", "en": "✅ No suspicious signs found."},
    "sms_reasons": {"uz": "Sabab(lar):", "ru": "Причины:", "en": "Reason(s):"},
    "default_reply": {"uz": "🏠 Asosiy menyu uchun /menu ni bosing.", "ru": "🏠 Нажмите /menu для главного меню.", "en": "🏠 Press /menu for the main menu."},
}


def t(key, lang, **kwargs):
    template = MSG.get(key, {}).get(lang) or MSG.get(key, {}).get("uz", "")
    return template.format(**kwargs) if kwargs else template


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


def get_lang(user_id: int) -> str:
    data = load_data()
    return data["users"].get(str(user_id), {}).get("lang", "uz")


def set_lang(user_id: int, lang: str):
    data = load_data()
    uid = str(user_id)
    if uid not in data["users"]:
        data["users"][uid] = {}
    data["users"][uid]["lang"] = lang
    save_data(data)


def notify_admin(text: str):
    if not ADMIN_ID:
        return
    try:
        bot.send_message(int(ADMIN_ID), f"🚨 *XAVFSIZLIK OGOHLANTIRISHI*\n\n{text}")
    except Exception:
        pass


# ================== Menyu ==================
def main_menu_keyboard(lang):
    kb = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    if WEBAPP_URL:
        kb.add(types.KeyboardButton(BUTTONS["webapp"][lang], web_app=types.WebAppInfo(WEBAPP_URL)))
    kb.add(types.KeyboardButton(BUTTONS["check"][lang]), types.KeyboardButton(BUTTONS["domain"][lang]))
    kb.add(types.KeyboardButton(BUTTONS["ip"][lang]), types.KeyboardButton(BUTTONS["phone"][lang]))
    kb.add(types.KeyboardButton(BUTTONS["genpass"][lang]), types.KeyboardButton(BUTTONS["passcheck"][lang]))
    kb.add(types.KeyboardButton(BUTTONS["sms"][lang]), types.KeyboardButton(BUTTONS["2fa"][lang]))
    kb.add(types.KeyboardButton(BUTTONS["stats"][lang]), types.KeyboardButton(BUTTONS["sub"][lang]))
    kb.add(types.KeyboardButton(BUTTONS["emergency"][lang]), types.KeyboardButton(BUTTONS["lang"][lang]))
    return kb


def pdf_button(lang):
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton(t("pdf_btn", lang), callback_data="get_pdf"))
    return kb


# ================== /start, /menu, /til ==================
def perform_action(chat_id, uid, lang, action):
    prompts = {
        "check": ("await_url", "prompt_check"),
        "domain": ("await_domain", "prompt_domain"),
        "ip": ("await_ip", "prompt_ip"),
        "passcheck": ("await_password", "prompt_pass"),
        "phone": ("await_phone", "prompt_phone"),
        "sms": ("await_sms", "prompt_sms"),
    }
    if action in prompts:
        state, msg_key = prompts[action]
        user_state[uid] = state
        bot.send_message(chat_id, t(msg_key, lang))
        return True
    if action == "genpass":
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = "".join(random.choice(chars) for _ in range(16))
        bot.send_message(chat_id, t("genpass_result", lang, pwd=pwd))
        return True
    if action == "2fa":
        bot.send_message(chat_id, t("2fa_text", lang))
        return True
    if action == "stats":
        data = load_data()
        user = data["users"].get(str(uid), {})
        bot.send_message(chat_id, t("stats_header", lang) + f"\n\n🔗{user.get('url_checks',0)} 🌐{user.get('domain_checks',0)} 🌍{user.get('ip_checks',0)} 🔓{user.get('pass_checks',0)}")
        return True
    if action == "emergency":
        bot.send_message(chat_id, t("emergency_text", lang))
        return True
    return False


@bot.message_handler(commands=['start'])
def send_welcome(message):
    uid = message.from_user.id
    user_state.pop(uid, None)
    lang = get_lang(uid)

    parts = message.text.split(maxsplit=1)
    payload = parts[1].strip() if len(parts) > 1 else None
    if payload and perform_action(message.chat.id, uid, lang, payload):
        return

    bot.send_message(message.chat.id, t("welcome", lang), reply_markup=main_menu_keyboard(lang))


@bot.message_handler(commands=['menu'])
def menu_command(message):
    uid = message.from_user.id
    user_state.pop(uid, None)
    lang = get_lang(uid)
    bot.send_message(message.chat.id, t("menu_title", lang), reply_markup=main_menu_keyboard(lang))


@bot.message_handler(commands=['help'])
def help_command(message):
    bot.reply_to(message, "/start yoki /menu ni bosing.")


def show_lang_picker(chat_id, lang):
    kb = types.InlineKeyboardMarkup()
    for code, label in LANGS.items():
        kb.add(types.InlineKeyboardButton(label, callback_data=f"setlang_{code}"))
    bot.send_message(chat_id, t("lang_prompt", lang), reply_markup=kb)


@bot.message_handler(commands=['til', 'language', 'lang'])
def lang_command(message):
    show_lang_picker(message.chat.id, get_lang(message.from_user.id))


# ================== Callback'lar ==================
@bot.callback_query_handler(func=lambda call: call.data.startswith("setlang_"))
def handle_setlang(call):
    uid = call.from_user.id
    lang = call.data.split("_", 1)[1]
    if lang not in LANGS:
        lang = "uz"
    set_lang(uid, lang)
    bot.answer_callback_query(call.id)
    bot.send_message(call.message.chat.id, t("lang_set", lang), reply_markup=main_menu_keyboard(lang))


@bot.callback_query_handler(func=lambda call: call.data in ("sub_now", "unsub_now"))
def handle_sub_toggle(call):
    uid = call.from_user.id
    lang = get_lang(uid)
    chat_id = call.message.chat.id
    data = load_data()
    if call.data == "sub_now":
        if chat_id not in data["subscribers"]:
            data["subscribers"].append(chat_id)
            save_data(data)
        bot.edit_message_text(t("sub_done", lang), chat_id, call.message.message_id)
    else:
        if chat_id in data["subscribers"]:
            data["subscribers"].remove(chat_id)
            save_data(data)
        bot.edit_message_text(t("unsub_done", lang), chat_id, call.message.message_id)
    bot.answer_callback_query(call.id)


@bot.callback_query_handler(func=lambda call: call.data == "get_pdf")
def handle_get_pdf(call):
    uid = call.from_user.id
    lang = get_lang(uid)
    report = last_report.get(uid)
    bot.answer_callback_query(call.id)
    if not report:
        return
    title, lines = report
    path = generate_pdf(title, lines)
    with open(path, "rb") as f:
        bot.send_document(call.message.chat.id, f, caption=t("pdf_caption", lang))
    try:
        os.remove(path)
    except Exception:
        pass


# ================== PDF yaratish ==================
def generate_pdf(title: str, lines) -> str:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.multi_cell(0, 10, title)
    pdf.ln(4)
    pdf.set_font("Helvetica", size=11)
    for line in lines:
        safe = line.encode("latin-1", "replace").decode("latin-1")
        pdf.multi_cell(0, 7, safe)
    path = f"/tmp/report_{int(time.time())}.pdf"
    pdf.output(path)
    return path


# ================== Tekshirish funksiyalari ==================
def analyze_url_with_vt(url: str, lang: str) -> str:
    if not VT_API_KEY:
        return t("vt_no_key", lang)
    try:
        headers = {"x-apikey": VT_API_KEY}
        submit = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=15)
        submit.raise_for_status()
        analysis_id = submit.json()["data"]["id"]

        result = None
        for _ in range(6):
            resp = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()["data"]["attributes"]
            if data["status"] == "completed":
                result = data["stats"]
                break
            time.sleep(3)

        if not result:
            return t("vt_pending", lang)

        malicious = result.get("malicious", 0)
        suspicious = result.get("suspicious", 0)
        harmless = result.get("harmless", 0)

        if malicious > 0 or suspicious > 0:
            notify_admin(f"Havola zararli deb topildi:\nLink: {url}\n\nZararli: {malicious}, Shubhali: {suspicious}")
            return t("vt_malicious", lang, mal=malicious, sus=suspicious)
        return t("vt_safe", lang, harm=harmless)
    except requests.exceptions.RequestException as e:
        return t("generic_error", lang, err=e)


def analyze_domain(domain: str, lang: str) -> str:
    domain = domain.lower()
    domain = re.sub(r"^https?://", "", domain).split("/")[0]

    if domain in POPULAR_DOMAINS:
        return t("domain_known", lang, d=domain)

    matches = difflib.get_close_matches(domain, POPULAR_DOMAINS, n=3, cutoff=0.75)
    if matches:
        notify_admin(f"Fishing domen aniqlandi: {domain} (taqlid: {', '.join(matches)})")
        m = "\n".join(f"• {x}" for x in matches)
        return t("domain_phish", lang, d=domain, m=m)
    return t("domain_unknown", lang, d=domain)


def password_strength_score(pwd: str, lang: str):
    score = 0
    tips = []
    if len(pwd) >= 12:
        score += 2
    elif len(pwd) >= 8:
        score += 1
    else:
        tips.append(t("tip_len", lang))
    if re.search(r"[a-z]", pwd):
        score += 1
    else:
        tips.append(t("tip_lower", lang))
    if re.search(r"[A-Z]", pwd):
        score += 1
    else:
        tips.append(t("tip_upper", lang))
    if re.search(r"\d", pwd):
        score += 1
    else:
        tips.append(t("tip_digit", lang))
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", pwd):
        score += 1
    else:
        tips.append(t("tip_special", lang))
    return score, tips


def analyze_sms(text: str, lang: str):
    lowered = text.lower()
    reasons = []
    score = 0

    for kw in PHISH_KEYWORDS:
        if kw in lowered:
            reasons.append(kw)
            score += 1

    urls = re.findall(r"(?:https?://|www\.)[^\s]+", lowered)
    if urls:
        score += 2
        reasons.append("URL/havola mavjud" if lang == "uz" else ("Есть ссылка" if lang == "ru" else "Contains a link"))

    if re.search(r"\b\d{4,6}\b", text) and ("kod" in lowered or "code" in lowered or "код" in lowered):
        score += 1
        reasons.append("Tasdiqlash kodi so'ralmoqda" if lang == "uz" else ("Запрашивается код" if lang == "ru" else "Asking for a code"))

    is_high = score >= 2
    return is_high, reasons


def check_phone_number(phone: str, lang: str) -> str:
    if not NUMVERIFY_API_KEY:
        return t("phone_no_key", lang)
    try:
        resp = requests.get(
            "http://apilayer.net/api/validate",
            params={"access_key": NUMVERIFY_API_KEY, "number": phone},
            timeout=10,
        ).json()
    except requests.exceptions.RequestException as e:
        return t("generic_error", lang, err=e)

    if not resp.get("valid"):
        return t("phone_invalid", lang)

    lines = [
        f"📞 {resp.get('international_format', phone)}",
        f"{'Davlat' if lang=='uz' else ('Страна' if lang=='ru' else 'Country')}: {resp.get('country_name', '-')}",
        f"{'Operator' if lang=='uz' else ('Оператор' if lang=='ru' else 'Carrier')}: {resp.get('carrier') or '-'}",
        f"{'Turi' if lang=='uz' else ('Тип' if lang=='ru' else 'Line type')}: {resp.get('line_type') or '-'}",
    ]
    return "\n".join(lines)


# ================== Kutilayotgan matnlarni qayta ishlash ==================
@bot.message_handler(func=lambda m: m.chat.type == "private" and m.text and not m.text.startswith('/'), content_types=['text'])
def handle_stateful_text(message):
    uid = message.from_user.id
    lang = get_lang(uid)
    state = user_state.get(uid)
    text_in = message.text.strip()

    # ---- Menyu tugmalari (istalgan tildan) ----
    action = ACTION_BY_LABEL.get(text_in)
    if action:
        if action == "lang":
            show_lang_picker(message.chat.id, lang)
            return
        if action == "check":
            user_state[uid] = "await_url"
            bot.reply_to(message, t("prompt_check", lang))
            return
        if action == "domain":
            user_state[uid] = "await_domain"
            bot.reply_to(message, t("prompt_domain", lang))
            return
        if action == "ip":
            user_state[uid] = "await_ip"
            bot.reply_to(message, t("prompt_ip", lang))
            return
        if action == "phone":
            user_state[uid] = "await_phone"
            bot.reply_to(message, t("prompt_phone", lang))
            return
        if action == "sms":
            user_state[uid] = "await_sms"
            bot.reply_to(message, t("prompt_sms", lang))
            return
        if action == "genpass":
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            pwd = "".join(random.choice(chars) for _ in range(16))
            bot.reply_to(message, t("genpass_result", lang, pwd=pwd))
            return
        if action == "passcheck":
            user_state[uid] = "await_password"
            bot.reply_to(message, t("prompt_pass", lang))
            return
        if action == "2fa":
            bot.reply_to(message, t("2fa_text", lang))
            return
        if action == "stats":
            data = load_data()
            user = data["users"].get(str(uid), {})
            text = (
                t("stats_header", lang) + "\n\n"
                f"🔗 {user.get('url_checks', 0)}  🌐 {user.get('domain_checks', 0)}  🌍 {user.get('ip_checks', 0)}\n"
                f"🔓 {user.get('pass_checks', 0)}  📷 {user.get('qr_checks', 0)}  📄 {user.get('file_checks', 0)}\n"
                f"📞 {user.get('phone_checks', 0)}  ✉️ {user.get('sms_checks', 0)}"
            )
            bot.reply_to(message, text)
            return
        if action == "sub":
            data = load_data()
            is_sub = message.chat.id in data["subscribers"]
            kb = types.InlineKeyboardMarkup()
            kb.add(types.InlineKeyboardButton(
                t("sub_btn_off", lang) if is_sub else t("sub_btn_on", lang),
                callback_data="unsub_now" if is_sub else "sub_now"
            ))
            status = t("sub_on", lang) if is_sub else t("sub_off", lang)
            bot.send_message(message.chat.id, f"{t('sub_header', lang)}\n\n{status}", reply_markup=kb)
            return
        if action == "emergency":
            bot.reply_to(message, t("emergency_text", lang))
            return

    # ---- Holatga bog'liq javoblar ----
    if state == "await_url":
        user_state.pop(uid, None)
        bot.reply_to(message, "🔍 ..." )
        result = analyze_url_with_vt(text_in, lang)
        bump_stat(uid, "url_checks")
        last_report[uid] = ("CyberGuard — Havola tekshiruvi", [f"URL: {text_in}", "", result.replace('*', '')])
        bot.send_message(message.chat.id, result, reply_markup=pdf_button(lang))
        return

    if state == "await_domain":
        user_state.pop(uid, None)
        result = analyze_domain(text_in, lang)
        bump_stat(uid, "domain_checks")
        last_report[uid] = ("CyberGuard — Domen tekshiruvi", [f"Domain: {text_in}", "", result.replace('*', '')])
        bot.send_message(message.chat.id, result, reply_markup=pdf_button(lang))
        return

    if state == "await_ip":
        user_state.pop(uid, None)
        target = text_in
        bump_stat(uid, "ip_checks")
        try:
            geo = requests.get(
                f"http://ip-api.com/json/{target}?fields=status,message,country,city,isp,org,proxy,hosting,query",
                timeout=10
            ).json()
        except requests.exceptions.RequestException as e:
            bot.send_message(message.chat.id, t("generic_error", lang, err=e))
            return

        if geo.get("status") != "success":
            error_text = geo.get('message', "?")
            bot.send_message(message.chat.id, t("ip_not_found", lang, err=error_text))
            return

        lines = [
            f"🌍 IP: {geo.get('query')}",
            f"{geo.get('country')}, {geo.get('city')}",
            f"ISP: {geo.get('isp')}",
        ]
        if geo.get("proxy"):
            lines.append(t("ip_vpn", lang))
        if geo.get("hosting"):
            lines.append(t("ip_hosting", lang))

        if ABUSEIPDB_API_KEY:
            try:
                abuse = requests.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                    params={"ipAddress": target, "maxAgeInDays": 90},
                    timeout=10,
                ).json()
                sc = abuse.get("data", {}).get("abuseConfidenceScore")
                if sc is not None:
                    lines.append(t("ip_abuse", lang, score=sc))
            except requests.exceptions.RequestException:
                pass

        result_text = "\n".join(lines)
        last_report[uid] = ("CyberGuard — IP tekshiruvi", lines)
        bot.send_message(message.chat.id, result_text, reply_markup=pdf_button(lang))
        return

    if state == "await_phone":
        user_state.pop(uid, None)
        bump_stat(uid, "phone_checks")
        result = check_phone_number(text_in, lang)
        last_report[uid] = ("CyberGuard — Raqam tekshiruvi", [text_in, "", result])
        bot.send_message(message.chat.id, result, reply_markup=pdf_button(lang))
        return

    if state == "await_sms":
        user_state.pop(uid, None)
        bump_stat(uid, "sms_checks")
        is_high, reasons = analyze_sms(text_in, lang)
        verdict = t("sms_high", lang) if is_high else t("sms_low", lang)
        lines = [t("sms_header", lang), "", verdict]
        if reasons:
            lines.append("")
            lines.append(t("sms_reasons", lang) + " " + ", ".join(reasons))
        result_text = "\n".join(lines)
        last_report[uid] = ("CyberGuard — SMS tahlili", [text_in, "", verdict])
        bot.send_message(message.chat.id, result_text, reply_markup=pdf_button(lang))
        return

    if state == "await_password":
        user_state.pop(uid, None)
        pwd = text_in
        try:
            bot.delete_message(message.chat.id, message.message_id)
        except Exception:
            pass

        score, tips = password_strength_score(pwd, lang)
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

        lines = [t("pass_score", lang, s=score)]
        if tips:
            lines.append(t("pass_tips_label", lang) + " " + "; ".join(tips))
        if breached_count is None:
            lines.append(t("breach_err", lang))
        elif breached_count > 0:
            lines.append(t("breach_found", lang, c=breached_count))
        else:
            lines.append(t("breach_clean", lang))

        bot.send_message(message.chat.id, "\n\n".join(lines))
        return

    # Holat yo'q — oddiy javob
    lowered = text_in.lower()
    if "http" in lowered or "t.me" in lowered or ".apk" in lowered:
        bot.reply_to(message, t("default_reply", lang))
    else:
        bot.reply_to(message, t("default_reply", lang), reply_markup=main_menu_keyboard(lang))


DAILY_TIPS = {
    "uz": [
        "🔐 Har bir akkaunt uchun alohida parol ishlating.",
        "📱 Muhim akkauntlarda 2FA'ni yoqing.",
        "🔗 Noma'lum havolalarni /check orqali tekshiring.",
    ],
    "ru": [
        "🔐 Используйте разные пароли для разных аккаунтов.",
        "📱 Включите 2FA для важных аккаунтов.",
        "🔗 Проверяйте незнакомые ссылки перед открытием.",
    ],
    "en": [
        "🔐 Use a different password for every account.",
        "📱 Turn on 2FA for your important accounts.",
        "🔗 Check unfamiliar links before opening them.",
    ],
}


def send_daily_tip():
    data = load_data()
    for chat_id in data.get("subscribers", []):
        uid_lookup = None
        for uid_str, u in data["users"].items():
            pass
        lang = "uz"
        for uid_str, u in data["users"].items():
            try:
                if int(uid_str) == chat_id:
                    lang = u.get("lang", "uz")
            except ValueError:
                pass
        tip = random.choice(DAILY_TIPS.get(lang, DAILY_TIPS["uz"]))
        try:
            bot.send_message(chat_id, f"💡 {tip}")
        except Exception:
            pass


def scheduler_loop():
    schedule.every().day.at("09:00").do(send_daily_tip)
    while True:
        schedule.run_pending()
        time.sleep(30)


# ================== Mini App'dan kelgan ma'lumotlar (eski usul, zaxira) ==================
@bot.message_handler(content_types=['web_app_data'])
def handle_webapp_data(message):
    uid = message.from_user.id
    lang = get_lang(uid)
    action = message.web_app_data.data
    perform_action(message.chat.id, uid, lang, action)


# ================== QR-kod / OCR skaneri ==================
@bot.message_handler(content_types=['photo'])
def handle_qr_photo(message):
    uid = message.from_user.id
    lang = get_lang(uid)
    try:
        file_info = bot.get_file(message.photo[-1].file_id)
        file_bytes = bot.download_file(file_info.file_path)

        img_array = np.frombuffer(file_bytes, dtype=np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(img)

        if data:
            bump_stat(uid, "qr_checks")
            bot.reply_to(message, f"📷 QR-koddan topildi:\n`{data}`\n\n🔍 ...")
            if data.startswith("http"):
                domain_result = analyze_domain(data, lang)
                vt_result = analyze_url_with_vt(data, lang)
                bot.send_message(message.chat.id, f"{domain_result}\n\n{vt_result}")
            else:
                bot.send_message(message.chat.id, data)
            return

        # QR topilmadi -> OCR bilan matn izlash
        if not OCRSPACE_API_KEY:
            bot.reply_to(message, t("ocr_no_key", lang))
            return

        bot.reply_to(message, t("qr_not_found", lang))
        ocr_resp = requests.post(
            "https://api.ocr.space/parse/image",
            files={"file": ("image.jpg", file_bytes)},
            data={"apikey": OCRSPACE_API_KEY, "language": "eng", "OCREngine": 2},
            timeout=30,
        ).json()

        parsed = ""
        try:
            parsed = ocr_resp["ParsedResults"][0]["ParsedText"].strip()
        except Exception:
            parsed = ""

        if not parsed:
            bot.send_message(message.chat.id, t("ocr_empty", lang))
            return

        bump_stat(uid, "sms_checks")
        is_high, reasons = analyze_sms(parsed, lang)
        verdict = t("sms_high", lang) if is_high else t("sms_low", lang)
        lines = [f"📝 {parsed[:500]}", "", t("sms_header", lang), verdict]
        if reasons:
            lines.append(t("sms_reasons", lang) + " " + ", ".join(reasons))
        bot.send_message(message.chat.id, "\n".join(lines))

    except Exception as e:
        bot.reply_to(message, t("generic_error", lang, err=e))


# ================== Fayl tekshirish ==================
@bot.message_handler(content_types=['document'])
def handle_file(message):
    uid = message.from_user.id
    lang = get_lang(uid)
    if not VT_API_KEY:
        bot.reply_to(message, t("vt_no_key", lang))
        return

    bot.reply_to(message, "🔍 ...")

    try:
        file_info = bot.get_file(message.document.file_id)
        file_bytes = bot.download_file(file_info.file_path)

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        bump_stat(uid, "file_checks")

        headers = {"x-apikey": VT_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=15)

        if resp.status_code == 404:
            bot.send_message(message.chat.id, "ℹ️ VirusTotal bazasida topilmadi.")
            return

        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)

        if malicious > 0 or suspicious > 0:
            verdict = t("vt_malicious", lang, mal=malicious, sus=suspicious)
            username = message.from_user.username or message.from_user.first_name
            notify_admin(
                f"Foydalanuvchi @{username} zararli fayl yubordi:\n"
                f"Fayl: {message.document.file_name}\nSHA256: {sha256}\n"
                f"Zararli: {malicious}, Shubhali: {suspicious}"
            )
        else:
            verdict = t("vt_safe", lang, harm=harmless)

        bot.send_message(message.chat.id, f"📄 {message.document.file_name}\nSHA256: `{sha256}`\n\n{verdict}")
    except requests.exceptions.RequestException as e:
        bot.reply_to(message, t("generic_error", lang, err=e))


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
                    f"fishing domenga o'xshaganligi uchun o'chirildi: {domain}",
                )
            except Exception:
                bot.reply_to(message, f"⚠️ Diqqat: {domain} fishing bo'lishi mumkin (men admin emasman).")
            return


if __name__ == "__main__":
    threading.Thread(target=scheduler_loop, daemon=True).start()
    print("CyberGuard boti (ko'p tilli, kengaytirilgan versiya) ishga tushdi...")
    bot.infinity_polling()
