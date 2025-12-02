#!/usr/bin/env python3
"""
Upload + View Telegram Bot (single-file)

Changes made:
- Token generation: tokens are only persisted (activated) when the user actually opens the deep link (i.e. /start token_xxx).
- Active tokens grant unlimited access for 12 hours.
- VIP users bypass tokens.
- /protection admin command toggles sending with protect_content True/False (persisted in DB).
- Keeps content/media DB schema intact. Only token activation flow & settings modified.
- exe.io shortener is used if EXEIO_API_KEY is provided. Shortener requests are logged (but the token is still only saved on activation).

Config via environment variables:
- UPLOAD_BOT_TOKEN (bot token)
- MAIN_CHANNEL_ID (channel to post to)
- UPLOAD_PASSWORD (initial upload password)
- ADMIN_IDS (comma-separated list)
- EXEIO_API_KEY (optional)
- DB_PATH (optional)
"""
import os
import time
import logging
import secrets
import sqlite3
import urllib
from typing import Dict, Any, List, Optional

import aiohttp
from telegram import (
    Update,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputMediaPhoto,
    InputMediaVideo,
)
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    CallbackQueryHandler,
    ConversationHandler,
    filters,
)

from flask import Flask
from threading import Thread

# ----------------- Flask health endpoint (keeps renders/pella happy) -----------------
app = Flask('')

@app.route('/')
def home():
    return "Bot is running!"

def run():
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", "8080")))

t = Thread(target=run)
t.daemon = True
t.start()

# ---------- CONFIG (ENV-friendly) ----------
UPLOAD_BOT_TOKEN = os.environ.get("UPLOAD_BOT_TOKEN", "8413595718:AAEI8yJAcDt22VbzASEpNR_aJNMXrMscdGk")
MAIN_CHANNEL_ID = os.environ.get("MAIN_CHANNEL_ID", "-1003104322226")
PASSWORD = os.environ.get("UPLOAD_PASSWORD", "test")
PASSWORD_VALID_SECONDS = int(os.environ.get("PASSWORD_VALID_SECONDS", 24 * 3600))
DB_PATH = os.environ.get("DB_PATH", "tg_content.db")
ADMIN_IDS = [int(x) for x in os.environ.get("ADMIN_IDS", "6233731222").split(",") if x.strip().isdigit()]

EXEIO_API_KEY = os.environ.get("EXEIO_API_KEY", "c204899d0187dc988e3d368d21038fbf82789531").strip()
EXEIO_API_ENDPOINT = os.environ.get("EXEIO_API_ENDPOINT", "https://exe.io/api")

# default runtime flag; actual value loaded from DB settings at startup
content_protection = True

# token validity
TOKEN_VALID_SECONDS = 12 * 3600  # 12 hours

# Conversation states
(
    STATE_PASSWORD,
    STATE_THUMBNAIL,
    STATE_DESCRIPTION,
    STATE_OPTION,
    STATE_MEDIA_UPLOAD,
    STATE_TEXT_UPLOAD,
    STATE_TOKEN_REQUIRE,
    STATE_CONFIRM_TOKEN,
) = range(8)

sessions: Dict[int, Dict[str, Any]] = {}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------- DB helpers -----------------
def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        user_id INTEGER PRIMARY KEY,
        last_auth INTEGER,
        is_vip INTEGER DEFAULT 0
    )""")
    # Run this once in your bot startup section (after DB connect)
# with sqlite3.connect("your_database_name.db") as conn:
#     c = conn.cursor()
   # c.execute("""
  #      ALTER TABLE  shortener_requests 
  #      ADD COLUMN created_at TEXT
  #  """)
    # conn.commit()

    c.execute("""CREATE TABLE IF NOT EXISTS content(
        content_id INTEGER PRIMARY KEY AUTOINCREMENT,
        uploader_id INTEGER,
        thumb_file_id TEXT,
        description TEXT,
        is_text_only INTEGER DEFAULT 0,
        requires_token INTEGER DEFAULT 0,
        created_at INTEGER,
        main_channel_message_id INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS media_items(
        media_id INTEGER PRIMARY KEY AUTOINCREMENT,
        content_id INTEGER,
        file_id TEXT,
        file_unique_id TEXT,
        media_type TEXT,
        is_forwarded INTEGER DEFAULT 0
    )""")
    # tokens table: tokens saved only when activated (after user opens the deep link)
    c.execute("""CREATE TABLE IF NOT EXISTS tokens(
        token TEXT PRIMARY KEY,
        user_id INTEGER,
        issued_at INTEGER,
        expires_at INTEGER
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS shortener_requests(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        shortener_url TEXT,
        token TEXT,
        status TEXT,
        created_at INTEGER
    )""")
    # settings table (for persistent password and other key/values)
    c.execute("""CREATE TABLE IF NOT EXISTS settings(
        key TEXT PRIMARY KEY,
        value TEXT
    )""")
    conn.commit()
    conn.close()

def load_password_from_db():
    """Load password from DB into global PASSWORD variable (if present)."""
    global PASSWORD
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'password'")
        row = c.fetchone()
        conn.close()
        if row and row[0]:
            PASSWORD = row[0]
            logger.info("Loaded PASSWORD from settings table.")
            return
    except Exception:
        logger.exception("Failed to read password from DB; using default/env password.")
    # If not present, initialize settings value to current PASSWORD
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", ("password", PASSWORD))
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Failed to initialize password in DB.")

def load_protection_from_db():
    """Load protect_content setting into runtime global."""
    global content_protection
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT value FROM settings WHERE key = 'protect_content'")
        row = c.fetchone()
        conn.close()
        if row and row[0] is not None:
            content_protection = True if row[0] == "1" else False
            logger.info("Loaded protect_content=%s from settings.", content_protection)
            return
    except Exception:
        logger.exception("Failed to read protect_content from DB; using default True.")
    # default: ensure a record exists
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", ("protect_content", "1" if content_protection else "0"))
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Failed to initialize protect_content in DB.")

def set_protection_in_db(value: bool):
    global content_protection
    content_protection = bool(value)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", ("protect_content", "1" if content_protection else "0"))
    conn.commit()
    conn.close()

def set_password_in_db(new_pass: str):
    """Persist password in DB and update runtime global."""
    global PASSWORD
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", ("password", new_pass))
    conn.commit()
    conn.close()
    PASSWORD = new_pass

def user_is_authed(user_id: int) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_auth, is_vip FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    last_auth, is_vip = row
    if is_vip:
        return True
    if not last_auth:
        return False
    return (time.time() - last_auth) <= PASSWORD_VALID_SECONDS

def set_user_auth(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = int(time.time())
    # preserve VIP flag if present
    c.execute("SELECT is_vip FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    is_vip = row[0] if row else 0
    c.execute("INSERT OR REPLACE INTO users(user_id,last_auth,is_vip) VALUES(?,?,?)", (user_id, now, is_vip))
    conn.commit()
    conn.close()

def set_user_vip(user_id: int, is_vip: int = 1):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # preserve last_auth if present
    c.execute("SELECT last_auth FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    last_auth = row[0] if row else 0
    c.execute("INSERT OR REPLACE INTO users(user_id,last_auth,is_vip) VALUES(?,?,?)", (user_id, last_auth, is_vip))
    conn.commit()
    conn.close()

def save_content_to_db(uploader_id: int, thumb_file_id: str, description: str, is_text_only: int, requires_token: int) -> int:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = int(time.time())
    c.execute("""INSERT INTO content(uploader_id, thumb_file_id, description, is_text_only, requires_token, created_at)
                 VALUES(?,?,?,?,?,?)""", (uploader_id, thumb_file_id, description, is_text_only, requires_token, now))
    content_id = c.lastrowid
    conn.commit()
    conn.close()
    return content_id

def add_media_item(content_id: int, file_id: str, file_unique_id: str, media_type: str, is_forwarded: int = 0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""INSERT INTO media_items(content_id, file_id, file_unique_id, media_type, is_forwarded)
                 VALUES(?,?,?,?,?)""", (content_id, file_id, file_unique_id, media_type, is_forwarded))
    conn.commit()
    conn.close()

def get_content(content_id: int) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT content_id, uploader_id, thumb_file_id, description, is_text_only, requires_token, created_at, main_channel_message_id FROM content WHERE content_id = ?", (content_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return None
    keys = ["content_id", "uploader_id", "thumb_file_id", "description", "is_text_only", "requires_token", "created_at", "main_channel_message_id"]
    content = dict(zip(keys, row))
    # fetch media items
    c.execute("SELECT media_id, file_id, file_unique_id, media_type, is_forwarded FROM media_items WHERE content_id = ? ORDER BY media_id ASC", (content_id,))
    media_rows = c.fetchall()
    content["media_items"] = [
        {"media_id": r[0], "file_id": r[1], "file_unique_id": r[2], "media_type": r[3], "is_forwarded": r[4]} for r in media_rows
    ]
    conn.close()
    return content

# ----------------- Token helpers -----------------
def token_exists_in_tokens(token: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM tokens WHERE token = ? LIMIT 1", (token,))
    row = c.fetchone()
    conn.close()
    return bool(row)

def token_exists_in_shortener(token: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT 1 FROM shortener_requests WHERE token = ? LIMIT 1", (token,))
    row = c.fetchone()
    conn.close()
    return bool(row)

def generate_token_value(length_bytes: int = 4) -> str:
    """Generate an unactivated token (hex). Ensure global uniqueness across tokens and shortener_requests."""
    for _ in range(10):
        token = secrets.token_hex(length_bytes)  # 8 hex chars by default
        if not token_exists_in_tokens(token) and not token_exists_in_shortener(token):
            return token
    # fallback: try until unique
    while True:
        token = secrets.token_hex(length_bytes)
        if not token_exists_in_tokens(token) and not token_exists_in_shortener(token):
            return token

def activate_token_for_user(token: str, user_id: int) -> bool:
    """Persist token activation (issued_at, expires_at). Returns True if saved, False if already exists/invalid."""
    now = int(time.time())
    expires = now + TOKEN_VALID_SECONDS
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # if the token already exists in tokens table and not expired, do not override (but normally tokens are only created now)
        c.execute("SELECT expires_at FROM tokens WHERE token = ?", (token,))
        row = c.fetchone()
        if row:
            # if expired, we can re-activate for this user; otherwise keep existing
            if row[0] >= now:
                conn.close()
                return True  # already active
            else:
                # overwrite expired token
                c.execute("UPDATE tokens SET user_id=?, issued_at=?, expires_at=? WHERE token=?", (user_id, now, expires, token))
                conn.commit()
                conn.close()
                return True
        # create new token record
        c.execute("INSERT INTO tokens(token,user_id,issued_at,expires_at) VALUES(?,?,?,?)", (token, user_id, now, expires))
        conn.commit()
        conn.close()
        return True
    except Exception:
        logger.exception("Failed to activate token in DB.")
        return False

def get_active_token_for_user(user_id: int) -> Optional[Dict[str, Any]]:
    """Return a valid (not expired) token record for the user if exists, else None."""
    now = int(time.time())
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT token,issued_at,expires_at FROM tokens WHERE user_id = ? AND expires_at >= ? ORDER BY issued_at DESC LIMIT 1", (user_id, now))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {"token": row[0], "issued_at": row[1], "expires_at": row[2]}

def cleanup_expired_tokens():
    """Optionally delete expired tokens to keep DB clean."""
    now = int(time.time())
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM tokens WHERE expires_at < ?", (now,))
    conn.commit()
    conn.close()

def record_shortener_request(short_url: str, token: str, status: str = "created"):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = int(time.time())
    c.execute("INSERT INTO shortener_requests(shortener_url, token, status, created_at) VALUES(?,?,?,?)", (short_url, token, status, now))
    conn.commit()
    conn.close()

# ----------------- Helper utils -----------------
def count_media_for_session(session: Dict[str, Any]) -> Dict[str, int]:
    photos = sum(1 for m in session.get("media_list", []) if m["media_type"] == "photo")
    videos = sum(1 for m in session.get("media_list", []) if m["media_type"] == "video")
    docs = sum(1 for m in session.get("media_list", []) if m["media_type"] not in ("photo", "video"))
    return {"photos": photos, "videos": videos, "other": docs}

# ---------- Emoji UI helpers ----------
def kb_upload_options_with_emoji():
    keyboard = [
        [InlineKeyboardButton("🖼️ Upload from phone", callback_data="opt_upload_phone")],
        [InlineKeyboardButton("🔁 Forward media", callback_data="opt_forward")],
        [InlineKeyboardButton("🔗 Upload URL / Text only", callback_data="opt_url_text")],
        [InlineKeyboardButton("❌ Cancel", callback_data="opt_cancel")],
    ]
    return InlineKeyboardMarkup(keyboard)

def kb_token_choice_with_emoji():
    keyboard = [
        [InlineKeyboardButton("🎟️ Yes — requires token", callback_data="tok_yes")],
        [InlineKeyboardButton("✅ No — free (no token)", callback_data="tok_no")],
        [InlineKeyboardButton("❌ Cancel upload", callback_data="opt_cancel")],
    ]
    return InlineKeyboardMarkup(keyboard)

def kb_watch_button_with_emoji(watch_link: str):
    return InlineKeyboardMarkup([[InlineKeyboardButton("▶️ Watch Video", url=watch_link)]])

def kb_get_token_button_with_emoji(content_id: int):
    return InlineKeyboardMarkup([[InlineKeyboardButton("🎟️ Get Token", callback_data=f"gettok_{content_id}")]])

# ---------- exe.io shortener (async) ----------
async def exeio_shorten_long_url(long_url: str) -> Optional[str]:
    """
    Shorten a long URL using exe.io's API (if configured).
    Example endpoint: https://exe.io/api?api=API_KEY&url=<encoded_url>
    This will try to return the shortened url on success.
    """
    if not EXEIO_API_KEY:
        logger.info("EXEIO_API_KEY not set; skipping shortener.")
        return None
    try:
        encoded = urllib.parse.quote(long_url, safe='')
        api = f"{EXEIO_API_ENDPOINT}?api={EXEIO_API_KEY}&url={encoded}"
        async with aiohttp.ClientSession() as sess:
            async with sess.get(api, timeout=10) as resp:
                try:
                    data = await resp.json()
                except Exception:
                    text = await resp.text()
                    logger.warning("Shortener returned non-json: %s", text)
                    return None
                # many shorteners return {"status":"success","shortenedUrl":"..."}
                if isinstance(data, dict) and data.get("status") in ("success", "ok") and data.get("shortenedUrl"):
                    return data.get("shortenedUrl")
                # fallback keys
                if isinstance(data, dict) and data.get("shortUrl"):
                    return data.get("shortUrl")
                logger.warning("Shortener returned unexpected payload: %s", data)
                return None
    except Exception:
        logger.exception("Shortener request failed.")
        return None

# ---------- Handlers ----------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # handle deep-links: content_<id> or token_<token>
    args = context.args
    if args:
        payload = args[0]
        if payload.startswith("content_"):
            try:
                content_id = int(payload.split("_", 1)[1])
            except Exception:
                await update.effective_chat.send_message("Invalid content link.")
                return
            await handle_view_content(update, context, content_id)
            return
        if payload.startswith("token_"):
            token = payload.split("_", 1)[1]
            await handle_token_start(update, context, token)
            return
    # No args -> show welcome
    await update.message.reply_text(
        "Welcome. Use /upload to post content (password required).\nIf you have a content link, open it to view."
    )

async def handle_view_content(update: Update, context: ContextTypes.DEFAULT_TYPE, content_id: int):
    user = update.effective_user
    user_id = user.id
    content = get_content(content_id)
    if not content:
        await update.effective_chat.send_message("Content not found.")
        return
    requires_token = bool(content.get("requires_token"))
    # check VIP
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT is_vip FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    is_vip = bool(row[0]) if row else False
    conn.close()

    # If not required or VIP -> show
    if (not requires_token) or is_vip:
        await send_content_media(update, context, content)
        return

    # If token required -> check if user already has a valid token (active)
    cleanup_expired_tokens()
    active = get_active_token_for_user(user_id)
    if active:
        # user has valid active token (unlimited for its expiry window)
        await send_content_media(update, context, content)
        return

    # otherwise ask to get token
    kb = kb_get_token_button_with_emoji(content_id)
    await update.effective_chat.send_message(
        "🔒 This content requires a token to watch. Tokens are valid for 12 hours. Tap below to get your token.", reply_markup=kb
    )

async def handle_token_start(update: Update, context: ContextTypes.DEFAULT_TYPE, token: str):
    """
    This is invoked when user opens the deep link t.me/<bot>?start=token_<token>
    At this moment we ACTIVIATE (persist) the token for this user for 12 hours.
    """
    user = update.effective_user
    user_id = user.id
    # Basic validation of token format
    if not token or len(token) < 6:
        await update.effective_chat.send_message("❌ Token invalid.")
        return

    # If token is already active for this user and not expired, confirm it
    active = get_active_token_for_user(user_id)
    if active and active.get("token") == token:
        expires_at = active["expires_at"]
        remain = max(0, expires_at - int(time.time()))
        hrs = remain // 3600
        mins = (remain % 3600) // 60
        await update.effective_chat.send_message(f"✅ Token already active for you. Expires in {hrs}h {mins}m.")
        return

    # Activate the token for this user (persist it). This is the crucial change:
    # we persist only when the user actually opened the start link.
    ok = activate_token_for_user(token, user_id)
    if not ok:
        await update.effective_chat.send_message("❌ Failed to activate token; try again or contact admin.")
        return
    # record activation success message
    active = get_active_token_for_user(user_id)
    if active:
        expires_at = active["expires_at"]
        remain = max(0, expires_at - int(time.time()))
        hrs = remain // 3600
        mins = (remain % 3600) // 60
        await update.effective_chat.send_message(f"🎉 Token activated — you can watch protected content for the next {hrs}h {mins}m.")
    else:
        await update.effective_chat.send_message("🎉 Token activated. You can now access protected content for the next 12 hours.")

async def send_content_media(update: Update, context: ContextTypes.DEFAULT_TYPE, content: Dict[str, Any]):
    chat = update.effective_chat
    desc = content.get("description", "")
    requires_token = bool(content.get("requires_token"))
    label = "🔒 Token: Required" if requires_token else "🟢 Free"
    caption_intro = f"{desc}\n\n{label}"

    media_items = content.get("media_items", [])
    # Build media group where possible (up to 10), otherwise send thumbnail + each media separately
    medias = []
    for i, m in enumerate(media_items):
        caption_text = caption_intro if i == 0 else None  # only first media gets caption
        if m["media_type"] == "photo":
            medias.append(InputMediaPhoto(media=m["file_id"], caption=caption_text))
        elif m["media_type"] == "video":
            medias.append(InputMediaVideo(media=m["file_id"], caption=caption_text))
        else:
            # treat other as document: send as a separate message later
            pass

    try:
        if medias:
            # send as media group (Telegram allows up to 10)
            if len(medias) == 1:
                # single media: send as photo/video with caption
                if isinstance(medias[0], InputMediaPhoto):
                    await chat.send_photo(photo=medias[0].media, caption=medias[0].caption , protect_content=content_protection)
                else:
                    await chat.send_video(video=medias[0].media, caption=medias[0].caption , protect_content=content_protection)
            else:
                # media group
                await chat.send_media_group(media=medias[:10], protect_content=content_protection)
        else:
            # no photos/videos: send thumbnail as photo with caption
            thumb = content.get("thumb_file_id")
            if thumb:
                await chat.send_photo(photo=thumb, caption=caption_intro, protect_content=content_protection)
            else:
                await chat.send_message(caption_intro)

        # send any non-photo/video documents afterwards
        for m in media_items:
            if m["media_type"] not in ("photo", "video"):
                await chat.send_document(document=m["file_id"], protect_content=content_protection)
    except Exception as e:
        logger.exception("Failed to send media: %s", e)
        await chat.send_message("Failed to send media. The file ids may be invalid or the bot lacks access.")

# --- Upload flow (mostly preserved) ---
async def cmd_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    # VIP skip password
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT is_vip FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    is_vip = bool(row[0]) if row else False
    conn.close()

    if is_vip:
        sessions[user_id] = {"uploader_id": user_id, "media_list": []}
        await update.message.reply_text("🌟 VIP detected — you can upload now. Send the thumbnail image (photo).")
        return STATE_THUMBNAIL

    if user_is_authed(user_id):
        sessions[user_id] = {"uploader_id": user_id, "media_list": []}
        await update.message.reply_text("🔓 Password validated. Please send the thumbnail image now (photo).")
        return STATE_THUMBNAIL
    else:
        await update.message.reply_text("Please enter the password to begin upload:")
        return STATE_PASSWORD

async def password_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text or ""
    if text.strip() == PASSWORD:
        set_user_auth(user_id)
        sessions[user_id] = {"uploader_id": user_id, "media_list": []}
        await update.message.reply_text("✅ Password accepted for 24 hours. Now send the thumbnail image (photo).")
        return STATE_THUMBNAIL
    else:
        await update.message.reply_text("❌ Wrong password. Send /upload to try again.")
        return ConversationHandler.END

async def thumbnail_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if update.message.photo:
        photo = update.message.photo[-1]
        file_id = photo.file_id
        session = sessions.setdefault(user_id, {"uploader_id": user_id, "media_list": []})
        session["thumb_file_id"] = file_id
        await update.message.reply_text("🖼️ Thumbnail saved. Now send the description text message.")
        return STATE_DESCRIPTION
    else:
        await update.message.reply_text("Please send a photo to be used as thumbnail.")
        return STATE_THUMBNAIL

async def description_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    text = update.message.text or ""
    if not text.strip():
        await update.message.reply_text("Please send a non-empty description.")
        return STATE_DESCRIPTION
    session = sessions.get(user_id)
    session["description"] = text.strip()

    # Use emoji keyboard
    await update.message.reply_text("Choose how you want to add content (or Cancel):", reply_markup=kb_upload_options_with_emoji())
    return STATE_OPTION

async def option_pressed(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data

    if data == "opt_cancel":
        sessions.pop(user_id, None)
        await query.edit_message_text("Upload canceled and session reset.")
        return ConversationHandler.END

    if data == "opt_url_text":
        await query.edit_message_text("Send the URL or text that will be saved as the content (no media).")
        session = sessions.setdefault(user_id, {"uploader_id": user_id, "media_list": []})
        session["is_text_only"] = True
        return STATE_MEDIA_UPLOAD

    if data == "opt_forward":
        await query.edit_message_text("Now forward the media messages from any chat to me. When done, send /done .")
        session = sessions.setdefault(user_id, {"uploader_id": user_id, "media_list": []})
        session["expect_forward"] = True
        return STATE_MEDIA_UPLOAD

    if data == "opt_upload_phone":
        await query.edit_message_text("Now send photos/videos/documents from your phone. When finished, send /done .")
        session = sessions.setdefault(user_id, {"uploader_id": user_id, "media_list": []})
        session["expect_forward"] = False
        return STATE_MEDIA_UPLOAD

    await query.edit_message_text("Unknown option.")
    return ConversationHandler.END

async def media_receiver(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    session = sessions.get(user_id)
    if not session:
        await update.message.reply_text("No active upload session. Send /upload to start.")
        return ConversationHandler.END

    if session.get("is_text_only"):
        await update.message.reply_text("You selected URL/Text. Send the text/URL now (or /cancel).")
        return STATE_MEDIA_UPLOAD

    added = False

    if update.message.photo:
        photo = update.message.photo[-1]
        session["media_list"].append({"file_id": photo.file_id, "file_unique_id": photo.file_unique_id, "media_type": "photo", "is_forwarded": 1 if getattr(update.message, "forward_from", None) or getattr(update.message, "forward_from_chat", None) else 0})
        added = True

    if update.message.video:
        vid = update.message.video
        session["media_list"].append({"file_id": vid.file_id, "file_unique_id": vid.file_unique_id, "media_type": "video", "is_forwarded": 1 if getattr(update.message, "forward_from", None) or getattr(update.message, "forward_from_chat", None) else 0})
        added = True

    if update.message.document:
        doc = update.message.document
        session["media_list"].append({"file_id": doc.file_id, "file_unique_id": doc.file_unique_id, "media_type": "document", "is_forwarded": 1 if getattr(update.message, "forward_from", None) or getattr(update.message, "forward_from_chat", None) else 0})
        added = True

    if added:
        counts = count_media_for_session(session)
        await update.message.reply_text(f"Saved media. Current counts — 🖼 Photos: {counts['photos']}, 🎬 Videos: {counts['videos']}, 📁 Other: {counts['other']}. When finished send /done or /cancel.")
    else:
        await update.message.reply_text("No supported media found in that message. Send photo/video/document, or /done when finished.")
    return STATE_MEDIA_UPLOAD

async def url_text_receive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    session = sessions.get(user_id)
    if not session or not session.get("is_text_only"):
        await update.message.reply_text("No URL/Text upload session active. Use /upload to start.")
        return ConversationHandler.END
    text = (update.message.text or "").strip()
    if not text:
        await update.message.reply_text("Please send a non-empty URL or text.")
        return STATE_MEDIA_UPLOAD
    session["url_text"] = text
    return await ask_token_requirement(update, context)

async def done_receiving_media(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    session = sessions.get(user_id)
    if not session:
        await update.message.reply_text("No active session. Send /upload to start.")
        return ConversationHandler.END

    if not session.get("is_text_only") and not session.get("media_list"):
        await update.message.reply_text("You didn't add any media. Use /cancel to reset or add media.")
        return STATE_MEDIA_UPLOAD

    return await ask_token_requirement(update, context)

async def ask_token_requirement(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    await update.message.reply_text("Does this content require a watch token?", reply_markup=kb_token_choice_with_emoji())
    return STATE_CONFIRM_TOKEN

async def token_choice_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user_id = query.from_user.id
    data = query.data

    if data == "opt_cancel":
        sessions.pop(user_id, None)
        await query.edit_message_text("Upload canceled and session reset.")
        return ConversationHandler.END

    requires_token = 1 if data == "tok_yes" else 0
    session = sessions.get(user_id)
    thumbnail = session.get("thumb_file_id")
    description = session.get("description", "")
    is_text_only = 1 if session.get("is_text_only") else 0
    content_id = save_content_to_db(user_id, thumbnail, description, is_text_only, requires_token)

    for m in session.get("media_list", []):
        add_media_item(content_id, m["file_id"], m.get("file_unique_id", ""), m["media_type"], m.get("is_forwarded", 0))

    if is_text_only:
        url_text = session.get("url_text", "")
        if url_text:
            description_to_save = f"{description}\n\n[URL/TEXT]\n{url_text}"
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE content SET description = ? WHERE content_id = ?", (description_to_save, content_id))
            conn.commit()
            conn.close()

    counts = count_media_for_session(session)
    summary = f"🖼 Photos: {counts['photos']} | 🎬 Videos: {counts['videos']}"

    bot_username = (context.bot.username or "").lstrip("@")
    watch_link = f"https://t.me/{bot_username}?start=content_{content_id}"
    kb = kb_watch_button_with_emoji(watch_link)

    caption = f"{session.get('description','')}\n\n{summary}\n\n{'🔒 Token: Required' if requires_token else '🟢 Free'}"
    try:
        sent = await context.bot.send_photo(chat_id=MAIN_CHANNEL_ID, photo=thumbnail, caption=caption, reply_markup=kb)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("UPDATE content SET main_channel_message_id = ? WHERE content_id = ?", (sent.message_id, content_id))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.exception("Failed to post to main channel: %s", e)
        await query.edit_message_text(f"Saved content (id {content_id}) but failed to post to MAIN CHANNEL. Error: {e}")
        sessions.pop(user_id, None)
        return ConversationHandler.END

    await query.edit_message_text(f"✅ Content posted to main channel as content_id {content_id}.\nWatch link: {watch_link}\nUpload finished.")
    sessions.pop(user_id, None)
    return ConversationHandler.END

async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    sessions.pop(user_id, None)
    await update.message.reply_text("Upload cancelled and session reset.")
    return ConversationHandler.END

# Callback for Get Token button (improved: creates token + tries exe.io short link)
async def callback_get_token_exeio(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    Handles 'Get Token' button → creates token + exe.io short link.
    Important: This DOES NOT activate/persist the token yet.
    Activation occurs only when the user opens the bot via the deep link (/start token_xxx).
    """
    query = update.callback_query
    await query.answer()
    data = query.data

    if not data.startswith("gettok_"):
        await query.edit_message_text("Unknown action.")
        return

    try:
        content_id = int(data.split("_", 1)[1])
    except Exception:
        await query.edit_message_text("Invalid content id.")
        return

    user_id = query.from_user.id

    # Generate a token value but DO NOT save into tokens table yet
    token = generate_token_value()

    bot_username = (context.bot.username or "").lstrip("@")
    long_watch_link = f"https://t.me/{bot_username}?start=token_{token}"

    # Try shortening with exe.io
    short_link = await exeio_shorten_long_url(long_watch_link)
    if short_link:
        # record shortener request for auditing; status 'created' indicates short link created
        record_shortener_request(short_link, token, status="created")
        await query.edit_message_text(
            "🎟️ *Token prepared!*\n\n"
            "Click the link below to open Telegram and activate your token. The token is activated only when you open the link — not when it is generated. Token valid for 12 hours after activation.",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("🔗 Open to Activate Token", url=short_link)]]
            ),
            parse_mode="Markdown"
        )
    else:
        # no short link: give the long link directly (still token is NOT persisted until activation)
        # also record the plain URL as a shortener_request for debugging purposes
        record_shortener_request(long_watch_link, token, status="no_shortener")
        await query.edit_message_text(
            "🔗 Token link ready. Click below to open Telegram and activate your token (token is saved only when you open it).",
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("▶ Activate Token", url=long_watch_link)]]
            ),
        )

# Admin / VIP commands
async def cmd_addvip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user.id not in ADMIN_IDS:
        await update.message.reply_text("Only admins can manage VIPs.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /addvip <user_id>")
        return
    try:
        uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user id")
        return
    set_user_vip(uid, 1)
    await update.message.reply_text(f"User {uid} marked as VIP.")

async def cmd_delvip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user.id not in ADMIN_IDS:
        await update.message.reply_text("Only admins can manage VIPs.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /delvip <user_id>")
        return
    try:
        uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("Invalid user id")
        return
    set_user_vip(uid, 0)
    await update.message.reply_text(f"User {uid} removed from VIPs.")

# New /changepass admin command
async def cmd_changepass(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user.id not in ADMIN_IDS:
        await update.message.reply_text("Only admins can change the upload password.")
        return
    if not context.args:
        await update.message.reply_text("Usage: /changepass <new_password>")
        return
    newpass = context.args[0].strip()
    if not newpass:
        await update.message.reply_text("Password cannot be empty.")
        return
    try:
        set_password_in_db(newpass)
        await update.message.reply_text("🔒 Upload password changed successfully and saved.")
    except Exception as e:
        logger.exception("Failed to change password.")
        await update.message.reply_text(f"Failed to change password: {e}")

# /protection admin toggle
async def cmd_protection(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user

    # ✅ Only allow admins to use this command
    if user.id not in ADMIN_IDS:
        await update.message.reply_text("❌ Only admins can toggle protection.")
        return

    global content_protection  # make sure we modify the global variable

    # ✅ If an argument is provided: explicitly set the state
    if context.args:
        arg = context.args[0].lower()
        if arg in ("1", "on", "true", "yes"):
            content_protection = True
            set_protection_in_db(True)
            await update.message.reply_text(
                "✅ <b>protect_content</b> set to <b>True</b>. Media will be sent with protection.",
                parse_mode="HTML"
            )
            return
        elif arg in ("0", "off", "false", "no"):
            content_protection = False
            set_protection_in_db(False)
            await update.message.reply_text(
                "⚠️ <b>protect_content</b> set to <b>False</b>. Media will be sent without protection.",
                parse_mode="HTML"
            )
            return
        else:
            await update.message.reply_text(
                "Usage: <code>/protection [on|off]</code> OR just <code>/protection</code> to toggle.",
                parse_mode="HTML"
            )
            return

    # ✅ No argument → toggle current state
    content_protection = not content_protection
    set_protection_in_db(content_protection)

    state_text = "✅ Enabled" if content_protection else "⚠️ Disabled"
    await update.message.reply_text(
        f"<b>protect_content</b> is now {state_text}.",
        parse_mode="HTML"
    )



# Pretty /myinfo (emoji)
async def cmd_myinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_auth,is_vip FROM users WHERE user_id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        await update.message.reply_text("❌ You are not authenticated and not a VIP. Use /upload to start and provide password.")
        return
    last_auth, is_vip = row
    if is_vip:
        await update.message.reply_text("🌟 You are a VIP user. You can upload and view token-protected content without tokens.")
        return
    remaining = max(0, int(PASSWORD_VALID_SECONDS - (time.time() - (last_auth or 0))))
    hrs = remaining // 3600
    mins = (remaining % 3600) // 60
    secs = remaining % 60
    await update.message.reply_text(f"⏳ Password valid for another {hrs}h {mins}m {secs}s.")

# Utility to register handlers and run
def main():
    init_db()
    load_password_from_db()
    load_protection_from_db()
    app = ApplicationBuilder().token(UPLOAD_BOT_TOKEN).build()

    conv = ConversationHandler(
        entry_points=[CommandHandler("upload", cmd_upload)],
        states={
            STATE_PASSWORD: [MessageHandler(filters.TEXT & ~filters.COMMAND, password_text)],
            STATE_THUMBNAIL: [MessageHandler(filters.PHOTO & ~filters.COMMAND, thumbnail_handler), CommandHandler("cancel", cancel_command)],
            STATE_DESCRIPTION: [MessageHandler(filters.TEXT & ~filters.COMMAND, description_handler), CommandHandler("cancel", cancel_command)],
            STATE_OPTION: [CallbackQueryHandler(option_pressed)],
            STATE_MEDIA_UPLOAD: [
                MessageHandler((filters.PHOTO | filters.VIDEO | filters.Document.ALL) & ~filters.COMMAND, media_receiver),
                MessageHandler(filters.TEXT & ~filters.COMMAND, url_text_receive),
                CommandHandler("done", done_receiving_media),
                CommandHandler("cancel", cancel_command),
            ],
            STATE_CONFIRM_TOKEN: [CallbackQueryHandler(token_choice_callback)],
        },
        fallbacks=[CommandHandler("cancel", cancel_command)],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("start", start))
    app.add_handler(conv)
    # Original option handlers
    app.add_handler(CallbackQueryHandler(option_pressed, pattern="^opt_"))
    app.add_handler(CallbackQueryHandler(token_choice_callback, pattern="^tok_"))
    # Use improved token handler (creates token link, but activation only on /start)
    app.add_handler(CallbackQueryHandler(callback_get_token_exeio, pattern="^gettok_"))

    # admin & misc commands
    app.add_handler(CommandHandler("addvip", cmd_addvip))
    app.add_handler(CommandHandler("delvip", cmd_delvip))
    app.add_handler(CommandHandler("changepass", cmd_changepass))
    app.add_handler(CommandHandler("myinfo", cmd_myinfo))
    app.add_handler(CommandHandler("protection", cmd_protection))

    logger.info("Upload+View Bot starting...")
    app.run_polling()

if __name__ == "__main__":
    main()
