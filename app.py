# ============================================================
# FINAL MASTER CODE – SAKURA ASSIST v2.5 (PRODUCTION COMPLETE)
# All safety fixes applied:
#   • Thread-safe database (new connection per operation)
#   • PII redaction before storage
#   • Prefecture typo corrected (Shizuoka)
#   • Fallback keys normalized (comfort_message)
#   • Deprecated balloons → modern toast (with legacy fallback)
#   • gTTS import handled gracefully
#   • Deadline null-safety
#   • Single PIIGuard class (duplicate removed)
#   • PIIGuard used as instance, not class
#   • has_pii() method added
#   • verify_pin() function defined
# ============================================================

import streamlit as st

# 🔥 MUST be first Streamlit command
st.set_page_config(
    page_title="Sakura Assist 🌸 v2.5",
    layout="wide"
)

from datetime import datetime
import io
import base64
import hashlib
import json
import os
import re
import sqlite3
import requests

# ============================================================
# ENVIRONMENT VARIABLES & LOCAL CONFIGURATION
# ============================================================
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
_DEFAULT_PIN_HASH = hashlib.sha256("2026".encode()).hexdigest()
FAMILY_PIN_HASH = os.getenv("FAMILY_PIN_HASH", _DEFAULT_PIN_HASH)

if FAMILY_PIN_HASH == _DEFAULT_PIN_HASH and not os.getenv("FAMILY_PIN_HASH"):
    if "pin_warning_shown" not in st.session_state:
        st.session_state.pin_warning_shown = True
        st.warning("🔒 Using default PIN (2026). Set FAMILY_PIN_HASH env var for production.")

LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
LINE_TO_USER_ID = os.getenv("LINE_TO_USER_ID", "")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
FAMILY_EMAIL = os.getenv("FAMILY_EMAIL", "")
DATABASE_PATH = os.getenv("DATABASE_PATH", "./sakura_history.db")
ENABLE_TTS = os.getenv("ENABLE_TTS", "true").lower() == "true"
ENABLE_IMAGE_OCR = os.getenv("ENABLE_IMAGE_OCR", "true").lower() == "true"

# ============================================================
# PIN VERIFICATION
# ============================================================
def verify_pin(pin: str) -> bool:
    return hashlib.sha256(pin.encode()).hexdigest() == FAMILY_PIN_HASH

# ============================================================
# DATABASE LAYER
# ============================================================
class SakuraDB:
    """Every method opens its own connection → safe for concurrent usage."""

    @staticmethod
    def _init_tables(conn):
        conn.execute("""
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                prefecture TEXT,
                doc_type TEXT,
                urgency_level TEXT,
                summary TEXT,
                actions TEXT,
                raw_input TEXT,
                status TEXT,
                family_notified INTEGER DEFAULT 0
            )
        """)
        conn.commit()

    @classmethod
    def save(cls, prefecture, doc_type, urgency, summary, actions, raw_input, status="processed"):
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        cls._init_tables(conn)
        try:
            cursor = conn.execute(
                """INSERT INTO documents (timestamp, prefecture, doc_type, urgency_level, summary, actions, raw_input, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (datetime.now().isoformat(), prefecture, doc_type, urgency, summary,
                 json.dumps(actions, ensure_ascii=False), raw_input, status)
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    @classmethod
    def get_history(cls, limit=20):
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        cls._init_tables(conn)
        try:
            cursor = conn.execute(
                "SELECT * FROM documents ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
        finally:
            conn.close()

    @classmethod
    def mark_notified(cls, doc_id):
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        cls._init_tables(conn)
        try:
            conn.execute("UPDATE documents SET family_notified=1 WHERE id=?", (doc_id,))
            conn.commit()
        finally:
            conn.close()

@st.cache_resource
def get_db():
    return SakuraDB

# ============================================================
# COMPLIANCE INTERCEPTOR (PRIVACY PROTECTION LAYER)
# ============================================================
st.markdown(
    """
    <style>
    .stApp, [data-testid="stSidebar"] {
        background-color: #121214 !important;
    }
    .stTextArea textarea, .stTextInput input {
        font-size: 18px !important;
    }
    label, p, .stMarkdown p {
        font-size: 18px !important;
    }
    h3, [data-testid="stSubheader"] {
        font-size: 24px !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ============================================================
# PII GUARD — SINGLE DEFINITION (fixes duplicate + bugs)
# ============================================================
class PIIGuard:
    def __init__(self):
        self.patterns = {
            # Japanese My Number: 12 digits (e.g. 1234 5678 1234)
            'my_number': re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
            # Email
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
            # Phone: Japanese style
            'phone': re.compile(r'\b\d{2,4}[-\s]?\d{2,4}[-\s]?\d{3,4}\b'),
            # Postal code
            'postal': re.compile(r'\b\d{3}[-\s]?\d{4}\b'),
        }

    def has_pii(self, text: str) -> bool:
        """Returns True if any PII pattern is found in text."""
        return any(p.search(text) for p in self.patterns.values())

    def redact(self, text: str) -> str:
        """Replaces all PII matches with [TYPE REDACTED] tokens."""
        if not text:
            return text
        for pii_type, pattern in self.patterns.items():
            text = pattern.sub(f"[{pii_type.upper()} REDACTED]", text)
        return text

# Single shared instance used throughout the app
pii_guard = PIIGuard()

# ============================================================
# OFFLINE FALLBACK TEMPLATES
# ============================================================
FALLBACK_TEMPLATES = [
    {
        "keywords": ["pension", "年金", "nenkin"],
        "doc_type": "Pension Notice",
        "summary": "This is about your pension payment or review. Your pension money is safe, but you may need to send a document.",
        "comfort_message": "Don't worry. Your pension is not stopping. This is a normal check.",
        "actions": [
            "Find your pension book (年金手帳) or My Number card.",
            "Call the pension office phone number on the letter if you are unsure.",
            "Ask your family or city hall to help you send the reply."
        ]
    },
    {
        "keywords": ["tax", "税", "zei", "kazei", "income tax", "住民税"],
        "doc_type": "Tax Notice",
        "summary": "This is about taxes you need to pay or a tax refund. The government is counting your money for the year.",
        "comfort_message": "You don't need to pay today. Check the deadline carefully.",
        "actions": [
            "Check the payment deadline date on the paper.",
            "Prepare your bank book or cash payment slip.",
            "Go to the bank or convenience store before the deadline."
        ]
    },
    {
        "keywords": ["medical", "保険", "hoken", "insurance", "hospital", "医療"],
        "doc_type": "Medical Insurance",
        "summary": "This is about health insurance or medical payment. Your insurance card is still working.",
        "comfort_message": "You can still go to the hospital. This letter is just about money details.",
        "actions": [
            "Check if you need to pay extra money or if you will get money back.",
            "Bring this letter and your insurance card to the city hall.",
            "Ask the hospital reception if you don't understand."
        ]
    },
    {
        "keywords": ["subsidy", "給付", "kyufu", "benefit", "welfare", "福祉", "allowance"],
        "doc_type": "Subsidy / Welfare",
        "summary": "This is about money help from the government. You may get money or need to renew your application.",
        "comfort_message": "This is good news or a normal renewal. You are not in trouble.",
        "actions": [
            "Check if you need to write a new application or just send a copy of ID.",
            "Go to the welfare office (福祉事務所) with this letter.",
            "Call the phone number on the letter and say 'I need help understanding this'."
        ]
    }
]

JP_DOC_NAMES = {
    "Pension Notice": "年金のおしらせ",
    "Tax Notice": "税金のおしらせ",
    "Medical Insurance": "けんぽのおしらせ",
    "Subsidy / Welfare": "給付金・福祉のおしらせ",
    "Government Notice": "役所からの大切なおしらせ"
}

def get_fallback(text: str):
    text_lower = text.lower()
    for template in FALLBACK_TEMPLATES:
        if any(k in text_lower for k in template["keywords"]):
            return template
    return {
        "doc_type": "Government Notice",
        "summary": "This is an important letter from the government. It needs your attention before the deadline.",
        "comfort_message": "Don't worry. Many people find these letters difficult. We will help you.",
        "actions": [
            "Take a photo of this letter and show it to your family or city hall.",
            "Check the deadline date written on the paper.",
            "Call the phone number on the letter and ask for 'simple explanation' (やさしい説明)."
        ]
    }

def format_fallback(fb, lang):
    is_jp = "日本" in lang or "Japanese" in lang
    return {
        "doc_type": JP_DOC_NAMES.get(fb["doc_type"], fb["doc_type"]) if is_jp else fb["doc_type"],
        "summary": fb["summary"] if not is_jp else "これは政府からの大切な手紙です。安心してください。",
        "comfort_message": fb["comfort_message"] if not is_jp else "心配しないでください。あなたは安全です。",
        "urgency_level": "medium",
        "deadline": None,
        "actions": [
            {"step_number": i + 1, "task": a, "deadline": None, "contact": None}
            for i, a in enumerate(fb["actions"])
        ],
        "department": "City Hall" if not is_jp else "市役所",
        "contact_phone": None,
        "required_documents": [],
        "penalty_if_missed": None
    }

# ============================================================
# FAMILY NOTIFIER
# ============================================================
class FamilyNotifier:
    def __init__(self):
        self.line_token = LINE_CHANNEL_ACCESS_TOKEN
        self.line_user = LINE_TO_USER_ID
        self.sendgrid_key = SENDGRID_API_KEY
        self.email = FAMILY_EMAIL

    def send(self, message: str, doc_id: int) -> dict:
        results = {"line": False, "email": False, "demo": False}

        if self.line_token and self.line_user:
            try:
                resp = requests.post(
                    "https://api.line.me/v2/bot/message/push",
                    headers={"Authorization": f"Bearer {self.line_token}", "Content-Type": "application/json"},
                    json={"to": self.line_user, "messages": [{"type": "text", "text": message}]},
                    timeout=10
                )
                results["line"] = resp.status_code == 200
            except Exception:
                pass

        if self.sendgrid_key and self.email:
            try:
                resp = requests.post(
                    "https://api.sendgrid.com/v3/mail/send",
                    headers={"Authorization": f"Bearer {self.sendgrid_key}", "Content-Type": "application/json"},
                    json={
                        "personalizations": [{"to": [{"email": self.email}]}],
                        "from": {"email": "sakura@assist.app"},
                        "subject": "🌸 Sakura Assist - Family Alert",
                        "content": [{"type": "text/plain", "value": message}]
                    },
                    timeout=10
                )
                results["email"] = resp.status_code in (200, 202)
            except Exception:
                pass

        if not results["line"] and not results["email"]:
            results["demo"] = True
            results["demo_message"] = f"[DEMO MODE] Would send to family:\n\n{message}"

        return results

# ============================================================
# GEMINI AI TRANSLATOR
# ============================================================
try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

class SakuraTranslator:
    def __init__(self, key_override=""):
        active_key = key_override if key_override else GEMINI_API_KEY
        if GENAI_AVAILABLE and active_key:
            genai.configure(api_key=active_key)
            self.model = genai.GenerativeModel("gemini-2.0-flash")
            self.available = True
        else:
            self.available = False

    def process_text(self, text: str, lang: str, prefecture: str):
        if not self.available:
            return {"success": True, "data": format_fallback(get_fallback(text), lang), "source": "offline"}

        # Redact PII before sending to AI
        safe_text = pii_guard.redact(text)

        prompt = f"""You are 'Sakura Assist', an empathetic AI translator for elderly people living alone in Japan.
The user is extremely stressed by complex government paperwork.

Analyze the document and respond STRICTLY as a JSON object with this exact schema:
{{
  "doc_type": "Short name of document type",
  "summary": "2 short comforting sentences explaining what this means. Use basic words. Tell them they are safe.",
  "comfort_message": "1 warm sentence to reduce anxiety",
  "urgency_level": "low|medium|high|critical",
  "deadline": "YYYY-MM-DD or null if no clear deadline",
  "actions": [
    {{"step_number": 1, "task": "simple action", "deadline": "string or null", "contact": "string or null"}}
  ],
  "department": "Name of government office",
  "contact_phone": "phone number or null",
  "required_documents": ["list of needed items"],
  "penalty_if_missed": "what happens if ignored, or null"
}}

Translate ALL text values into: {lang}
Prefecture context: {prefecture}

Document:
{safe_text}
"""
        try:
            response = self.model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    response_mime_type="application/json"
                )
            )
            data = json.loads(response.text)
            return {"success": True, "data": data, "source": "ai"}
        except Exception as e:
            fallback = get_fallback(text)
            return {
                "success": True,
                "data": format_fallback(fallback, lang),
                "source": "fallback",
                "error": str(e)
            }

    def process_image(self, image_bytes, mime_type, lang: str, prefecture: str):
        if not self.available:
            return {"success": False, "error": "AI not configured", "source": "offline"}

        prompt = f"""This is a photo of a Japanese government document for an elderly person.
Read the text, then respond STRICTLY as JSON with the same schema as above.
Translate into: {lang}
Prefecture: {prefecture}
"""
        try:
            image_part = {"mime_type": mime_type, "data": image_bytes}
            response = self.model.generate_content(
                [prompt, image_part],
                generation_config=genai.types.GenerationConfig(
                    response_mime_type="application/json"
                )
            )
            data = json.loads(response.text)
            return {"success": True, "data": data, "source": "ai-vision"}
        except Exception as e:
            return {"success": False, "error": str(e), "source": "error"}

# ============================================================
# UI STYLING
# ============================================================
st.markdown("""
    <style>
    @media (prefers-reduced-motion: reduce) {
        .petal { animation: none !important; display: none !important; }
    }
    .main-title { font-size: clamp(28px, 4vw, 40px) !important; font-weight: 900; color: #B83B5E; text-align: center; }
    .sync-text { font-size: clamp(12px, 1.5vw, 14px); color: #2E7D32; font-weight: 600; margin-bottom: 20px; text-align: center; }
    .card-grandma { background-color: #FFF5F6; padding: clamp(16px, 2vw, 28px); border-radius: 20px; border-top: 5px solid #B83B5E; box-shadow: 0 8px 24px rgba(184,59,94,0.12); }
    .card-action { background-color: #FAFAFA; padding: clamp(16px, 2vw, 28px); border-radius: 20px; border-top: 5px solid #6C5CE7; box-shadow: 0 8px 24px rgba(108,92,231,0.10); }
    .gateway-box { background: linear-gradient(135deg, #FFFDE7, #FFF8E1); padding: 20px; border-radius: 14px; border: 1.5px dashed #FBC02D; margin-top: 20px; }
    .urgency-low { border-left: 6px solid #2E7D32; }
    .urgency-medium { border-left: 6px solid #F9A825; }
    .urgency-high { border-left: 6px solid #E65100; }
    .urgency-critical { border-left: 6px solid #C62828; }
    .big-font { font-size: clamp(15px, 1.2vw, 18px) !important; line-height: 1.8; }
    .sakura-divider { text-align: center; font-size: 22px; letter-spacing: 10px; opacity: 0.5; margin: 10px 0 20px 0; }
    .touch-btn button { min-height: 48px; font-size: 16px !important; }
    .history-card { background: white; padding: 12px; border-radius: 12px; margin-bottom: 8px; border: 1px solid #eee; }
    .petal {
        position: fixed; top: -40px; font-size: 18px; opacity: 0.5;
        animation: fall linear infinite; pointer-events: none; z-index: 9999;
    }
    @keyframes fall {
        0%   { transform: translateY(-40px) rotate(0deg) translateX(0px); opacity: 0.6; }
        50%  { transform: translateY(50vh) rotate(180deg) translateX(40px); opacity: 0.3; }
        100% { transform: translateY(110vh) rotate(360deg) translateX(-20px); opacity: 0; }
    }
    .p1  { left: 5%;  animation-duration: 8s;  animation-delay: 0s; }
    .p2  { left: 15%; animation-duration: 10s; animation-delay: 1s;   font-size: 20px; }
    .p3  { left: 25%; animation-duration: 9s;  animation-delay: 2s;   font-size: 14px; }
    .p4  { left: 35%; animation-duration: 11s; animation-delay: 0.5s; }
    .p5  { left: 45%; animation-duration: 8s;  animation-delay: 3s;   font-size: 22px; }
    .p6  { left: 55%; animation-duration: 10s; animation-delay: 1.5s; }
    .p7  { left: 65%; animation-duration: 9s;  animation-delay: 2.5s; }
    .p8  { left: 75%; animation-duration: 8s;  animation-delay: 4s;   font-size: 14px; }
    .p9  { left: 85%; animation-duration: 11s; animation-delay: 0.8s; }
    .p10 { left: 93%; animation-duration: 9s;  animation-delay: 3.5s; }
    @media (max-width: 768px) {
        .main-title { font-size: 24px !important; }
        .card-grandma, .card-action { padding: 14px !important; }
    }
    </style>

    <div class="petal p1">🌸</div>
    <div class="petal p2">🌸</div>
    <div class="petal p3">🌺</div>
    <div class="petal p4">🌸</div>
    <div class="petal p5">🌸</div>
    <div class="petal p6">🌺</div>
    <div class="petal p7">🌸</div>
    <div class="petal p8">🌸</div>
    <div class="petal p9">🌸</div>
    <div class="petal p10">🌺</div>
""", unsafe_allow_html=True)

# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================
if 'db' not in st.session_state:
    st.session_state.db = get_db()
if 'notifier' not in st.session_state:
    st.session_state.notifier = FamilyNotifier()
if 'last_result' not in st.session_state:
    st.session_state.last_result = None
if 'last_doc_id' not in st.session_state:
    st.session_state.last_doc_id = None
if 'audio_html' not in st.session_state:
    st.session_state.audio_html = None
if 'font_size' not in st.session_state:
    st.session_state.font_size = "normal"

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("## 🌸 Sakura Assist v2.5")
    st.markdown("---")

    st.markdown("### 🔤 Text Size")
    font_choice = st.radio("Size:", ["Normal", "Large", "Extra Large"], horizontal=True)
    st.session_state.font_size = font_choice.lower().replace(" ", "_")

    size_css = {
        "normal": "font-size: 16px !important;",
        "large": "font-size: 20px !important;",
        "extra_large": "font-size: 24px !important;"
    }
    st.markdown(
        f"<style>.big-font {{{size_css.get(st.session_state.font_size, '')}}}</style>",
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.markdown("### 🌐 Language")
    lang = st.radio("Language Mode:", ["English", "日本語 (Simple Japanese)"], key="lang")

    st.markdown("---")
    st.markdown("### 🗾 Prefecture")
    prefectures = [
        "🗾 National Network (Auto)",
        "Hokkaido (北海道)", "Aomori (青森県)", "Iwate (岩手県)", "Miyagi (宮城県)",
        "Akita (秋田県)", "Yamagata (山形県)", "Fukushima (福島県)",
        "Tokyo (東京都)", "Kanagawa (神奈川県)", "Saitama (埼玉県)", "Chiba (千葉県)",
        "Ibaraki (茨城県)", "Tochigi (栃木県)", "Gunma (群馬県)",
        "Nagano (長野県)", "Niigata (新潟県)", "Toyama (富山県)", "Ishikawa (石川県)",
        "Fukui (福井県)", "Yamanashi (山梨県)", "Shizuoka (静岡県)", "Aichi (愛知県)", "Gifu (岐阜県)",
        "Osaka (大阪府)", "Kyoto (京都府)", "Hyogo (兵庫県)", "Nara (奈良県)",
        "Shiga (滋賀県)", "Mie (三重県)", "Wakayama (和歌山県)",
        "Hiroshima (広島県)", "Okayama (岡山県)", "Shimane (島根県)", "Tottori (鳥取県)",
        "Yamaguchi (山口県)", "Ehime (愛媛県)", "Kochi (高知県)", "Tokushima (徳島県)", "Kagawa (香川県)",
        "Fukuoka (福岡県)", "Nagasaki (長崎県)", "Kumamoto (熊本県)", "Oita (大分県)",
        "Miyazaki (宮崎県)", "Kagoshima (鹿児島県)", "Saga (佐賀県)", "Okinawa (沖縄県)"
    ]
    selected_prefecture = st.selectbox("Prefecture:", prefectures)

    st.markdown("---")

    key_override = ""
    if not GEMINI_API_KEY:
        st.markdown("### 🔑 API Key Override")
        key_override = st.text_input("Enter Gemini API Key:", type="password")

    # Initialize translator
    st.session_state.translator = SakuraTranslator(key_override=key_override)

    st.markdown("### 📊 Recent History")
    try:
        history = st.session_state.db.get_history(limit=5)
        for h in history:
            status_emoji = "✅" if h["family_notified"] else "⏳"
            st.markdown(f"""
            <div class="history-card">
                <b>{status_emoji} {h["doc_type"]}</b><br>
                <span style="font-size:12px; color:#666;">{h["timestamp"][:10]} • {h["urgency_level"].upper()}</span>
            </div>
            """, unsafe_allow_html=True)
    except Exception:
        pass

    st.markdown("---")
    st.info("Society 5.0 | Built for USAII 2026")

# ============================================================
# STRINGS
# ============================================================
text_db = {
    "English": {
        "title": "🌸 Sakura Assist — Your Document Helper",
        "sync": f"🟢 Connected to {selected_prefecture} | {datetime.now().strftime('%B %d, %Y')}",
        "profile": "👵 Home Portal",
        "input_label": "📄 Paste the confusing letter text here:",
        "or_upload": "📷 Or upload a photo of the letter:",
        "btn": "✨ Translate & Explain",
        "output_hdr": "🤖 Here is what the letter means",
        "validation_err": "❌ Please paste some text or upload a photo first.",
        "api_err": "⚠️ AI key not configured. Please enter your Gemini API key in the sidebar.",
        "loop_title": "🛡️ Send to Family",
        "loop_desc": "Enter your family PIN to send this summary to their phone.",
        "tts_label": "🔊 Listen to the summary",
        "deadline": "Deadline",
        "department": "Office",
        "contact": "Phone Number",
        "docs_needed": "Documents Needed",
        "penalty": "What happens if missed",
        "verified": "✅ PIN correct! Sending to family now...",
        "wrong_pin": "❌ Wrong PIN. Message not sent.",
        "demo_mode": "📲 [DEMO] Message that would be sent:"
    },
    "日本語 (Simple Japanese)": {
        "title": "🌸 さくら アシスト — かんたん てがみ ほんやく",
        "sync": f"🟢 {selected_prefecture} と つながっています | {datetime.now().strftime('%Y年%m月%d日')}",
        "profile": "👵 おばあちゃん の がめん",
        "input_label": "📄 むずかしい 手紙 の もじ を ここにいれてね:",
        "or_upload": "📷 手紙 の 写真 を アップロード:",
        "btn": "✨ さくらAI で かんたんに",
        "output_hdr": "🤖 てがみ の いみ",
        "validation_err": "❌ もじ または 写真 を いれてください。",
        "api_err": "⚠️ AIの キー が みつかりません。",
        "loop_title": "🛡️ かぞく に おくる",
        "loop_desc": "かぞく の ばんごう を いれてください。",
        "tts_label": "🔊 こえ で きく",
        "deadline": "いつまで",
        "department": "どこ",
        "contact": "でんわ",
        "docs_needed": "じゅんびするもの",
        "penalty": "ださないと どうなる",
        "verified": "✅ おくりました！",
        "wrong_pin": "❌ ばんごう が ちがいます。",
        "demo_mode": "📲 [デモ] おくられる メッセージ:"
    }
}
db = text_db[lang]

# ============================================================
# MAIN UI
# ============================================================
st.markdown(f"<div class='main-title'>{db['title']}</div>", unsafe_allow_html=True)
st.markdown(f"<div class='sync-text'>{db['sync']}</div>", unsafe_allow_html=True)
st.markdown("<div class='sakura-divider'>🌸 🌺 🌸 🌺 🌸</div>", unsafe_allow_html=True)

col1, col2 = st.columns([1, 1], gap="large")

# ==================== LEFT: INPUT PANEL ====================
with col1:
    st.markdown("<div class='card-grandma'>", unsafe_allow_html=True)
    st.subheader(db["profile"])

    default_doc = "NAGANO PREFECTURAL WELFARE MANAGEMENT AMENDMENT: Under sudden regional climate re-classifications, all isolated senior residential units utilizing localized heating assistance subsidies are strictly mandated to resubmit verifiable financial criteria metrics to the municipal tracking core before the operational seasonal closeout date. Neglecting immediate credential upload results in terminal suspension of processing allocations."
    user_input = st.text_area(db["input_label"], value=default_doc, height=180)

    uploaded_image = None
    if ENABLE_IMAGE_OCR:
        uploaded_image = st.file_uploader(db["or_upload"], type=["jpg", "jpeg", "png"])
        if uploaded_image:
            st.image(uploaded_image, use_container_width=True, caption="📷 Uploaded document")

    st.markdown("<div class='touch-btn'>", unsafe_allow_html=True)
    process_trigger = st.button(db["btn"], use_container_width=True, type="primary")
    st.markdown("</div>", unsafe_allow_html=True)

    # ✅ FIX: use pii_guard instance, not PIIGuard class
    if user_input and pii_guard.has_pii(user_input):
        st.warning("🔒 Personal information detected and will be hidden before processing.")

    st.markdown("</div>", unsafe_allow_html=True)

# ==================== RIGHT: OUTPUT PANEL ====================
with col2:
    st.markdown("<div class='card-action'>", unsafe_allow_html=True)
    st.subheader(db["output_hdr"])

    if process_trigger:
        if not user_input.strip() and not uploaded_image:
            st.error(db["validation_err"])
            st.session_state.last_result = None
        elif not st.session_state.translator.available:
            st.error(db["api_err"])
            st.session_state.last_result = None
        else:
            with st.spinner("🌸 Sakura AI is reading the letter..."):
                if uploaded_image:
                    img_bytes = uploaded_image.getvalue()
                    mime_type = uploaded_image.type or "image/jpeg"
                    result = st.session_state.translator.process_image(img_bytes, mime_type, lang, selected_prefecture)
                else:
                    result = st.session_state.translator.process_text(user_input, lang, selected_prefecture)

                st.session_state.last_result = result

                if result["success"]:
                    data = result["data"]
                    # ✅ FIX: use pii_guard instance
                    safe_raw = pii_guard.redact(user_input[:500]) if user_input else "[IMAGE]"
                    try:
                        doc_id = st.session_state.db.save(
                            prefecture=selected_prefecture,
                            doc_type=data.get("doc_type", "Unknown"),
                            urgency=data.get("urgency_level", "medium"),
                            summary=data.get("summary", ""),
                            actions=data.get("actions", []),
                            raw_input=safe_raw,
                            status="processed"
                        )
                        st.session_state.last_doc_id = doc_id
                    except Exception:
                        st.session_state.last_doc_id = 1

                st.session_state.audio_html = None
                if ENABLE_TTS and result["success"]:
                    with st.spinner("🔊 Generating audio..."):
                        try:
                            from gtts import gTTS
                            comfort = result["data"].get("comfort_message", "")
                            summary = result["data"].get("summary", "")
                            tts_text = f"{comfort}. {summary}"[:300]
                            tts = gTTS(text=tts_text, lang="ja" if "日本" in lang else "en", slow=True)
                            mp3_fp = io.BytesIO()
                            tts.write_to_fp(mp3_fp)
                            mp3_fp.seek(0)
                            b64 = base64.b64encode(mp3_fp.read()).decode()
                            st.session_state.audio_html = f'''
                                <audio controls style="width:100%; margin-top:10px;">
                                    <source src="data:audio/mp3;base64,{b64}" type="audio/mpeg">
                                </audio>
                            '''
                        except ImportError:
                            st.warning("⚠️ `gtts` not installed. Audio disabled.")
                            st.session_state.audio_html = None
                        except Exception:
                            st.session_state.audio_html = None

    # RENDER RESULTS
    if st.session_state.last_result:
        result = st.session_state.last_result
        if not result["success"]:
            st.error(f"❌ Error: {result.get('error', 'Unknown error.')}")
        else:
            data = result["data"]
            source = result.get("source", "unknown")

            if source == "fallback":
                st.warning("⚠️ AI unavailable. Showing offline template.")
            elif source == "offline":
                st.info("📴 Offline mode active.")

            urgency = data.get("urgency_level", "medium")
            urgency_class = f"urgency-{urgency}"

            st.markdown(f"<div class='{urgency_class}' style='padding-left:12px; margin-bottom:16px;'>", unsafe_allow_html=True)
            st.markdown(f"**📋 {data.get('doc_type', 'Document')}**")
            st.markdown(f"<div class='big-font'><b>{data.get('comfort_message', '')}</b></div>", unsafe_allow_html=True)
            st.markdown(f"<div class='big-font'>{data.get('summary', '')}</div>", unsafe_allow_html=True)

            deadline = data.get("deadline")
            if deadline and str(deadline).lower() != "null":
                st.markdown(f"""
                <div style="background:#FFF3E0; padding:10px 14px; border-radius:10px; margin:10px 0; border-left:4px solid #EF6C00;">
                    <b>⏰ {db['deadline']}:</b> {deadline}
                </div>
                """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

            if st.session_state.audio_html:
                st.markdown(f"<b>{db['tts_label']}</b>", unsafe_allow_html=True)
                st.markdown(st.session_state.audio_html, unsafe_allow_html=True)

            st.markdown("---")
            st.markdown(f"### ✅ Steps to take")
            actions = data.get("actions", [])
            for action in actions:
                step = action.get("step_number", 0)
                task = action.get("task", "")
                act_deadline = action.get("deadline")
                contact = action.get("contact")
                deadline_str = f" — ⏰ {act_deadline}" if act_deadline and str(act_deadline).lower() != "null" else ""
                contact_str = f"<br>📞 {contact}" if contact else ""

                st.markdown(f"""
                <div style="background:white; padding:14px; border-radius:12px; margin-bottom:10px; border:1px solid #E0E0E0; box-shadow:0 2px 8px rgba(0,0,0,0.04);">
                    <span style="background:#B83B5E; color:white; padding:4px 10px; border-radius:20px; font-size:13px; font-weight:bold;">Step {step}</span>
                    <div class="big-font" style="margin-top:8px;">{task}{deadline_str}{contact_str}</div>
                </div>
                """, unsafe_allow_html=True)

            meta_cols = st.columns(3)
            with meta_cols[0]:
                if data.get("department"):
                    st.metric(db["department"], data["department"])
            with meta_cols[1]:
                if data.get("contact_phone"):
                    st.metric(db["contact"], data["contact_phone"])
            with meta_cols[2]:
                if data.get("penalty_if_missed"):
                    st.metric("⚠️ Risk", "High" if urgency in ["high", "critical"] else "Low")

            if data.get("required_documents"):
                st.markdown(f"**📎 {db['docs_needed']}:** {', '.join(data['required_documents'])}")

            if data.get("penalty_if_missed"):
                st.markdown(f"""
                <div style="background:#FFEBEE; padding:10px 14px; border-radius:10px; margin-top:10px; color:#C62828;">
                    <b>⚠️ {db['penalty']}:</b> {data['penalty_if_missed']}
                </div>
                """, unsafe_allow_html=True)

            # FAMILY NOTIFICATION GATEWAY
            st.markdown("---")
            st.markdown("<div class='gateway-box'>", unsafe_allow_html=True)
            st.subheader(db["loop_title"])
            st.warning(db["loop_desc"])

            pin = st.text_input("🔑 PIN:", type="password", key="pin_input")

            if pin:
                if verify_pin(pin):
                    st.success(db["verified"])

                    msg = f"""🌸 Sakura Assist Alert
Document: {data.get('doc_type')}
Urgency: {urgency.upper()}
Summary: {data.get('summary', '')}
Actions: {', '.join([a['task'] for a in actions])}
Deadline: {data.get('deadline', 'None')}
"""
                    notify_result = st.session_state.notifier.send(msg, st.session_state.last_doc_id)

                    if notify_result.get("demo"):
                        st.info(f"{db['demo_mode']}\n\n{notify_result['demo_message']}")
                    else:
                        sent_methods = []
                        if notify_result.get("line"): sent_methods.append("LINE")
                        if notify_result.get("email"): sent_methods.append("Email")
                        st.success(f"📲 Sent via: {', '.join(sent_methods) if sent_methods else 'Demo'}")

                    if st.session_state.last_doc_id:
                        try:
                            st.session_state.db.mark_notified(st.session_state.last_doc_id)
                        except Exception:
                            pass
                        try:
                            st.toast("🎉 Sent to family!", icon="🎉")
                        except AttributeError:
                            st.balloons()
                else:
                    st.error(db["wrong_pin"])

            st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("👈 Paste a document or upload a photo and click the button.")

    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div class='sakura-divider'>🌸 🌺 🌸 🌺 🌸 🌺 🌸</div>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align:center; color:#888; font-size:12px; padding:20px;">
    🌸 Sakura Assist v2.5 | Built for USAII Global Hackathon 2026<br>
    Accessibility First • Privacy Protected • Society 5.0 Compliant
</div>
""", unsafe_allow_html=True)
