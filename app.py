import streamlit as st
import streamlit.components.v1 as components

# ============================================================
# 🔥 MUST be first Streamlit command
# ============================================================
st.set_page_config(
    page_title="Sakura Assist 🌸 v3.0",
    layout="wide",
    initial_sidebar_state="expanded"
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
import secrets
from typing import Optional, List, Dict, Any

# ============================================================
# ENVIRONMENT & SECURITY CONFIGURATION
# ============================================================
# ============================================================
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- API Keys ---
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
if not GEMINI_API_KEY:
    try:
        GEMINI_API_KEY = st.secrets["GEMINI_API_KEY"]
    except Exception:
        GEMINI_API_KEY = ""

# --- PIN Configuration (PBKDF2 preferred, legacy SHA256 fallback) ---
# Default demo PIN: 2026 (SHA256 legacy hash)
# For hackathon only — generate a real PBKDF2 hash via the sidebar admin tool for production
_DEFAULT_PIN_HASH = hashlib.sha256("2026".encode()).hexdigest()
FAMILY_PIN_HASH = os.getenv("FAMILY_PIN_HASH", _DEFAULT_PIN_HASH)
FAMILY_PIN_SALT = os.getenv("FAMILY_PIN_SALT", "")

# --- Other Config ---
LINE_CHANNEL_ACCESS_TOKEN = os.getenv("LINE_CHANNEL_ACCESS_TOKEN", "")
LINE_TO_USER_ID = os.getenv("LINE_TO_USER_ID", "")
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY", "")
FAMILY_EMAIL = os.getenv("FAMILY_EMAIL", "")
DATABASE_PATH = os.getenv("DATABASE_PATH", "./sakura_history.db")
ENABLE_TTS = os.getenv("ENABLE_TTS", "true").lower() == "true"
ENABLE_IMAGE_OCR = os.getenv("ENABLE_IMAGE_OCR", "true").lower() == "true"

# ============================================================
# PIN VERIFICATION (PBKDF2 + Legacy Fallback)
# ============================================================
def verify_pin(pin: str) -> bool:
    """Verify family PIN using PBKDF2-HMAC-SHA256 (preferred) or legacy SHA256."""
    if not pin or not isinstance(pin, str):
        return False
    
    # Secure: PBKDF2 with salt
    if FAMILY_PIN_SALT and FAMILY_PIN_HASH:
        computed = hashlib.pbkdf2_hmac(
            'sha256', 
            pin.encode('utf-8'), 
            FAMILY_PIN_SALT.encode('utf-8'), 
            100000
        ).hex()
        return secrets.compare_digest(computed, FAMILY_PIN_HASH)
    
    # Legacy: unsalted SHA256 (backward compatibility only)
    if FAMILY_PIN_HASH:
        computed = hashlib.sha256(pin.encode('utf-8')).hexdigest()
        return secrets.compare_digest(computed, FAMILY_PIN_HASH)
    
    return False

# ============================================================
# DATABASE LAYER (Thread-Safe)
# ============================================================
class SakuraDB:
    """Every method opens its own connection → safe for concurrent usage."""
    
    @staticmethod
    def _init_tables(conn: sqlite3.Connection):
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
    def save(cls, prefecture, doc_type, urgency, summary, actions, raw_input, status="processed") -> int:
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        cls._init_tables(conn)
        try:
            cursor = conn.execute(
                """INSERT INTO documents 
                   (timestamp, prefecture, doc_type, urgency_level, summary, actions, raw_input, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    datetime.now().isoformat(), 
                    prefecture, 
                    doc_type, 
                    urgency, 
                    summary,
                    json.dumps(actions, ensure_ascii=False), 
                    raw_input, 
                    status
                )
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    @classmethod
    def get_history(cls, limit: int = 20) -> List[Dict[str, Any]]:
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
    def mark_notified(cls, doc_id: int):
        conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
        cls._init_tables(conn)
        try:
            conn.execute("UPDATE documents SET family_notified=1 WHERE id=?", (doc_id,))
            conn.commit()
        finally:
            conn.close()

# ============================================================
# PII GUARD (Privacy Protection)
# ============================================================
class PIIGuard:
    """Detects and redacts personally identifiable information."""
    
    def __init__(self):
        self.patterns = {
            # Japanese My Number: 12 digits, e.g., 1234 5678 9012
            'my_number': re.compile(r'(?<!\d)\d{4}[-\s]?\d{4}[-\s]?\d{4}(?!\d)'),
            # Email addresses
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
            # Japanese phone numbers (starts with 0; won't match dates like 2026-06-19)
            'phone': re.compile(r'(?<!\d)0\d{1,3}[-\s(]?\d{1,4}[-\s)]?\d{4}(?!\d)'),
            # Japanese postal codes
            'postal': re.compile(r'(?<!\d)\d{3}[-\s]?\d{4}(?!\d)'),
        }

    def has_pii(self, text: str) -> bool:
        """Returns True if any PII pattern is found."""
        if not text:
            return False
        return any(p.search(text) for p in self.patterns.values())

    def redact(self, text: str) -> str:
        """Replaces all PII matches with [TYPE REDACTED] tokens."""
        if not text:
            return text
        for pii_type, pattern in self.patterns.items():
            text = pattern.sub(f"[{pii_type.upper()} REDACTED]", text)
        return text

# Single shared instance
pii_guard = PIIGuard()

# ============================================================
# OFFLINE FALLBACK TEMPLATES (with Japanese translations)
# ============================================================
FALLBACK_TEMPLATES = [
    {
        "keywords": ["pension", "年金", "nenkin"],
        "doc_type": "Pension Notice",
        "doc_type_jp": "年金のおしらせ",
        "summary": "This is about your pension payment or review. Your pension money is safe, but you may need to send a document.",
        "summary_jp": "これは年金のおしらせです。あなたの年金は安全ですが、書類を送る必要があるかもしれません。",
        "comfort_message": "Don't worry. Your pension is not stopping. This is a normal check.",
        "comfort_jp": "心配しないでください。年金は止まりません。これは普通の確認です。",
        "actions": [
            "Find your pension book (年金手帳) or My Number card.",
            "Call the pension office phone number on the letter if you are unsure.",
            "Ask your family or city hall to help you send the reply."
        ],
        "actions_jp": [
            "年金手帳またはマイナンバーカードを探してください。",
            "お手紙に書いてある年金事務所の電話番号に電話してください。",
            "家族や市役所の人に手伝ってもらってください。"
        ]
    },
    {
        "keywords": ["tax", "税", "zei", "kazei", "income tax", "住民税"],
        "doc_type": "Tax Notice",
        "doc_type_jp": "税金のおしらせ",
        "summary": "This is about taxes you need to pay or a tax refund. The government is counting your money for the year.",
        "summary_jp": "これは税金のおしらせです。払う必要がある税金、または戻ってくる税金についてです。",
        "comfort_message": "You don't need to pay today. Check the deadline carefully.",
        "comfort_jp": "今日払う必要はありません。期限をよく確認してください。",
        "actions": [
            "Check the payment deadline date on the paper.",
            "Prepare your bank book or cash payment slip.",
            "Go to the bank or convenience store before the deadline."
        ],
        "actions_jp": [
            "お手紙に書いてある支払い期限を確認してください。",
            "通帳または払込票を準備してください。",
            "期限までに銀行またはコンビニに行ってください。"
        ]
    },
    {
        "keywords": ["medical", "保険", "hoken", "insurance", "hospital", "医療", "健康"],
        "doc_type": "Medical Insurance",
        "doc_type_jp": "健康保険のおしらせ",
        "summary": "This is about health insurance or medical payment. Your insurance card is still working.",
        "summary_jp": "これは健康保険のおしらせです。保険証はまだ使えます。",
        "comfort_message": "You can still go to the hospital. This letter is just about money details.",
        "comfort_jp": "病院にはまだ行けます。この手紙はお金の詳細についてです。",
        "actions": [
            "Check if you need to pay extra money or if you will get money back.",
            "Bring this letter and your insurance card to the city hall.",
            "Ask the hospital reception if you don't understand."
        ],
        "actions_jp": [
            "お金を払う必要があるか、お金が戻ってくるか確認してください。",
            "この手紙と保険証を市役所に持っていってください。",
            "わからない場合は病院の受付に聞いてください。"
        ]
    },
    {
        "keywords": ["subsidy", "給付", "kyufu", "benefit", "welfare", "福祉", "allowance", "子育て"],
        "doc_type": "Subsidy / Welfare",
        "doc_type_jp": "給付金・福祉のおしらせ",
        "summary": "This is about money help from the government. You may get money or need to renew your application.",
        "summary_jp": "これは政府からのお金の助けについてです。お金がもらえるか、申請を更新する必要があるかもしれません。",
        "comfort_message": "This is good news or a normal renewal. You are not in trouble.",
        "comfort_jp": "これは良い知らせか、普通の更新です。あなたは困っていません。",
        "actions": [
            "Check if you need to write a new application or just send a copy of ID.",
            "Go to the welfare office (福祉事務所) with this letter.",
            "Call the phone number on the letter and say 'I need help understanding this'."
        ],
        "actions_jp": [
            "新しい申請書を書く必要があるか、身分証明書のコピーを送るだけでいいか確認してください。",
            "この手紙を持って福祉事務所に行ってください。",
            "お手紙の電話番号に電話して、「説明を聞きたい」と言ってください。"
        ]
    }
]

JP_DOC_NAMES = {
    "Pension Notice": "年金のおしらせ",
    "Tax Notice": "税金のおしらせ",
    "Medical Insurance": "健康保険のおしらせ",
    "Subsidy / Welfare": "給付金・福祉のおしらせ",
    "Government Notice": "役所からの大切なおしらせ"
}

def get_fallback(text: str) -> dict:
    """Select best fallback template based on keyword matching."""
    text_lower = text.lower()
    for template in FALLBACK_TEMPLATES:
        if any(k in text_lower for k in template["keywords"]):
            return template
    # Default fallback
    return {
        "doc_type": "Government Notice",
        "doc_type_jp": "役所からの大切なおしらせ",
        "summary": "This is an important letter from the government. It needs your attention before the deadline.",
        "summary_jp": "これは政府からの大切な手紙です。期限までに対応が必要です。",
        "comfort_message": "Don't worry. Many people find these letters difficult. We will help you.",
        "comfort_jp": "心配しないでください。これらの手紙は難しいと感じる人が多いです。私たちが手伝います。",
        "actions": [
            "Take a photo of this letter and show it to your family or city hall.",
            "Check the deadline date written on the paper.",
            "Call the phone number on the letter and ask for 'simple explanation' (やさしい説明)."
        ],
        "actions_jp": [
            "この手紙の写真を撮って、家族や市役所の人に見せてください。",
            "紙に書いてある期限を確認してください。",
            "お手紙の電話番号に電話して、「やさしい説明がほしい」と言ってください。"
        ]
    }

def format_fallback(fb: dict, lang: str) -> dict:
    """Format fallback template for display, with proper Japanese support."""
    is_jp = "日本語" in lang or "Japanese" in lang or lang.startswith("ja")
    
    actions_key = "actions_jp" if is_jp else "actions"
    raw_actions = fb.get(actions_key, fb["actions"])
    
    return {
        "doc_type": fb.get("doc_type_jp", fb["doc_type"]) if is_jp else fb["doc_type"],
        "summary": fb.get("summary_jp", fb["summary"]) if is_jp else fb["summary"],
        "comfort_message": fb.get("comfort_jp", fb["comfort_message"]) if is_jp else fb["comfort_message"],
        "urgency_level": "medium",
        "deadline": None,
        "actions": [
            {"step_number": i + 1, "task": task, "deadline": None, "contact": None}
            for i, task in enumerate(raw_actions)
        ],
        "department": "市役所" if is_jp else "City Hall",
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
        # Redact PII before sending to family
        safe_message = pii_guard.redact(message)
        results = {"line": False, "email": False, "demo": False}
        
        # LINE Notify
        if self.line_token and self.line_user:
            try:
                resp = requests.post(
                    "https://api.line.me/v2/bot/message/push",
                    headers={
                        "Authorization": f"Bearer {self.line_token}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "to": self.line_user,
                        "messages": [{"type": "text", "text": safe_message}]
                    },
                    timeout=15
                )
                results["line"] = resp.status_code == 200
            except Exception as e:
                results["line_error"] = str(e)
        
        # SendGrid Email
        if self.sendgrid_key and self.email:
            try:
                resp = requests.post(
                    "https://api.sendgrid.com/v3/mail/send",
                    headers={
                        "Authorization": f"Bearer {self.sendgrid_key}",
                        "Content-Type": "application/json"
                    },
                    json={
                        "personalizations": [{"to": [{"email": self.email}]}],
                        "from": {"email": "sakura@assist.app"},
                        "subject": "🌸 Sakura Assist - Family Alert",
                        "content": [{"type": "text/plain", "value": safe_message}]
                    },
                    timeout=15
                )
                results["email"] = resp.status_code in (200, 202)
            except Exception as e:
                results["email_error"] = str(e)
        
        # Demo mode fallback
        if not results["line"] and not results["email"]:
            results["demo"] = True
            results["demo_message"] = f"[DEMO MODE] Would send to family:\n\n{safe_message}"
        
        return results

# ============================================================
# GEMINI REST API CLIENT (Stateless — No Global Config)
# ============================================================
class GeminiClient:
    """
    Stateless Gemini client using REST API.
    No global genai.configure() — safe for multi-user Streamlit.
    """
    MODELS = ["gemini-3.5-flash", "gemini-3.1-flash-lite", "gemini-2.5-flash"]
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.available = bool(api_key)
        self.base_url = "https://generativelanguage.googleapis.com/v1beta/models"
    
    def _generate(self, model: str, contents: List[dict], json_mode: bool = True) -> dict:
        """Call Gemini REST API and return parsed JSON response."""
        url = f"{self.base_url}/{model}:generateContent?key={self.api_key}"
        payload = {"contents": [{"parts": contents}]}
        
        if json_mode:
            payload["generationConfig"] = {"responseMimeType": "application/json"}
        
        resp = requests.post(url, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        
        # Handle API errors
        if "error" in data:
            raise ValueError(f"Gemini API error: {data['error'].get('message', 'Unknown')}")
        
        # Handle blocked/empty responses
        candidates = data.get("candidates", [])
        if not candidates:
            feedback = data.get("promptFeedback", {})
            block_reason = feedback.get("blockReason", "Unknown")
            raise ValueError(f"Response blocked or empty: {block_reason}")
        
        # Extract text
        text = candidates[0]["content"]["parts"][0]["text"]
        
        # Clean markdown fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text[3:]
            if text.lower().startswith("json"):
                text = text[4:]
            text = text.strip()
            if text.endswith("```"):
                text = text[:-3].strip()
        
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON from model: {e}")
    
    def _build_prompt(self, lang: str, prefecture: str, doc_text: str) -> str:
        """Build the analysis prompt."""
        return f"""You are 'Sakura Assist', an empathetic AI translator for elderly people living alone in Japan.
The user is extremely stressed by complex government paperwork.

Analyze the document and respond STRICTLY as a JSON object with this exact schema:
{{
  "doc_type": "Short name of document type",
  "summary": "3-4 clear sentences in very simple words explaining: what this letter is, why they received it, and what it means for them. Write as if speaking gently and slowly to someone who feels confused and worried. Avoid jargon completely.",
  "comfort_message": "1 warm, reassuring sentence to calm anxiety before the summary",
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
{doc_text}
"""
    
    def process_text(self, text: str, lang: str, prefecture: str) -> dict:
        """Process text document via Gemini REST API."""
        if not self.available:
            return {"success": True, "data": format_fallback(get_fallback(text), lang), "source": "offline"}
        
        safe_text = pii_guard.redact(text)
        prompt = self._build_prompt(lang, prefecture, safe_text)
        
        last_error = None
        for model in self.MODELS:
            try:
                data = self._generate(model, [{"text": prompt}], json_mode=True)
                return {"success": True, "data": data, "source": "ai"}
            except Exception as e:
                last_error = e
                continue
        
        # All models failed — use fallback
        fallback = get_fallback(text)
        return {
            "success": True,
            "data": format_fallback(fallback, lang),
            "source": "fallback",
            "error": str(last_error)
        }
    
    def process_image(self, image_bytes: bytes, mime_type: str, lang: str, prefecture: str) -> dict:
        """Process image document via Gemini REST API."""
        if not self.available:
            return {"success": False, "error": "AI not configured", "source": "offline"}
        
        # Validate size (20MB total request limit for inline data)
        if len(image_bytes) > 20 * 1024 * 1024:
            return {"success": False, "error": "Image too large (max 20MB for inline upload)", "source": "error"}
        
        b64_image = base64.b64encode(image_bytes).decode()
        prompt = self._build_prompt(lang, prefecture, "[Image uploaded — please read text from photo]")
        
        last_error = None
        for model in self.MODELS:
            try:
                data = self._generate(model, [
                    {"text": prompt},
                    {"inline_data": {"mime_type": mime_type, "data": b64_image}}
                ], json_mode=True)
                return {"success": True, "data": data, "source": "ai-vision"}
            except Exception as e:
                last_error = e
                continue
        
        return {"success": False, "error": str(last_error), "source": "error"}
    
    def process_audio(self, audio_bytes: bytes, mime_type: str, lang: str, prefecture: str) -> dict:
        """Process audio voice memo via Gemini REST API."""
        if not self.available:
            return {"success": False, "error": "AI not configured", "source": "offline"}
        
        if len(audio_bytes) > 20 * 1024 * 1024:
            return {"success": False, "error": "Audio too large (max 20MB)", "source": "error"}
        
        b64_audio = base64.b64encode(audio_bytes).decode()
        prompt = self._build_prompt(lang, prefecture, "[Voice message uploaded — please transcribe and analyze]")
        
        last_error = None
        for model in self.MODELS:
            try:
                data = self._generate(model, [
                    {"text": prompt},
                    {"inline_data": {"mime_type": mime_type, "data": b64_audio}}
                ], json_mode=True)
                return {"success": True, "data": data, "source": "ai-audio"}
            except Exception as e:
                last_error = e
                continue
        return {"success": False, "error": str(last_error), "source": "error"}

# ============================================================
# TTS HELPER
# ============================================================
def generate_tts_audio(text: str, lang_code: str) -> Optional[str]:
    """
    Generate base64-encoded MP3 audio from text.
    Returns None if gTTS is unavailable or fails.
    """
    if not text:
        return None
    
    try:
        from gtts import gTTS
        
        # Google TTS has an unofficial ~5000 char limit
        MAX_CHARS = 5000
        if len(text) > MAX_CHARS:
            text = text[:MAX_CHARS] + " ..."
        
        tts = gTTS(text=text, lang=lang_code, slow=True)
        mp3_fp = io.BytesIO()
        tts.write_to_fp(mp3_fp)
        mp3_fp.seek(0)
        return base64.b64encode(mp3_fp.read()).decode()
    except ImportError:
        return None
    except Exception:
        return None

# ============================================================
# QR CODE HELPER
# ============================================================
try:
    import qrcode
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

def generate_qr_code(data: str) -> Optional[str]:
    """Generate base64 PNG QR code, or None if qrcode not installed."""
    if not QR_AVAILABLE:
        return None
    try:
        qr = qrcode.QRCode(box_size=4, border=2)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#B83B5E", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return None

# ============================================================
# GLOBAL CSS STYLING
# ============================================================
st.markdown(
    """
    <style>
    .stApp {
        background-color: #FFF0F5 !important;
        color: #1A1A1A !important;
    }
    .stApp, .stApp p, .stApp span, .stApp div, .stApp label,
    .stMarkdown, .stMarkdown p, .stMarkdown div, .stMarkdown span {
        color: #1A1A1A !important;
    }
    [data-testid="stSidebar"] {
        background-color: #FFE4EF !important;
    }
    [data-testid="stSidebar"] * {
        color: #1A1A1A !important;
    }
    /* Textarea and input always white background, dark text */
    .stTextArea textarea,
    .stTextInput input,
    textarea,
    input[type="text"],
    input[type="password"] {
        font-size: 18px !important;
        color: #1A1A1A !important;
        background-color: #FFFFFF !important;
        border: 1px solid #E0A0B5 !important;
        -webkit-text-fill-color: #1A1A1A !important;
    }
    label, p, .stMarkdown p {
        font-size: 18px !important;
    }
    h3, [data-testid="stSubheader"] {
        font-size: 24px !important;
    }
    /* Critical alert animation */
    .critical-alert {
        animation: pulse-red 2s infinite;
        margin-bottom: 16px;
    }
    @keyframes pulse-red {
        0% { box-shadow: 0 0 0 0 rgba(198, 40, 40, 0.4); }
        70% { box-shadow: 0 0 0 20px rgba(198, 40, 40, 0); }
        100% { box-shadow: 0 0 0 0 rgba(198, 40, 40, 0); }
    }
    </style>
    """,
    unsafe_allow_html=True
)

# ============================================================
# UI STYLING (Main App)
# ============================================================
st.markdown("""
    <style>
    @media (prefers-reduced-motion: reduce) {
        .petal { animation: none !important; display: none !important; }
    }
    .main-title { 
        font-size: clamp(28px, 4vw, 40px) !important; 
        font-weight: 900; 
        color: #B83B5E; 
        text-align: center; 
    }
    .sync-text { 
        font-size: clamp(12px, 1.5vw, 14px); 
        color: #2E7D32; 
        font-weight: 600; 
        margin-bottom: 20px; 
        text-align: center; 
    }
    .card-grandma { 
        background-color: #FFF5F6; 
        padding: clamp(16px, 2vw, 28px); 
        border-radius: 20px; 
        border-top: 5px solid #B83B5E; 
        box-shadow: 0 8px 24px rgba(184,59,94,0.12); 
    }
    .card-action { 
        background-color: #FAFAFA; 
        padding: clamp(16px, 2vw, 28px); 
        border-radius: 20px; 
        border-top: 5px solid #6C5CE7; 
        box-shadow: 0 8px 24px rgba(108,92,231,0.10); 
    }
    .gateway-box { 
        background: linear-gradient(135deg, #FFFDE7, #FFF8E1); 
        padding: 20px; 
        border-radius: 14px; 
        border: 1.5px dashed #FBC02D; 
        margin-top: 20px; 
    }
    .urgency-low { border-left: 6px solid #2E7D32; }
    .urgency-medium { border-left: 6px solid #F9A825; }
    .urgency-high { border-left: 6px solid #E65100; }
    .urgency-critical { border-left: 6px solid #C62828; }
    .big-font { font-size: clamp(15px, 1.2vw, 18px) !important; line-height: 1.8; }
    .sakura-divider { 
        text-align: center; 
        font-size: 22px; 
        letter-spacing: 10px; 
        opacity: 0.5; 
        margin: 10px 0 20px 0; 
    }
    .touch-btn button { min-height: 48px; font-size: 16px !important; }
    .history-card { 
        background: white; 
        padding: 12px; 
        border-radius: 12px; 
        margin-bottom: 8px; 
        border: 1px solid #eee; 
    }
    .petal {
        position: fixed; 
        top: -40px; 
        font-size: 18px; 
        opacity: 0.5;
        animation: fall linear infinite; 
        pointer-events: none; 
        z-index: 9999;
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
    st.session_state.db = SakuraDB
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
if 'user_input_value' not in st.session_state:
    st.session_state.user_input_value = ""

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("## 🌸 Sakura Assist v3.0")
    st.markdown("---")

    # Text size
    st.markdown("### 🔤 Text Size")
    font_choice = st.radio("Size:", ["Normal", "Large", "Extra Large"], horizontal=True, index=0)
    st.session_state.font_size = font_choice.lower().replace(" ", "_")

    size_css = {
        "normal": "font-size: 16px !important;",
        "large": "font-size: 20px !important;",
        "extra_large": "font-size: 24px !important;"
    }
    st.markdown(
        f"<style>.big-font, .stMarkdown, .stMarkdown p, .element-container p, label, .stText span {{ {size_css.get(st.session_state.font_size, '')} }}</style>",
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
    selected_prefecture = st.selectbox("Prefecture:", prefectures, index=0)

    st.markdown("---")

    # API Key override
    key_override = ""
    if not GEMINI_API_KEY:
        st.markdown("### 🔑 API Key Override")
        key_override = st.text_input("Enter Gemini API Key:", type="password", key="api_key_input")
    
    active_key = key_override or GEMINI_API_KEY
    st.session_state.translator = GeminiClient(api_key=active_key)

    # Security warnings
    if not FAMILY_PIN_HASH:
        st.error("⚠️ No PIN configured. Set FAMILY_PIN_HASH env var.")
    elif not FAMILY_PIN_SALT:
        st.warning("⚠️ Using legacy PIN hash. Set FAMILY_PIN_SALT for PBKDF2 security.")

    # Admin: Generate secure PIN
    with st.expander("🔐 Admin: Generate Secure PIN"):
        admin_pin = st.text_input("New PIN:", type="password", key="admin_pin")
        if admin_pin and st.button("Generate Hash & Salt"):
            new_salt = os.urandom(32).hex()
            new_hash = hashlib.pbkdf2_hmac('sha256', admin_pin.encode(), new_salt.encode(), 100000).hex()
            st.code(f"FAMILY_PIN_HASH={new_hash}\nFAMILY_PIN_SALT={new_salt}")
            st.info("Add these to your .env file and restart the app.")

    st.markdown("---")
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
    except Exception as e:
        st.caption(f"History unavailable: {e}")

    st.markdown("---")
    st.info("Society 5.0 | Built for USAII 2026")

# ============================================================
# UI STRINGS
# ============================================================
is_jp = "日本語" in lang

text_db = {
    "English": {
        "title": "🌸 Sakura Assist — Your Document Helper",
        "sync": f"🟢 Connected to {selected_prefecture} | {datetime.now().strftime('%B %d, %Y')}",
        "profile": "👵 Home Portal",
        "input_label": "📄 Paste the confusing letter text here:",
        "placeholder": "e.g., I received a letter from the pension office asking for documents...",
        "or_upload": "📷 Or upload a photo of the letter:",
        "btn": "✨ Translate & Explain",
        "output_hdr": "🤖 Here is what the letter means",
        "validation_err": "❌ Please paste some text, upload a photo, or record a voice message first.",
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
        "placeholder": "例: 年金事務所から手紙が来て、書類を送る必要があるようです。",
        "or_upload": "📷 手紙 の 写真 を アップロード:",
        "btn": "✨ さくらAI で かんたんに",
        "output_hdr": "🤖 てがみ の いみ",
        "validation_err": "❌ もじ、写真、またはこえをいれてください。",
        "api_err": "⚠️ AIの キー が みつかりません。サイドバーにキーを入力してください。",
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

    # Demo sample buttons
    st.markdown("#### 🎯 Try a Sample")
    demo_cols = st.columns(3)
    demo_samples = {
        "💰 Pension": "PENSION OFFICE NAGANO: Annual pension review 2026. Submit income certificate (所得証明書) by July 15, 2026. Bring pension book and My Number card.",
        "🏠 Tax": "CITY TAX NOTICE: 2026 resident tax is ¥48,500. Due June 30, 2026. Late payment incurs penalty fees.",
        "🏥 Medical": "HEALTH INSURANCE: Your card expires July 31, 2026. Renew at city hall with proof of address and ID."
    }

    def set_demo_text(text):
        st.session_state.user_input_value = text

    for i, (label, text) in enumerate(demo_samples.items()):
        demo_cols[i].button(label, on_click=set_demo_text, args=(text,), key=f"demo_{i}", use_container_width=True)

    # Text input (controlled by session_state for demo buttons)
    user_input = st.text_area(
        db["input_label"], 
        height=180,
        placeholder=db.get("placeholder", ""),
        key="user_input_value"
    )

    # Image upload
    uploaded_image = None
    if ENABLE_IMAGE_OCR:
        uploaded_image = st.file_uploader(db["or_upload"], type=["jpg", "jpeg", "png"])
        if uploaded_image:
            st.image(uploaded_image, use_container_width=True, caption="📷 Uploaded document")

    # Voice memo
    audio_input = st.audio_input("🎤 Or record a voice message reading the letter")
    if audio_input:
        st.audio(audio_input)

    st.markdown("<div class='touch-btn'>", unsafe_allow_html=True)
    process_trigger = st.button(db["btn"], use_container_width=True, type="primary")
    st.markdown("</div>", unsafe_allow_html=True)

    if user_input and pii_guard.has_pii(user_input):
        st.warning("🔒 Personal information detected and will be hidden before processing.")

    st.markdown("</div>", unsafe_allow_html=True)

# ==================== RIGHT: OUTPUT PANEL ====================
with col2:
    st.markdown("<div class='card-action'>", unsafe_allow_html=True)
    st.subheader(db["output_hdr"])

    if process_trigger:
        has_input = bool(user_input.strip()) or uploaded_image is not None or audio_input is not None
        if not has_input:
            st.error(db["validation_err"])
            st.session_state.last_result = None
            st.session_state.audio_html = None
        elif not st.session_state.translator.available:
            st.error(db["api_err"])
            st.session_state.last_result = None
            st.session_state.audio_html = None
        else:
            with st.spinner("🌸 Sakura AI is reading the letter..."):
                # Priority: Audio > Image > Text
                if audio_input:
                    audio_bytes = audio_input.getvalue()
                    mime_type = audio_input.type or "audio/wav"
                    result = st.session_state.translator.process_audio(
                        audio_bytes, mime_type, lang, selected_prefecture
                    )
                elif uploaded_image:
                    img_bytes = uploaded_image.getvalue()
                    mime_type = uploaded_image.type or "image/jpeg"
                    result = st.session_state.translator.process_image(
                        img_bytes, mime_type, lang, selected_prefecture
                    )
                else:
                    result = st.session_state.translator.process_text(
                        user_input, lang, selected_prefecture
                    )

                st.session_state.last_result = result
                st.session_state.audio_html = None

                # Save to DB on success
                if result.get("success"):
                    data = result["data"]
                    safe_raw = pii_guard.redact(user_input[:500]) if user_input else "[IMAGE/AUDIO]"
                    
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
                    except Exception as e:
                        st.session_state.last_doc_id = None
                        st.warning(f"⚠️ Could not save to history: {e}")

                # Generate TTS audio
                if ENABLE_TTS and result.get("success"):
                    with st.spinner("🔊 Generating audio..."):
                        d = result["data"]
                        comfort = d.get("comfort_message", "")
                        summary = d.get("summary", "")
                        deadline = d.get("deadline")
                        acts = d.get("actions", [])

                        parts = [comfort, summary]
                        if deadline and str(deadline).lower() not in ("null", "none", ""):
                            parts.append(
                                f"期限は {deadline} です。" if is_jp
                                else f"The deadline is {deadline}."
                            )
                        if acts:
                            parts.append("やることは次の通りです。" if is_jp else "Here are the steps to take.")
                            for a in acts:
                                step = a.get("step_number", "")
                                task = a.get("task", "")
                                if task:
                                    parts.append(
                                        f"{step}番目: {task}" if is_jp
                                        else f"Step {step}: {task}"
                                    )

                        tts_text = " ".join(p for p in parts if p).strip()
                        tts_lang = "ja" if is_jp else "en"
                        
                        b64_audio = generate_tts_audio(tts_text, tts_lang)
                        if b64_audio:
                            st.session_state.audio_html = f'''
                                <audio autoplay controls style="width:100%; margin-top:10px;">
                                    <source src="data:audio/mp3;base64,{b64_audio}" type="audio/mpeg">
                                </audio>
                            '''

    # RENDER RESULTS
    if st.session_state.last_result:
        result = st.session_state.last_result
        
        if not result.get("success"):
            st.markdown("""
            <div style="background:#FFF0F5; padding:20px; border-radius:14px; border-left:5px solid #B83B5E; margin-bottom:10px;">
                <span style="font-size:22px;">🌸</span>
                <b style="color:#B83B5E; font-size:18px;"> Sakura is resting for a moment</b>
                <div class="big-font" style="margin-top:8px; color:#555;">
                    The AI helper is taking a short break. Please try again in a minute,
                    or use the offline guide below for now.
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Show offline fallback for the original text if available
            if user_input:
                fb = format_fallback(get_fallback(user_input), lang)
                st.markdown("### 📴 Offline Guide")
                st.markdown(f"**{fb['doc_type']}**")
                st.markdown(f"*{fb['comfort_message']}*")
                st.markdown(fb['summary'])
                for a in fb['actions']:
                    st.markdown(f"**Step {a['step_number']}:** {a['task']}")
        else:
            data = result["data"]
            source = result.get("source", "unknown")

            if source == "fallback":
                st.markdown("""
                <div style="background:#FFF8E1; padding:14px 18px; border-radius:14px; border-left:5px solid #FBC02D; margin-bottom:14px;">
                    🌸 <b>Using our trusted offline guide</b> — Sakura AI is briefly busy, so here's a reliable starting explanation.
                </div>
                """, unsafe_allow_html=True)
            elif source == "offline":
                st.markdown("""
                <div style="background:#E8F5E9; padding:14px 18px; border-radius:14px; border-left:5px solid #2E7D32; margin-bottom:14px;">
                    📴 <b>Offline helper active</b> — showing our built-in guide for this type of letter.
                </div>
                """, unsafe_allow_html=True)

            urgency = data.get("urgency_level", "medium")
            urgency_class = f"urgency-{urgency}"

            # CRITICAL ALERT ANIMATION
            if urgency == "critical":
                st.markdown("""
                <div class="critical-alert" style="background:#FFEBEE; padding:16px; border-radius:12px; border:2px solid #C62828; text-align:center;">
                    <span style="font-size:32px;">🚨</span><br>
                    <b style="color:#C62828; font-size:20px;">CRITICAL — Please act immediately!</b><br>
                    <span style="color:#555;">Contact your family or city hall today.</span>
                </div>
                """, unsafe_allow_html=True)

            st.markdown(f"<div class='{urgency_class}' style='padding-left:12px; margin-bottom:16px;'>", unsafe_allow_html=True)
            st.markdown(f"**📋 {data.get('doc_type', 'Document')}**")
            st.markdown(f"<div class='big-font'><b>{data.get('comfort_message', '')}</b></div>", unsafe_allow_html=True)
            st.markdown(f"<div class='big-font'>{data.get('summary', '')}</div>", unsafe_allow_html=True)

            deadline = data.get("deadline")
            if deadline and str(deadline).lower() not in ("null", "none", ""):
                st.markdown(f"""
                <div style="background:#FFF3E0; padding:10px 14px; border-radius:10px; margin:10px 0; border-left:4px solid #EF6C00;">
                    <b>⏰ {db['deadline']}:</b> {deadline}
                </div>
                """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

            # Audio player (autoplay requested; browsers may block until user interaction)
            if st.session_state.audio_html:
                st.markdown(f"<b>{db['tts_label']}</b>", unsafe_allow_html=True)
                st.markdown(st.session_state.audio_html, unsafe_allow_html=True)

            st.markdown("---")
            st.markdown(f"### ✅ {db['department'] if is_jp else 'Steps to take'}")
            actions = data.get("actions", [])
            if not actions:
                st.info("No specific steps provided.")
            for action in actions:
                step = action.get("step_number", 0)
                task = action.get("task", "")
                if not task:
                    continue
                act_deadline = action.get("deadline")
                contact = action.get("contact")
                deadline_str = f" — ⏰ {act_deadline}" if act_deadline and str(act_deadline).lower() not in ("null", "none", "") else ""
                contact_str = f"<br>📞 {contact}" if contact else ""

                st.markdown(f"""
                <div style="background:white; padding:14px; border-radius:12px; margin-bottom:10px; border:1px solid #E0E0E0; box-shadow:0 2px 8px rgba(0,0,0,0.04);">
                    <span style="background:#B83B5E; color:white; padding:4px 10px; border-radius:20px; font-size:13px; font-weight:bold;">Step {step}</span>
                    <div class="big-font" style="margin-top:8px;">{task}{deadline_str}{contact_str}</div>
                </div>
                """, unsafe_allow_html=True)

            # Metadata
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

            # QR CODE SHARING (clean text format)
            qr_lines = [f"🌸 Sakura Assist Alert", f"📋 {data.get('doc_type', 'Document')}"]
            if data.get('deadline') and str(data.get('deadline')).lower() not in ('null', 'none', ''):
                qr_lines.append(f"⏰ Deadline: {data['deadline']}")
            qr_lines.append(f"📝 {data.get('summary', '')}")
            qr_lines.append("✅ Steps:")
            for i, a in enumerate(actions, 1):
                if a.get('task'):
                    qr_lines.append(f"{i}. {a['task']}")
            qr_payload = "\n".join(qr_lines)
            
            qr_b64 = generate_qr_code(qr_payload)
            if qr_b64:
                st.markdown("---")
                st.markdown("### 📱 Share with Family")
                st.markdown(
                    f'<div style="text-align:center; background:white; padding:16px; border-radius:16px; border:2px solid #B83B5E;">'
                    f'<img src="data:image/png;base64,{qr_b64}" width="180">'
                    f'<p style="font-size:12px; color:#666; margin-top:8px;">Scan to view summary</p></div>',
                    unsafe_allow_html=True
                )

            # DOWNLOAD REPORT
            report = {
                "document_type": data.get("doc_type"),
                "summary": data.get("summary"),
                "comfort_message": data.get("comfort_message"),
                "urgency": data.get("urgency_level"),
                "deadline": data.get("deadline"),
                "actions": data.get("actions"),
                "department": data.get("department"),
                "contact": data.get("contact_phone"),
                "generated_at": datetime.now().isoformat()
            }
            report_json = json.dumps(report, ensure_ascii=False, indent=2)
            st.download_button(
                label="📥 Save Report",
                data=report_json,
                file_name=f"sakura_report_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
                use_container_width=True
            )

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
Actions: {', '.join([a['task'] for a in actions if a.get('task')])}
Deadline: {data.get('deadline', 'None')}
"""
                    notify_result = st.session_state.notifier.send(msg, st.session_state.last_doc_id or 0)

                    if notify_result.get("demo"):
                        st.info(f"{db['demo_mode']}\n\n{notify_result['demo_message']}")
                    else:
                        sent_methods = []
                        if notify_result.get("line"): sent_methods.append("LINE")
                        if notify_result.get("email"): sent_methods.append("Email")
                        if sent_methods:
                            st.success(f"📲 Sent via: {', '.join(sent_methods)}")
                        else:
                            st.info("📲 Notification attempted but no delivery method confirmed.")

                    if st.session_state.last_doc_id:
                        try:
                            st.session_state.db.mark_notified(st.session_state.last_doc_id)
                        except Exception as e:
                            st.warning(f"Could not mark as notified: {e}")
                    
                    try:
                        st.toast("🎉 Sent to family!", icon="🎉")
                        # Confetti burst
                        components.html("""
                        <script src="https://cdn.jsdelivr.net/npm/canvas-confetti@1.6.0/dist/confetti.browser.min.js"></script>
                        <script>
                            confetti({
                                particleCount: 150,
                                spread: 70,
                                origin: {y: 0.6},
                                colors: ['#B83B5E', '#FF69B4', '#FFB6C1', '#6C5CE7']
                            });
                        </script>
                        """, height=0)
                    except Exception:
                        pass
                else:
                    st.error(db["wrong_pin"])

            st.markdown("</div>", unsafe_allow_html=True)
    else:
        st.info("👈 Paste a document, upload a photo, record your voice, or try a sample and click the button.")

    st.markdown("</div>", unsafe_allow_html=True)

st.markdown("<div class='sakura-divider'>🌸 🌺 🌸 🌺 🌸 🌺 🌸</div>", unsafe_allow_html=True)
st.markdown("""
<div style="text-align:center; color:#888; font-size:12px; padding:20px;">
    🌸 Sakura Assist v3.0 | Built for USAII Global Hackathon 2026<br>
    Accessibility First • Privacy Protected • Society 5.0 Compliant
</div>
""", unsafe_allow_html=True)
