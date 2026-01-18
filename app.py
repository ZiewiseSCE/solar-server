# -*- coding: utf-8 -*-
"""
SCEnergy Solar Server (Cloudtype friendly)

- /health always returns 200 quickly (readiness probe)
- Users DB:
    * If DATABASE_URL is set -> Postgres
    * Else -> SQLite (ephemeral in many PaaS)
  DB init failures NEVER crash the server (important for PaaS readiness)
- Admin bootstrap:
    * ADMIN_ID + ADMIN_PW (plain) or ADMIN_PW_HASH (hashed)
"""

import os
import json
import datetime
import logging
import sqlite3
from typing import Optional, Tuple, Any, Dict

import requests
import urllib3

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from werkzeug.security import generate_password_hash, check_password_hash

# Optional Gemini (legacy google-generativeai). Keep backward compatible.
try:
    import google.generativeai as genai  # type: ignore
except Exception:
    genai = None  # type: ignore

# Optional Postgres driver
try:
    import psycopg2  # type: ignore
except Exception:
    psycopg2 = None  # type: ignore


# ---------------------------------------------------------
# Config
# ---------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenergy")

DATABASE_URL = os.environ.get("DATABASE_URL")  # MUST exist as a variable (avoid NameError)
USER_DB_PATH = os.environ.get("USER_DB_PATH", "users.db")  # used when sqlite

ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
ADMIN_PW = os.environ.get("ADMIN_PW", "")
ADMIN_PW_HASH = os.environ.get("ADMIN_PW_HASH", "")
if not ADMIN_PW_HASH and ADMIN_PW:
    ADMIN_PW_HASH = generate_password_hash(ADMIN_PW)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or ""
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")

# External services (optional)
VWORLD_KEY = os.environ.get("VWORLD_KEY", "")  # if you use VWorld APIs
BACKEND_BASE_URL = os.environ.get("BACKEND_URL", "")  # front can set too

# ---------------------------------------------------------
# App
# ---------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app, supports_credentials=True)

# Session secret
app.secret_key = os.environ.get("SECRET_KEY") or os.environ.get("FLASK_SECRET_KEY") or "dev-secret-change-me"


# ---------------------------------------------------------
# HTTP session w/ retry (for external calls)
# ---------------------------------------------------------
_http = requests.Session()
retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
_http.mount("https://", HTTPAdapter(max_retries=retries))
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------
# Helpers: Auth
# ---------------------------------------------------------
def _now_iso() -> str:
    return datetime.datetime.utcnow().isoformat()

def _is_logged_in() -> bool:
    return bool(session.get("user_id"))

def _is_admin() -> bool:
    return session.get("role") == "admin"

def _require_login() -> Optional[Tuple[Any, int]]:
    if not _is_logged_in():
        return jsonify({"ok": False, "error": "login_required"}), 401
    return None

def _require_admin() -> Optional[Tuple[Any, int]]:
    if not _is_logged_in() or not _is_admin():
        return jsonify({"ok": False, "error": "admin_required"}), 403
    return None


# ---------------------------------------------------------
# Helpers: Users DB (sqlite or postgres)
# ---------------------------------------------------------
def _userdb_kind() -> str:
    # Safe: DATABASE_URL is always defined (may be None)
    if DATABASE_URL:
        return "postgres"
    return "sqlite"

def _db_sqlite() -> sqlite3.Connection:
    conn = sqlite3.connect(USER_DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def _db_pg():
    if not psycopg2:
        raise RuntimeError("psycopg2 is not installed. Add psycopg2-binary to requirements.txt")
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is missing")
    return psycopg2.connect(DATABASE_URL)

def init_user_db() -> None:
    """
    IMPORTANT: Must NEVER crash app startup.
    """
    try:
        kind = _userdb_kind()

        if kind == "postgres":
            conn = _db_pg()
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    pw_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

            # ensure admin exists
            if ADMIN_PW_HASH:
                cur.execute("SELECT id FROM users WHERE id=%s", (ADMIN_ID,))
                row = cur.fetchone()
                if not row:
                    cur.execute(
                        "INSERT INTO users (id, pw_hash, role, created_at) VALUES (%s, %s, %s, %s)",
                        (ADMIN_ID, ADMIN_PW_HASH, "admin", _now_iso())
                    )
                    conn.commit()

            cur.close()
            conn.close()
            logger.info("User DB initialized (postgres).")

        else:
            conn = _db_sqlite()
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    pw_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'user',
                    created_at TEXT NOT NULL
                )
            """)
            conn.commit()

            if ADMIN_PW_HASH:
                cur.execute("SELECT id FROM users WHERE id=?", (ADMIN_ID,))
                row = cur.fetchone()
                if not row:
                    cur.execute(
                        "INSERT INTO users (id, pw_hash, role, created_at) VALUES (?, ?, ?, ?)",
                        (ADMIN_ID, ADMIN_PW_HASH, "admin", _now_iso())
                    )
                    conn.commit()

            cur.close()
            conn.close()
            logger.info("User DB initialized (sqlite).")

    except Exception as e:
        # Do NOT crash startup (needed for readiness probe)
        logger.error("⚠️ init_user_db failed; continuing without blocking startup.")
        logger.error(repr(e))


def _user_get(user_id: str) -> Optional[Dict[str, Any]]:
    kind = _userdb_kind()
    if kind == "postgres":
        conn = _db_pg()
        cur = conn.cursor()
        cur.execute("SELECT id, pw_hash, role, created_at FROM users WHERE id=%s", (user_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return None
        return {"id": row[0], "pw_hash": row[1], "role": row[2], "created_at": row[3]}
    else:
        conn = _db_sqlite()
        cur = conn.cursor()
        cur.execute("SELECT id, pw_hash, role, created_at FROM users WHERE id=?", (user_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return None
        return {"id": row["id"], "pw_hash": row["pw_hash"], "role": row["role"], "created_at": row["created_at"]}

def _user_upsert(user_id: str, pw_hash: str, role: str = "user") -> None:
    kind = _userdb_kind()
    if kind == "postgres":
        conn = _db_pg()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE id=%s", (user_id,))
        exists = cur.fetchone()
        if exists:
            cur.execute("UPDATE users SET pw_hash=%s, role=%s WHERE id=%s", (pw_hash, role, user_id))
        else:
            cur.execute(
                "INSERT INTO users (id, pw_hash, role, created_at) VALUES (%s, %s, %s, %s)",
                (user_id, pw_hash, role, _now_iso())
            )
        conn.commit()
        cur.close()
        conn.close()
    else:
        conn = _db_sqlite()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE id=?", (user_id,))
        exists = cur.fetchone()
        if exists:
            cur.execute("UPDATE users SET pw_hash=?, role=? WHERE id=?", (pw_hash, role, user_id))
        else:
            cur.execute("INSERT INTO users (id, pw_hash, role, created_at) VALUES (?, ?, ?, ?)", (user_id, pw_hash, role, _now_iso()))
        conn.commit()
        cur.close()
        conn.close()

def _user_delete(user_id: str) -> None:
    kind = _userdb_kind()
    if kind == "postgres":
        conn = _db_pg()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        cur.close()
        conn.close()
    else:
        conn = _db_sqlite()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
        cur.close()
        conn.close()

def _users_list() -> list:
    kind = _userdb_kind()
    if kind == "postgres":
        conn = _db_pg()
        cur = conn.cursor()
        cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [{"id": r[0], "role": r[1], "created_at": r[2]} for r in rows]
    else:
        conn = _db_sqlite()
        cur = conn.cursor()
        cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return [{"id": r["id"], "role": r["role"], "created_at": r["created_at"]} for r in rows]


# Initialize user DB at import time, but safely (won't crash)
init_user_db()


# ---------------------------------------------------------
# Health (readiness/liveness)
# ---------------------------------------------------------
@app.get("/health")
def health_check():
    # Never touch DB / external services here
    return "ok", 200


# ---------------------------------------------------------
# Pages
# ---------------------------------------------------------
@app.get("/")
def index():
    return render_template("index.html")

@app.post("/report")
def report_page():
    """
    Receives JSON-stringified analysis data (from form hidden input "analysisData").
    Renders templates/report.html (Jinja) with `data` context.
    """
    raw = request.form.get("analysisData") or request.json or "{}"
    if isinstance(raw, dict):
        data = raw
    else:
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
    # Simple normalization
    data.setdefault("address", request.form.get("address", "") or data.get("address", ""))
    data.setdefault("date", request.form.get("date", "") or data.get("date", _now_iso()[:10]))
    # Make sure finance keys exist
    data.setdefault("finance", {})
    fin = data["finance"]
    if "capacity" not in fin and "acCapacity" in fin:
        fin["capacity"] = fin.get("acCapacity")
    if "kepco_capacity" not in data:
        # allow nesting from ai_analysis
        ks = (data.get("ai_analysis") or {}).get("kepco_capacity")
        if ks:
            data["kepco_capacity"] = ks
    return render_template("report.html", data=data)


# ---------------------------------------------------------
# Auth APIs
# ---------------------------------------------------------
@app.post("/api/auth/login")
def api_login():
    payload = request.get_json(silent=True) or {}
    user_id = (payload.get("id") or "").strip()
    pw = payload.get("pw") or ""
    if not user_id or not pw:
        return jsonify({"ok": False, "error": "missing_credentials"}), 400

    u = _user_get(user_id)
    if not u:
        return jsonify({"ok": False, "error": "invalid_credentials"}), 401

    if not check_password_hash(u["pw_hash"], pw):
        return jsonify({"ok": False, "error": "invalid_credentials"}), 401

    session["user_id"] = u["id"]
    session["role"] = u["role"]
    return jsonify({"ok": True, "id": u["id"], "role": u["role"]})

@app.post("/api/auth/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.get("/api/auth/me")
def api_me():
    if not _is_logged_in():
        return jsonify({"ok": False, "logged_in": False})
    return jsonify({"ok": True, "logged_in": True, "id": session.get("user_id"), "role": session.get("role")})


# ---------------------------------------------------------
# Admin APIs
# ---------------------------------------------------------
@app.get("/api/admin/users")
def admin_users_list():
    auth = _require_admin()
    if auth:
        return auth
    return jsonify({"ok": True, "users": _users_list()})

@app.post("/api/admin/users")
def admin_users_create():
    auth = _require_admin()
    if auth:
        return auth
    payload = request.get_json(silent=True) or {}
    user_id = (payload.get("id") or "").strip()
    pw = payload.get("pw") or ""
    role = (payload.get("role") or "user").strip()
    if not user_id or not pw:
        return jsonify({"ok": False, "error": "missing_fields"}), 400
    if role not in ("user", "admin"):
        role = "user"
    _user_upsert(user_id, generate_password_hash(pw), role)
    return jsonify({"ok": True})

@app.delete("/api/admin/users/<user_id>")
def admin_users_delete(user_id: str):
    auth = _require_admin()
    if auth:
        return auth
    if user_id == ADMIN_ID:
        return jsonify({"ok": False, "error": "cannot_delete_admin"}), 400
    _user_delete(user_id)
    return jsonify({"ok": True})


# ---------------------------------------------------------
# Analysis API (keeps compatibility with your frontend)
# ---------------------------------------------------------
def _gemini_summary(context: Dict[str, Any]) -> str:
    if not genai or not GEMINI_API_KEY:
        return "AI 분석 지연"
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = (
            "태양광 부지 분석. 점수/등급 언급 없이 리스크/장점 3줄 요약.\n"
            f"주소:{context.get('address')}\n"
            f"용도:{context.get('zoning')}\n"
            f"지목:{context.get('jimok')}\n"
            f"생태:{context.get('eco')}\n"
            f"일사량:{context.get('sun')}h\n"
        )
        resp = model.generate_content(prompt)
        return getattr(resp, "text", "") or "분석 완료"
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return "AI 분석 지연"

@app.post("/api/analyze/comprehensive")
def analyze_comprehensive():
    payload = request.get_json(silent=True) or {}
    address = payload.get("address", "")
    # Provide deterministic placeholders if fields missing
    finance = payload.get("finance") or {}
    if "capacity" not in finance and "acCapacity" in finance:
        finance["capacity"] = finance.get("acCapacity")
    # Example/placeholder outputs
    ai_score = payload.get("ai_score") or {
        "score": 78,
        "grade": "B",
        "risk_flags": ["계통여유 확인 필요", "농지전용 여부 검토"]
    }
    env_assessment = payload.get("env_assessment") or {
        "eco_grade": "미확인",
        "heritage": "미확인",
        "protected_area": "미확인",
        "note": "상세 확인 필요"
    }
    context = {
        "address": address,
        "zoning": payload.get("zoning", ""),
        "jimok": payload.get("jimok", ""),
        "eco": (env_assessment or {}).get("eco_grade", ""),
        "sun": payload.get("sun", payload.get("sun_hours", "")),
    }
    ai_text = _gemini_summary(context)

    local = (address.split()[:2] + [""])[0] if address else ""
    return jsonify({
        "ok": True,
        "address": address,
        "date": _now_iso()[:10],
        "finance": finance,
        "ai_analysis": {
            "summary": ai_text,
            "ai_score": ai_score,
            "env_assessment": env_assessment,
            "kepco_capacity": payload.get("kepco_capacity", "데이터 없음 (한전ON 확인)")
        },
        "links": {
            "elis": f"https://www.elis.go.kr/search/normSearch?searchType=ALL&searchKeyword={local}+태양광",
            "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
            "kepco": "https://online.kepco.co.kr/",
            "neins": "https://webgis.neins.go.kr/map.do",
            "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?"
        }
    })


# ---------------------------------------------------------
# Run (local)
# ---------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
