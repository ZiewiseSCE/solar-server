# -*- coding: utf-8 -*-
"""
Cloudtype-friendly Flask backend for solar-server

Key fixes:
- /health always returns 200 quickly (readiness probe)
- User DB supports:
  * PostgreSQL (when DATABASE_URL is provided)
  * SQLite fallback (USER_DB_PATH)
- init_user_db() never crashes the process (wrapped in try/except)
- Admin auto-provisioning via ADMIN_ID + (ADMIN_PW or ADMIN_PW_HASH)
"""

import os
import json
import datetime
import logging
import sqlite3
from contextlib import contextmanager

import requests
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from werkzeug.security import generate_password_hash, check_password_hash

# Optional: rate limiter (installed in your requirements)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None
    get_remote_address = None

# Optional (Gemini SDK)
try:
    import google.generativeai as genai  # warning is fine; migrate later if desired
except Exception:
    genai = None


# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("solar-server")


# ---------------------------------------------------------
# App init
# ---------------------------------------------------------
app = Flask(__name__, template_folder="templates")
CORS(app, supports_credentials=True)

# Secret key for session cookies (MUST be set in production)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")

# Limiter (optional)
if Limiter and get_remote_address:
    limiter = Limiter(get_remote_address, app=app, default_limits=["300 per minute"])
else:
    limiter = None


# ---------------------------------------------------------
# Environment variables
# ---------------------------------------------------------
PORT = int(os.environ.get("PORT", "5000"))

# User DB: prefer managed DB (PostgreSQL) if provided
DATABASE_URL = os.environ.get("DATABASE_URL")  # e.g. postgresql://user:pw@host:5432/db
USER_DB_PATH = os.environ.get("USER_DB_PATH", "users.db")  # sqlite fallback path

ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
# allow either pre-hashed password or plaintext password
ADMIN_PW_HASH = os.environ.get("ADMIN_PW_HASH", "")
ADMIN_PW = os.environ.get("ADMIN_PW", "")

if (not ADMIN_PW_HASH) and ADMIN_PW:
    ADMIN_PW_HASH = generate_password_hash(ADMIN_PW)

VWORLD_KEY = os.environ.get("VWORLD_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
MY_DOMAIN_URL = os.environ.get("MY_DOMAIN_URL", "")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; solar-server/1.0)",
}
if MY_DOMAIN_URL:
    # Some public APIs may require referer/origin
    HEADERS["Referer"] = MY_DOMAIN_URL
    HEADERS["Origin"] = MY_DOMAIN_URL


# Requests session with retry
_session = requests.Session()
retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
_session.mount("https://", HTTPAdapter(max_retries=retries))
_session.mount("http://", HTTPAdapter(max_retries=retries))


# Gemini init
if genai and GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        logger.info("Gemini configured.")
    except Exception as e:
        logger.warning(f"Gemini init failed: {e}")


# ---------------------------------------------------------
# User DB helpers (Postgres optional)
# ---------------------------------------------------------
def _userdb_kind() -> str:
    return "postgres" if DATABASE_URL else "sqlite"


def _normalize_db_url(url: str) -> str:
    # Some platforms give postgres:// which psycopg2 accepts, but normalize anyway
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://"):]
    return url


def _pg_connect():
    try:
        import psycopg2  # requires psycopg2-binary in requirements
    except Exception as e:
        raise RuntimeError("psycopg2 is required for PostgreSQL. Add psycopg2-binary to requirements.txt") from e

    return psycopg2.connect(_normalize_db_url(DATABASE_URL))


@contextmanager
def _db_conn():
    """
    Context manager yielding (kind, conn, cursor)
    Cursor is a DB-API cursor.
    """
    kind = _userdb_kind()
    if kind == "postgres":
        conn = _pg_connect()
        cur = conn.cursor()
        try:
            yield kind, conn, cur
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass
    else:
        conn = sqlite3.connect(USER_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            yield kind, conn, cur
        finally:
            try:
                cur.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass


def init_user_db():
    """
    Creates users table and auto-inserts admin if ADMIN_PW/ADMIN_PW_HASH provided.
    Must never crash the server process.
    """
    try:
        with _db_conn() as (kind, conn, cur):
            if kind == "postgres":
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
                    cur.execute("SELECT id FROM users WHERE id=%s", (ADMIN_ID,))
                    row = cur.fetchone()
                    if not row:
                        cur.execute(
                            "INSERT INTO users (id, pw_hash, role, created_at) VALUES (%s, %s, %s, %s)",
                            (ADMIN_ID, ADMIN_PW_HASH, "admin", datetime.datetime.utcnow().isoformat()),
                        )
                        conn.commit()
                        logger.info("Admin user inserted into Postgres.")
                else:
                    logger.warning("ADMIN_PW/ADMIN_PW_HASH not set. Admin login will fail.")

            else:
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
                            (ADMIN_ID, ADMIN_PW_HASH, "admin", datetime.datetime.utcnow().isoformat()),
                        )
                        conn.commit()
                        logger.info("Admin user inserted into SQLite.")
                else:
                    logger.warning("ADMIN_PW/ADMIN_PW_HASH not set. Admin login will fail.")

    except Exception as e:
        # Do not crash the server; readiness probe must pass.
        logger.error("⚠️ init_user_db failed, continuing without DB init")
        logger.error(repr(e))


# Run DB init safely at import time
init_user_db()


# ---------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------
def require_login():
    if not session.get("user_id"):
        return jsonify({"status": "ERROR", "msg": "Not logged in"}), 401
    return None


def require_admin():
    if not session.get("user_id"):
        return jsonify({"status": "ERROR", "msg": "Not logged in"}), 401
    if session.get("role") != "admin":
        return jsonify({"status": "FORBIDDEN", "msg": "Admin only"}), 403
    return None


# ---------------------------------------------------------
# Routes (pages)
# ---------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health_check():
    # keep super-light: no DB, no network
    return "OK", 200


@app.route("/report", methods=["POST"])
def report_page():
    """
    Renders templates/report.html (Jinja template) using posted form fields.
    Frontend sends json strings for some fields; normalize them here.
    """
    data = request.form.to_dict()

    # Normalize/parse common json fields if present
    for k in ["finance", "ai_analysis"]:
        if k in data and isinstance(data[k], str):
            try:
                data[k] = json.loads(data[k])
            except Exception:
                pass

    # Ensure nested keys exist for report template safety
    if "finance" not in data:
        data["finance"] = {}
    if "ai_analysis" not in data:
        data["ai_analysis"] = {}

    # Backfill kepco_capacity if missing
    if not data["ai_analysis"].get("kepco_capacity") and data.get("kepco_capacity"):
        data["ai_analysis"]["kepco_capacity"] = data.get("kepco_capacity")

    # Backfill capacity if missing (some frontends send acCapacity)
    fin = data.get("finance", {}) if isinstance(data.get("finance"), dict) else {}
    if fin and (not fin.get("capacity")) and fin.get("acCapacity"):
        fin["capacity"] = fin.get("acCapacity")

    # Ensure report has at least address/date
    if not data.get("address"):
        data["address"] = "주소 미상"
    if not data.get("date"):
        data["date"] = datetime.datetime.now().strftime("%Y-%m-%d")

    return render_template("report.html", data=data)


# ---------------------------------------------------------
# Auth API
# ---------------------------------------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    user_id = (payload.get("id") or "").strip()
    pw = payload.get("pw") or ""

    if not user_id or not pw:
        return jsonify({"status": "ERROR", "msg": "Missing id/pw"}), 400

    try:
        with _db_conn() as (kind, conn, cur):
            if kind == "postgres":
                cur.execute("SELECT id, pw_hash, role FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"status": "ERROR", "msg": "Invalid credentials"}), 401
                # psycopg2 returns tuple
                db_id, db_hash, db_role = row[0], row[1], row[2]
            else:
                cur.execute("SELECT id, pw_hash, role FROM users WHERE id=?", (user_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"status": "ERROR", "msg": "Invalid credentials"}), 401
                db_id, db_hash, db_role = row["id"], row["pw_hash"], row["role"]

        if not check_password_hash(db_hash, pw):
            return jsonify({"status": "ERROR", "msg": "Invalid credentials"}), 401

        session["user_id"] = db_id
        session["role"] = db_role
        return jsonify({"status": "OK", "user": {"id": db_id, "role": db_role}})

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({"status": "ERROR", "msg": "Login failed"}), 500


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "OK"})


@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if not session.get("user_id"):
        return jsonify({"status": "OK", "user": None})
    return jsonify({"status": "OK", "user": {"id": session.get("user_id"), "role": session.get("role")}})


# ---------------------------------------------------------
# Admin API
# ---------------------------------------------------------
@app.route("/api/admin/users", methods=["GET"])
def admin_users_list():
    err = require_admin()
    if err:
        return err

    try:
        with _db_conn() as (kind, conn, cur):
            if kind == "postgres":
                cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC")
                rows = cur.fetchall() or []
                users = [{"id": r[0], "role": r[1], "created_at": r[2]} for r in rows]
            else:
                cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC")
                rows = cur.fetchall() or []
                users = [{"id": r["id"], "role": r["role"], "created_at": r["created_at"]} for r in rows]

        return jsonify({"status": "OK", "users": users})

    except Exception as e:
        logger.error(f"admin_users_list error: {e}")
        return jsonify({"status": "ERROR", "msg": "Failed"}), 500


@app.route("/api/admin/users", methods=["POST"])
def admin_users_create():
    err = require_admin()
    if err:
        return err

    payload = request.get_json(silent=True) or {}
    user_id = (payload.get("id") or "").strip()
    pw = payload.get("pw") or ""
    role = (payload.get("role") or "user").strip() or "user"

    if not user_id or not pw:
        return jsonify({"status": "ERROR", "msg": "Missing id/pw"}), 400

    pw_hash = generate_password_hash(pw)
    created_at = datetime.datetime.utcnow().isoformat()

    try:
        with _db_conn() as (kind, conn, cur):
            if kind == "postgres":
                cur.execute("SELECT id FROM users WHERE id=%s", (user_id,))
                if cur.fetchone():
                    return jsonify({"status": "ERROR", "msg": "User exists"}), 409
                cur.execute(
                    "INSERT INTO users (id, pw_hash, role, created_at) VALUES (%s, %s, %s, %s)",
                    (user_id, pw_hash, role, created_at),
                )
                conn.commit()
            else:
                cur.execute("SELECT id FROM users WHERE id=?", (user_id,))
                if cur.fetchone():
                    return jsonify({"status": "ERROR", "msg": "User exists"}), 409
                cur.execute(
                    "INSERT INTO users (id, pw_hash, role, created_at) VALUES (?, ?, ?, ?)",
                    (user_id, pw_hash, role, created_at),
                )
                conn.commit()

        return jsonify({"status": "OK"})

    except Exception as e:
        logger.error(f"admin_users_create error: {e}")
        return jsonify({"status": "ERROR", "msg": "Failed"}), 500


@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
def admin_users_delete(user_id):
    err = require_admin()
    if err:
        return err

    if user_id == ADMIN_ID:
        return jsonify({"status": "ERROR", "msg": "Cannot delete admin"}), 400

    try:
        with _db_conn() as (kind, conn, cur):
            if kind == "postgres":
                cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
                conn.commit()
            else:
                cur.execute("DELETE FROM users WHERE id=?", (user_id,))
                conn.commit()

        return jsonify({"status": "OK"})

    except Exception as e:
        logger.error(f"admin_users_delete error: {e}")
        return jsonify({"status": "ERROR", "msg": "Failed"}), 500


# ---------------------------------------------------------
# External / AI helpers (copied from your original backend logic)
# ---------------------------------------------------------
def get_solar_irradiance(lat, lng):
    # Placeholder: no real irradiance API configured; keep stable
    # You can replace with real API later.
    try:
        lat = float(lat)
        lng = float(lng)
        # simple heuristic: higher in south
        base = 3.2
        if lat < 35.0:
            base += 0.3
        if lat < 34.0:
            base += 0.2
        return round(base, 2)
    except Exception:
        return 3.2


def fetch_vworld_info(layer, lat, lng):
    if not VWORLD_KEY:
        return None
    try:
        url = "https://api.vworld.kr/req/data"
        params = {
            "key": VWORLD_KEY,
            "service": "data",
            "version": "2.0",
            "request": "GetFeature",
            "format": "json",
            "size": 1,
            "page": 1,
            "data": layer,
            "geomFilter": f"POINT({lng} {lat})",
            "crs": "EPSG:4326",
        }
        r = _session.get(url, params=params, headers=HEADERS, timeout=10)
        r.raise_for_status()
        js = r.json()
        feats = js.get("response", {}).get("result", {}).get("featureCollection", {}).get("features", [])
        if not feats:
            return None
        props = feats[0].get("properties", {}) or {}
        # pick a meaningful property
        for k in ["uquq_nm", "grade", "jibun", "jimok", "emd_kor_nm", "addr", "name"]:
            if props.get(k):
                return str(props.get(k))
        return json.dumps(props, ensure_ascii=False)
    except Exception as e:
        logger.warning(f"fetch_vworld_info failed: {e}")
        return None


def calculate_ai_score(ctx: dict):
    # simple heuristic scoring
    zoning = (ctx.get("zoning") or "")
    eco = (ctx.get("eco") or "")
    jimok = (ctx.get("jimok") or "")
    sun = ctx.get("sun") or 0

    score = 80
    flags = []

    try:
        sunf = float(sun)
        if sunf < 3.0:
            score -= 15
            flags.append("일사량 낮음")
        elif sunf < 3.4:
            score -= 5
    except Exception:
        pass

    if "보전" in zoning or "제한" in zoning:
        score -= 15
        flags.append("용도지역 제한 가능성")

    if "1" in eco or "I" in eco:
        score -= 20
        flags.append("생태자연도 1등급 가능성")

    if jimok and ("임야" in jimok or "대지" in jimok):
        # not necessarily bad; keep neutral
        pass

    score = max(0, min(100, score))
    grade = "A" if score >= 85 else ("B" if score >= 70 else ("C" if score >= 55 else "D"))
    return {"score": score, "grade": grade, "risk_flags": flags}


def estimate_land_price(address: str):
    # lightweight placeholder; you can connect to real land-price API later.
    if not address:
        return "확인불가"
    return "확인불가 (공시지가 API 미연동)"


def ask_gemini(prompt: str) -> str:
    if not (genai and GEMINI_API_KEY):
        return "AI 분석 지연"
    try:
        model = genai.GenerativeModel("gemini-1.5-flash")
        resp = model.generate_content(prompt)
        return (resp.text or "").strip() or "AI 분석 지연"
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return "AI 분석 지연"


@app.route("/api/analyze/comprehensive", methods=["POST"])
def analyze_site():
    payload = request.get_json(silent=True) or {}
    lat = payload.get("lat")
    lng = payload.get("lng")
    addr = payload.get("address", "주소 미상") or "주소 미상"
    if lat is None or lng is None:
        return jsonify({"status": "ERROR", "msg": "Missing coordinates"}), 400

    sun = get_solar_irradiance(lat, lng)
    zoning = fetch_vworld_info("LT_C_UQ111", lat, lng) or "확인불가"
    eco = fetch_vworld_info("LT_C_WISNAT", lat, lng) or "등급외"
    jimok = fetch_vworld_info("LP_PA_CBND_BUBUN", lat, lng) or "미확인"

    ai_score = calculate_ai_score({"zoning": zoning, "sun": sun, "eco": eco, "jimok": jimok})
    price = estimate_land_price(addr)

    # kepco capacity placeholder
    kepco = "데이터 없음 (한전ON 확인)"

    # ai comment (optional)
    local = addr.split(" ")[0] if addr else ""
    comment = ask_gemini(
        f"다음 대상지의 태양광 사업성을 간단히 평가해줘.\n"
        f"- 주소: {addr}\n"
        f"- 일사량(추정): {sun}\n"
        f"- 용도지역: {zoning}\n"
        f"- 생태자연도: {eco}\n"
        f"- 지목/지번: {jimok}\n"
        f"리스크 포인트와 체크리스트를 5개 이내로."
    )

    env_assessment = {
        "zoning": zoning,
        "eco": eco,
        "jimok": jimok,
        "risk_flags": ai_score.get("risk_flags", []),
    }

    return jsonify({
        "status": "OK",
        "env_assessment": env_assessment,
        "kepco_capacity": kepco,
        "sun_hours": sun,
        "ai_comment": comment,
        "ai_score": ai_score,
        "price_estimate": price,
        "links": {
            "elis": f"https://www.elis.go.kr/search/normSearch?searchType=ALL&searchKeyword={local}+태양광",
            "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
            "kepco": "https://online.kepco.co.kr/",
            "neins": "https://webgis.neins.go.kr/map.do",
            "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?"
        }
    })


# ---------------------------------------------------------
# Run
# ---------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
