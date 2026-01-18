# -*- coding: utf-8 -*-
import os
DATABASE_URL = os.environ.get('DATABASE_URL')  # optional: cloud DB connection string
import json
import datetime
import logging
import sqlite3
import requests
import urllib3

from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from werkzeug.security import generate_password_hash, check_password_hash

# Optional (AI)
try:
    import google.generativeai as genai
except Exception:
    genai = None

# Optional rate limit
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None
    get_remote_address = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------
# Logging
# ---------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenergy")

# ---------------------------------------------------------
# App
# ---------------------------------------------------------
app = Flask(__name__)

# ✅ 세션 비밀키 (Cloudtype ENV로 반드시 설정 권장)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# 세션 쿠키 옵션 (프론트/백 분리 운영 시 중요)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.environ.get("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=(os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true"),
)

# ---------------------------------------------------------
# ENV
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
MY_DOMAIN_URL = os.environ.get("MY_DOMAIN_URL", "https://port-0-solar-server-mkiol9jsc308f567.sel3.cloudtype.app")  # 백엔드 도메인(Referer/Origin 헤더용)

# ✅ 관리자 계정 (프론트에서 관리자 로그인 시 id=admin, pw=입력값으로 백엔드 로그인)
ADMIN_ID = os.environ.get("ADMIN_ID", "admin")
ADMIN_PW_HASH = os.environ.get("ADMIN_PW_HASH", "")
ADMIN_PW = os.environ.get("ADMIN_PW", "")
if (not ADMIN_PW_HASH) and ADMIN_PW:
    try:
        ADMIN_PW_HASH = generate_password_hash(ADMIN_PW)
    except Exception:
        ADMIN_PW_HASH = ""


# ✅ 사용자 DB (SQLite)
USER_DB_PATH = os.environ.get("USER_DB_PATH", "users.db")

# CORS (세션 쿠키 사용하려면 supports_credentials=True 필수)
allowed_origins_raw = os.environ.get("ALLOWED_ORIGINS", "")
allowed_origins = [o.strip() for o in allowed_origins_raw.split(",") if o.strip()]
if not allowed_origins:
    # 안전장치: 최소한 동일 도메인은 허용
    allowed_origins = [MY_DOMAIN_URL] if MY_DOMAIN_URL else ["http://localhost:5000"]

CORS(app, resources={r"/api/*": {"origins": allowed_origins}}, supports_credentials=True)

# Rate Limiter (선택)
if Limiter and get_remote_address:
    limiter = Limiter(get_remote_address, app=app, default_limits=["2000 per day", "200 per hour"], storage_uri="memory://")
else:
    limiter = None

# HTTP Session with Retry
session_http = requests.Session()
retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry)
session_http.mount("https://", adapter)
session_http.mount("http://", adapter)

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Referer": MY_DOMAIN_URL or "https://localhost/",
    "Origin": MY_DOMAIN_URL or "https://localhost/",
}

# Gemini init
if genai and GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception as e:
        logger.warning(f"Gemini init failed: {e}")

# ---------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------
def _db():
    conn = sqlite3.connect(USER_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_user_db():
    conn = _db()
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

    # ensure admin exists (in DB)
    if ADMIN_PW_HASH:
        cur.execute("SELECT id FROM users WHERE id=?", (ADMIN_ID,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (id, pw_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                (ADMIN_ID, ADMIN_PW_HASH, datetime.datetime.utcnow().isoformat()),
            )
            conn.commit()
            logger.info("Admin user inserted into DB.")
    else:
        logger.warning("ADMIN_PW_HASH is not set. Admin login will fail.")
    conn.close()

try:
    init_user_db()
except Exception as e:
    logger.exception('init_user_db failed; continuing without user DB init')


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
    return "OK", 200

@app.route("/report", methods=["POST"])
def report_page():
    data = request.form.to_dict()
    try:
        if "finance" in data:
            data["finance"] = json.loads(data["finance"])
        if "ai_analysis" in data:
            data["ai_analysis"] = json.loads(data["ai_analysis"])
    except Exception as e:
        logger.warning(f"report parse err: {e}")
    return render_template("report.html", data=data)

# ---------------------------------------------------------
# Auth API
# ---------------------------------------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    payload = request.get_json(silent=True) or {}
    user_id = (payload.get("id") or "").strip()
    pw = (payload.get("pw") or "").strip()
    if not user_id or not pw:
        return jsonify({"status": "ERROR", "msg": "Missing id/pw"}), 400

    conn = _db()
    cur = conn.cursor()
    cur.execute("SELECT id, pw_hash, role FROM users WHERE id=?", (user_id,))
    row = cur.fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "ERROR", "msg": "Invalid credentials"}), 401

    if not check_password_hash(row["pw_hash"], pw):
        return jsonify({"status": "ERROR", "msg": "Invalid credentials"}), 401

    session["user_id"] = row["id"]
    session["role"] = row["role"]

    return jsonify({"status": "OK", "user": row["id"], "role": row["role"]})

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "OK"})

@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if not session.get("user_id"):
        return jsonify({"status": "NOAUTH"}), 200
    return jsonify({"status": "OK", "user": session.get("user_id"), "role": session.get("role", "user")})

# ---------------------------------------------------------
# Admin Users API (backend-based user management)
# ---------------------------------------------------------
@app.route("/api/admin/users", methods=["GET"])
def admin_users_list():
    guard = require_admin()
    if guard: return guard

    conn = _db()
    cur = conn.cursor()
    cur.execute("SELECT id, role, created_at FROM users ORDER BY created_at DESC")
    rows = [dict(id=r["id"], role=r["role"], created_at=r["created_at"]) for r in cur.fetchall()]
    conn.close()

    # 프론트는 id만 보여주면 됨
    users = [{"id": r["id"], "role": r["role"]} for r in rows if r["id"] != ADMIN_ID]  # admin 제외(원하면 포함 가능)
    return jsonify({"status": "OK", "users": users})

@app.route("/api/admin/users", methods=["POST"])
def admin_users_create():
    guard = require_admin()
    if guard: return guard

    payload = request.get_json(silent=True) or {}
    user_id = (payload.get("id") or "").strip()
    pw = (payload.get("pw") or "").strip()

    if not user_id or not pw:
        return jsonify({"status": "ERROR", "msg": "Missing id/pw"}), 400
    if user_id.lower() == ADMIN_ID.lower():
        return jsonify({"status": "ERROR", "msg": "Cannot create admin here"}), 400

    pw_hash = generate_password_hash(pw)

    try:
        conn = _db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (id, pw_hash, role, created_at) VALUES (?, ?, 'user', ?)",
            (user_id, pw_hash, datetime.datetime.utcnow().isoformat()),
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "OK"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "ERROR", "msg": "User already exists"}), 409
    except Exception as e:
        logger.error(f"create user error: {e}")
        return jsonify({"status": "ERROR", "msg": "Server error"}), 500

@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
def admin_users_delete(user_id):
    guard = require_admin()
    if guard: return guard

    user_id = (user_id or "").strip()
    if not user_id:
        return jsonify({"status": "ERROR", "msg": "Missing user id"}), 400
    if user_id.lower() == ADMIN_ID.lower():
        return jsonify({"status": "ERROR", "msg": "Cannot delete admin"}), 400

    conn = _db()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=? AND role!='admin'", (user_id,))
    conn.commit()
    deleted = cur.rowcount
    conn.close()

    if deleted == 0:
        return jsonify({"status": "ERROR", "msg": "User not found"}), 404
    return jsonify({"status": "OK"})

# ---------------------------------------------------------
# Analysis logic (same as before, POST)
# ---------------------------------------------------------
def get_solar_irradiance(lat, lng):
    """Open-Meteo: 일사량(시간/일로 쓰는 값) 근사"""
    try:
        url = "https://archive-api.open-meteo.com/v1/archive"
        end_date = datetime.date.today() - datetime.timedelta(days=7)
        start_date = end_date - datetime.timedelta(days=365)
        params = {
            "latitude": float(lat),
            "longitude": float(lng),
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "daily": "shortwave_radiation_sum",
            "timezone": "auto",
        }
        resp = requests.get(url, params=params, timeout=6)
        if resp.status_code == 200:
            data = resp.json()
            daily = data.get("daily", {}).get("shortwave_radiation_sum", [])
            valid = [x for x in daily if x is not None]
            if valid:
                # kWh/m2/day 근사 -> '시간'처럼 쓰기 위해 스케일링(기존 로직 유지)
                return round((sum(valid) / len(valid)) * 0.2778, 2)
    except Exception as e:
        logger.warning(f"Solar API error: {e}")
    return 3.6

def fetch_vworld_info(layer, lat, lng):
    """V-World API: 레이어 정보 조회"""
    if not VWORLD_KEY:
        return None
    url = "https://api.vworld.kr/req/data"
    delta = 0.0001
    bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
    params = {
        "service": "data",
        "request": "GetFeature",
        "data": layer,
        "key": VWORLD_KEY,
        "geomFilter": f"BOX({bbox})",
        "size": "1",
        "domain": MY_DOMAIN_URL,
        "format": "json",
    }
    try:
        resp = session_http.get(url, params=params, headers=COMMON_HEADERS, timeout=6, verify=False)
        data = resp.json()
        if data.get("response", {}).get("status") == "OK":
            feats = data["response"]["result"]["featureCollection"]["features"]
            if not feats:
                return None
            props = feats[0].get("properties", {})
            if layer == "LT_C_UQ111":
                return props.get("MNUM_NM")
            if layer == "LT_C_WISNAT":
                return props.get("GRD_NM")
            if layer == "LP_PA_CBND_BUBUN":
                return props.get("JIMOK", "미확인")
            return "정보 있음"
    except Exception as e:
        logger.warning(f"VWorld Error({layer}): {e}")
    return None

def calculate_ai_score(context):
    score = 50
    reasons, risks = [], []

    required = ["zoning", "jimok", "eco", "sun"]
    valid_cnt = sum(1 for f in required if context.get(f) and context.get(f) not in ["확인불가", "미확인", "등급외", None])
    confidence = round((valid_cnt / len(required)) * 100)

    zoning = context.get("zoning", "") or ""
    if "계획관리" in zoning:
        score += 25; reasons.append("계획관리지역")
    elif "생산관리" in zoning:
        score += 15; reasons.append("생산관리지역")
    elif "농림" in zoning:
        score -= 20; risks.append("농림지역 규제")
    elif "보전" in zoning:
        score -= 30; risks.append("보전지역 규제")

    jimok = context.get("jimok", "") or ""
    if "임" in jimok:
        score -= 20; risks.append("산지전용 필요")
    elif "전" in jimok or "답" in jimok:
        score += 5; reasons.append("농지전용 가능")
    elif "잡" in jimok or "대" in jimok:
        score += 15; reasons.append("개발 용이")

    sun = context.get("sun") or 3.6
    try:
        sun = float(sun)
    except Exception:
        sun = 3.6
    if sun >= 4.0:
        score += 15
    elif sun < 3.2:
        score -= 15; risks.append("일사량 부족")

    eco = context.get("eco", "") or ""
    if "1등급" in eco:
        score -= 50; risks.append("생태 1등급")
    elif "2등급" in eco:
        score -= 15; risks.append("생태 2등급")
    else:
        score += 10

    score = max(0, min(100, score))
    if score >= 90: grade = "A+"
    elif score >= 80: grade = "A"
    elif score >= 70: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 30: grade = "D"
    else: grade = "E"

    return {"score": score, "grade": grade, "confidence": confidence, "reasons": reasons, "risk_flags": risks}

def estimate_land_price(addr):
    base_price = 30
    if "경기" in addr: base_price = 85
    elif "충청" in addr: base_price = 45
    elif "강원" in addr: base_price = 35
    elif "전라" in addr or "경상" in addr: base_price = 28
    return f"약 {int(base_price*0.7)}~{int(base_price*1.3)}만원/평"

def ask_gemini(context):
    if not (genai and GEMINI_API_KEY):
        return "AI 분석 키 미설정"
    try:
        model = genai.GenerativeModel("gemini-pro")
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

@app.route("/api/analyze/comprehensive", methods=["POST"])
def analyze_site():
    # 로그인 없이도 가능하게 유지(원하면 require_login 붙이면 됨)
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
    comment = ask_gemini({"address": addr, "zoning": zoning, "jimok": jimok, "eco": eco, "sun": sun})

    env = "대상 아님"
    if "보전" in zoning or "농림" in zoning:
        env = "검토 필요"
    kepco = "데이터 없음 (한전ON 확인)"
    local = addr.split(" ")[1] if len(addr.split(" ")) > 1 else ""

    return jsonify({
        "status": "OK",
        "address": addr,
        "zoning": zoning,
        "jimok": jimok,
        "eco_grade": eco,
        "env_assessment": env,
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
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
