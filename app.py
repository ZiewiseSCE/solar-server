# -*- coding: utf-8 -*-
"""
SCEnergy Backend (Cloudtype friendly)
- Session 기반 인증 (localStorage에 유저/비번 저장하지 않음)
- Admin: 유저 등록/목록/삭제
- Analyze: 종합 분석 API (로그인 필요)
- CORS + 쿠키(세션) 크로스 도메인 전송 설정
"""
import os, json, datetime, logging
from pathlib import Path

import requests
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from werkzeug.security import check_password_hash

# optional (설치되어 있으면 rate limit 적용)
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:  # pragma: no cover
    Limiter = None
    get_remote_address = None

# optional Gemini
try:
    import google.generativeai as genai
except Exception:  # pragma: no cover
    genai = None

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scenergy")

app = Flask(__name__)

# -----------------------------------------------------------------------------
# Environment variables (Cloudtype "Environment variables"에 넣으세요)
# -----------------------------------------------------------------------------
VWORLD_KEY = os.getenv("VWORLD_KEY", "")
KEPCO_KEY = os.getenv("KEPCO_KEY", "")
LAW_API_ID = os.getenv("LAW_API_ID", "")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

# 관리자 계정(아이디/비번은 서버에만 존재)
ADMIN_ID = os.getenv("ADMIN_ID", "admin")
ADMIN_PW_HASH = os.getenv("ADMIN_PW_HASH", "")  # werkzeug generate_password_hash 결과 전체 문자열

# 세션 키(반드시 랜덤 긴 값)
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "")
if not FLASK_SECRET_KEY:
    # 개발 편의용(운영에서는 반드시 환경변수로 넣으세요)
    FLASK_SECRET_KEY = "DEV-ONLY-CHANGE-ME-VERY-LONG"
    logger.warning("FLASK_SECRET_KEY is not set. Using DEV fallback (NOT recommended).")
app.secret_key = FLASK_SECRET_KEY

# 프론트 도메인(여러개 가능, 콤마로 구분)
# 예: https://your-frontend.cloudtype.app,https://another-domain.com
FRONTEND_ORIGINS = [o.strip() for o in os.getenv("FRONTEND_ORIGINS", "").split(",") if o.strip()]
# 비어있으면 CORS가 애매해지므로, 개발 편의로 * 허용하되 credentials는 false 처리될 수 있음
if not FRONTEND_ORIGINS:
    logger.warning("FRONTEND_ORIGINS is empty. CORS will allow any origin (dev).")
    FRONTEND_ORIGINS = ["*"]

# -----------------------------------------------------------------------------
# CORS (쿠키 기반 세션을 쓰려면 supports_credentials=True + origin을 * 로 두면 안됨)
# -----------------------------------------------------------------------------
supports_credentials = FRONTEND_ORIGINS != ["*"]
CORS(
    app,
    resources={r"/api/*": {"origins": FRONTEND_ORIGINS}},
    supports_credentials=supports_credentials,
)

# -----------------------------------------------------------------------------
# Cookie / Session settings
# - 프론트/백엔드가 서로 다른 도메인이면 SameSite=None + Secure=True 필요(HTTPS 필수)
# -----------------------------------------------------------------------------
app.config["SESSION_COOKIE_HTTPONLY"] = True
# Cloudtype는 https 제공 → Secure True 권장
app.config["SESSION_COOKIE_SECURE"] = True
# 크로스 도메인 쿠키 전송 위해 None
app.config["SESSION_COOKIE_SAMESITE"] = "None"
# 세션 쿠키 경로
app.config["SESSION_COOKIE_PATH"] = "/"

# -----------------------------------------------------------------------------
# HTTP session with retry
# -----------------------------------------------------------------------------
session_http = requests.Session()
retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry)
session_http.mount("https://", adapter)
session_http.mount("http://", adapter)

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (SCEnergy Backend)",
}

# Gemini
if GEMINI_API_KEY and genai:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    if not GEMINI_API_KEY:
        logger.info("GEMINI_API_KEY not set. Gemini comment disabled.")
    if not genai:
        logger.info("google-generativeai not installed. Gemini comment disabled.")

# -----------------------------------------------------------------------------
# Simple user storage (Cloudtype 무료 플랜: DB 없이 /tmp에 json 저장)
# -----------------------------------------------------------------------------
USERS_PATH = Path(os.getenv("USERS_PATH", "/tmp/scenergy_users.json"))

def _load_users():
    if USERS_PATH.exists():
        try:
            return json.loads(USERS_PATH.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []

def _save_users(users):
    try:
        USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        USERS_PATH.write_text(json.dumps(users, ensure_ascii=False), encoding="utf-8")
    except Exception as e:
        logger.error(f"Failed to save users: {e}")

def _find_user(uid):
    users = _load_users()
    for u in users:
        if u.get("id") == uid:
            return u
    return None

def _require_login():
    return bool(session.get("uid"))

def _require_admin():
    return bool(session.get("is_admin") is True)

# -----------------------------------------------------------------------------
# Rate limiter (optional)
# -----------------------------------------------------------------------------
if Limiter and get_remote_address:
    limiter = Limiter(get_remote_address, app=app, default_limits=["600 per hour"], storage_uri="memory://")
else:
    limiter = None

# -----------------------------------------------------------------------------
# Views
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    # 백엔드에서 프론트를 함께 서빙할 때 사용(선택)
    # templates/index.html 이 없으면 404가 날 수 있음
    try:
        return render_template("index.html")
    except Exception:
        return "SCEnergy Backend Running", 200

@app.route("/health")
def health():
    return "OK", 200

# -----------------------------------------------------------------------------
# Auth APIs
# -----------------------------------------------------------------------------
@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    uid = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()
    if not uid or not pw:
        return jsonify({"status": "ERROR", "msg": "missing id/pw"}), 400

    user = _find_user(uid)
    # 저장은 평문 pw (간단 버전). 원하면 해시로 개선 가능.
    if not user or user.get("pw") != pw:
        return jsonify({"status": "ERROR", "msg": "invalid credentials"}), 401

    session["uid"] = uid
    session["is_admin"] = False
    return jsonify({"status": "OK", "user": {"id": uid}}), 200

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"status": "OK"}), 200

@app.route("/api/auth/me", methods=["GET"])
def api_me():
    if not _require_login():
        return jsonify({"status": "NOAUTH"}), 200
    return jsonify({"status": "OK", "user": {"id": session.get("uid"), "is_admin": bool(session.get("is_admin"))}}), 200

# -----------------------------------------------------------------------------
# Admin APIs
# -----------------------------------------------------------------------------
@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    if not ADMIN_PW_HASH:
        return jsonify({"status": "ERROR", "msg": "ADMIN_PW_HASH not set"}), 500

    data = request.get_json(silent=True) or {}
    admin_id = (data.get("id") or ADMIN_ID).strip()
    pw = (data.get("pw") or "").strip()

    if admin_id != ADMIN_ID:
        return jsonify({"status": "ERROR", "msg": "invalid admin id"}), 401
    if not check_password_hash(ADMIN_PW_HASH, pw):
        return jsonify({"status": "ERROR", "msg": "invalid admin password"}), 401

    session["uid"] = ADMIN_ID
    session["is_admin"] = True
    return jsonify({"status": "OK", "admin": {"id": ADMIN_ID}}), 200

@app.route("/api/admin/users", methods=["GET"])
def admin_list_users():
    if not _require_admin():
        return jsonify({"status": "NOAUTH"}), 200
    users = _load_users()
    # pw는 내려주지 않음(프론트에서 목록만)
    safe = [{"id": u.get("id", ""), "created_at": u.get("created_at")} for u in users]
    return jsonify({"status": "OK", "users": safe, "count": len(safe)}), 200

@app.route("/api/admin/users", methods=["POST"])
def admin_add_user():
    if not _require_admin():
        return jsonify({"status": "NOAUTH"}), 200

    data = request.get_json(silent=True) or {}
    uid = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()
    if not uid or not pw:
        return jsonify({"status": "ERROR", "msg": "missing id/pw"}), 400
    if uid == ADMIN_ID:
        return jsonify({"status": "ERROR", "msg": "reserved id"}), 400

    users = _load_users()
    if any(u.get("id") == uid for u in users):
        return jsonify({"status": "ERROR", "msg": "already exists"}), 409

    users.append({"id": uid, "pw": pw, "created_at": datetime.datetime.utcnow().isoformat()})
    _save_users(users)
    return jsonify({"status": "OK"}), 200

@app.route("/api/admin/users/<uid>", methods=["DELETE"])
def admin_delete_user(uid):
    if not _require_admin():
        return jsonify({"status": "NOAUTH"}), 200
    uid = (uid or "").strip()
    users = _load_users()
    new_users = [u for u in users if u.get("id") != uid]
    _save_users(new_users)
    return jsonify({"status": "OK", "count": len(new_users)}), 200

# -----------------------------------------------------------------------------
# Data collection helpers
# -----------------------------------------------------------------------------
def get_solar_irradiance(lat, lng):
    """Open-Meteo archive: 평균 일사량(시간/일) 추정"""
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
        resp = requests.get(url, params=params, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            daily = data.get("daily", {}).get("shortwave_radiation_sum", [])
            valid = [x for x in daily if x is not None]
            if valid:
                # kWh/m2/day -> peak-sun-hours(대략) 환산 계수
                return round((sum(valid) / len(valid)) * 0.2778, 2)
    except Exception as e:
        logger.warning(f"Solar API error: {e}")
    return None

def fetch_vworld_info(layer, lat, lng):
    """VWorld GetFeature (bbox small)"""
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
        "format": "json",
    }
    try:
        resp = session_http.get(url, params=params, headers=COMMON_HEADERS, timeout=8, verify=False)
        data = resp.json()
        if data.get("response", {}).get("status") == "OK":
            features = data["response"]["result"]["featureCollection"]["features"]
            if not features:
                return None
            props = features[0].get("properties", {})
            if layer == "LT_C_UQ111":  # 용도지역
                return props.get("MNUM_NM")
            if layer == "LT_C_WISNAT":  # 생태
                return props.get("GRD_NM")
            if layer == "LP_PA_CBND_BUBUN":  # 지목
                return props.get("JIMOK", "미확인")
            return "OK"
    except Exception as e:
        logger.warning(f"VWorld error ({layer}): {e}")
    return None

def calculate_ai_score(context):
    """보수적 규제 중심 스코어 + 신뢰도(confidence)"""
    score = 50
    reasons, risks = [], []

    # confidence
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
        score -= 20; risks.append("임야(산지전용)")
    elif ("전" in jimok) or ("답" in jimok):
        score += 5; reasons.append("농지(전/답)")
    elif ("잡" in jimok) or ("대" in jimok):
        score += 15; reasons.append("잡종지/대지")

    sun = context.get("sun") or 3.6
    if sun >= 4.0:
        score += 15; reasons.append(f"일사량 우수({sun}h)")
    elif sun < 3.2:
        score -= 15; risks.append(f"일사량 부족({sun}h)")

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
    addr = addr or ""
    base_price = 30
    if "경기" in addr: base_price = 85
    elif "충청" in addr: base_price = 45
    elif "강원" in addr: base_price = 35
    elif "전라" in addr or "경상" in addr: base_price = 28
    return f"약 {int(base_price*0.7)}~{int(base_price*1.3)}만원/평"

def ask_gemini(address, zoning, jimok, eco, sun):
    if not (GEMINI_API_KEY and genai):
        return "AI 분석 비활성"
    try:
        model = genai.GenerativeModel("gemini-pro")
        prompt = f"""
태양광 발전 사업 부지 분석가로서 다음 토지의 장점과 리스크를 3줄로 요약해 주세요.
점수나 등급을 언급하지 말고, 규제와 수익성 관점에서만 평가하세요.

주소: {address}
용도지역: {zoning}
지목: {jimok}
생태자연도: {eco}
일사량: {sun} 시간/일
"""
        r = model.generate_content(prompt)
        return getattr(r, "text", "") or "AI 응답 없음"
    except Exception as e:
        logger.error(f"Gemini error: {e}")
        return "AI 분석 지연"

# -----------------------------------------------------------------------------
# Analyze API (로그인 필요)
# -----------------------------------------------------------------------------
@app.route("/api/analyze/comprehensive", methods=["POST"])
def analyze_comprehensive():
    if not _require_login():
        return jsonify({"status": "NOAUTH"}), 200

    data = request.get_json(silent=True) or {}
    lat = data.get("lat")
    lng = data.get("lng")
    addr = data.get("address", "주소 미상")

    if lat is None or lng is None:
        return jsonify({"status": "ERROR", "msg": "missing lat/lng"}), 400

    sun = get_solar_irradiance(lat, lng)
    zoning = fetch_vworld_info("LT_C_UQ111", lat, lng) or "확인불가"
    eco = fetch_vworld_info("LT_C_WISNAT", lat, lng) or "등급외"
    jimok = fetch_vworld_info("LP_PA_CBND_BUBUN", lat, lng) or "미확인"

    ai_score = calculate_ai_score({"zoning": zoning, "sun": sun, "eco": eco, "jimok": jimok})
    price = estimate_land_price(addr)
    comment = ask_gemini(addr, zoning, jimok, eco, sun or 3.6)

    env = "대상 아님"
    if "보전" in zoning or "농림" in zoning:
        env = "검토 필요"

    local = addr.split(" ")[1] if isinstance(addr, str) and len(addr.split(" ")) > 1 else ""

    return jsonify({
        "status": "OK",
        "address": addr,
        "zoning": zoning,
        "jimok": jimok,
        "eco_grade": eco,
        "env_assessment": env,
        "kepco_capacity": "데이터 없음 (한전ON 확인)",
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
    }), 200

# -----------------------------------------------------------------------------
# Convenience: seed a default user (운영에서는 admin이 등록)
# -----------------------------------------------------------------------------
@app.route("/api/admin/seed_default_user", methods=["POST"])
def seed_default_user():
    """처음 세팅할 때만 쓰세요. admin 로그인 후 호출 권장."""
    if not _require_admin():
        return jsonify({"status": "NOAUTH"}), 200
    data = request.get_json(silent=True) or {}
    uid = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()
    if not uid or not pw:
        return jsonify({"status": "ERROR", "msg": "missing id/pw"}), 400
    users = _load_users()
    if any(u.get("id") == uid for u in users):
        return jsonify({"status": "OK", "msg": "already exists"}), 200
    users.append({"id": uid, "pw": pw, "created_at": datetime.datetime.utcnow().isoformat()})
    _save_users(users)
    return jsonify({"status": "OK"}), 200

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    # Cloudtype에서 gunicorn으로 돌리면 여기 실행 안 됨
    app.run(host="0.0.0.0", port=port)
