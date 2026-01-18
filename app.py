# -*- coding: utf-8 -*-
import os
import requests
import sys
import json
import datetime
import logging
from functools import wraps
from flask import Flask, render_template, request, jsonify, session
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import google.generativeai as genai
from werkzeug.security import check_password_hash, generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ---------------------------------------------------------
# Flask Session (signed cookie) 설정
#  - 서버 저장소(Redis/DB) 없이도 로그인 유지 가능 (Cloudtype Free 환경에 적합)
#  - 반드시 FLASK_SECRET_KEY를 환경변수로 설정하세요 (재시작해도 동일해야 함)
# ---------------------------------------------------------
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "CHANGE-ME-IN-PROD")

# 프론트/백엔드 도메인이 다른 경우(SameSite=None) 쿠키가 HTTPS에서만 동작합니다.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
)
# ---------------------------------------------------------
# 설정
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "") 
MY_DOMAIN_URL = os.environ.get("MY_DOMAIN_URL", "https://solar-server-jszy.onrender.com")
CLIENT_TOKEN = os.environ.get("CLIENT_TOKEN", "scenergy-secret-token-2025")

allowed_origins = [MY_DOMAIN_URL, "http://localhost:5000", "http://127.0.0.1:5000"]
CORS(app, resources={r"/api/*": {"origins": allowed_origins}}, supports_credentials=True)

limiter = Limiter(
    get_remote_address, app=app, default_limits=["2000 per day", "100 per hour"], storage_uri="memory://"
)

session = requests.Session()
retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry)
session.mount("https://", adapter)
session.mount("http://", adapter)

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
    "Referer": MY_DOMAIN_URL,
    "Origin": MY_DOMAIN_URL
}

if GEMINI_API_KEY: genai.configure(api_key=GEMINI_API_KEY)

# ---------------------------------------------------------
# Auth helpers (운영 권장: 환경변수 기반 + 서버에서만 비밀번호 검증)
# ---------------------------------------------------------
def get_auth_users():
    """환경변수 기반 유저 목록 반환.
    - ADMIN_ID: 기본 admin 아이디 (기본: admin)
    - ADMIN_PW_HASH: 비밀번호 해시(권장). 없으면 개발용으로 '1234' 해시를 임시 생성.
    """
    admin_id = os.environ.get("ADMIN_ID", "admin")
    admin_pw_hash = os.environ.get("ADMIN_PW_HASH")
    if not admin_pw_hash:
        # ⚠️ 개발용 fallback. 운영에서는 반드시 ADMIN_PW_HASH를 세팅하세요.
        admin_pw_hash = generate_password_hash("1234")
    return {admin_id: admin_pw_hash}


def login_required(fn):
    """세션 기반 로그인 체크 데코레이터"""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return jsonify({"status": "UNAUTHORIZED"}), 401
        return fn(*args, **kwargs)
    return wrapper



# ---------------------------------------------------------
# 라우트
# ---------------------------------------------------------
@app.route('/')
def index(): return render_template('index.html')

@app.route('/health')
def health_check(): return "OK", 200


# ---------------------------------------------------------
# Auth API
# ---------------------------------------------------------
@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("20/minute")
def api_login():
    data = request.get_json(silent=True) or {}
    user_id = (data.get("id") or "").strip()
    pw = (data.get("pw") or "").strip()

    if not user_id or not pw:
        return jsonify({"status": "ERROR", "msg": "Missing id/pw"}), 400

    users = get_auth_users()
    pw_hash = users.get(user_id)
    if (not pw_hash) or (not check_password_hash(pw_hash, pw)):
        return jsonify({"status": "FAIL"}), 401

    session["user_id"] = user_id
    return jsonify({"status": "OK", "user": user_id})


@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    session.pop("user_id", None)
    return jsonify({"status": "OK"})


@app.route("/api/auth/me", methods=["GET"])
def api_me():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"status": "NOLOGIN"}), 200
    return jsonify({"status": "OK", "user": uid}), 200


@app.route('/report', methods=['POST'])
def report_page():
    data = request.form.to_dict()
    try:
        if 'finance' in data: data['finance'] = json.loads(data['finance'])
        if 'ai_analysis' in data: data['ai_analysis'] = json.loads(data['ai_analysis'])
    except: pass
    return render_template('report.html', data=data)

# ---------------------------------------------------------
# 분석 로직
# ---------------------------------------------------------
def get_solar_irradiance(lat, lng):
    try:
        url = "https://archive-api.open-meteo.com/v1/archive"
        end_date = datetime.date.today() - datetime.timedelta(days=7)
        start_date = end_date - datetime.timedelta(days=365)
        params = { "latitude": lat, "longitude": lng, "start_date": start_date.strftime("%Y-%m-%d"), "end_date": end_date.strftime("%Y-%m-%d"), "daily": "shortwave_radiation_sum", "timezone": "auto" }
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            daily = data.get('daily', {}).get('shortwave_radiation_sum', [])
            valid = [x for x in daily if x is not None]
            if valid: return round((sum(valid) / len(valid)) * 0.2778, 2)
    except: pass
    return 3.6

def fetch_vworld_info(layer, lat, lng):
    url = "https://api.vworld.kr/req/data"
    delta = 0.0001
    bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
    params = { "service": "data", "request": "GetFeature", "data": layer, "key": VWORLD_KEY, "geomFilter": f"BOX({bbox})", "size": "1", "domain": MY_DOMAIN_URL, "format": "json" }
    try:
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        data = resp.json()
        if data['response']['status'] == 'OK':
            props = data['response']['result']['featureCollection']['features'][0]['properties']
            if layer == "LT_C_UQ111": return props.get('MNUM_NM')
            if layer == "LT_C_WISNAT": return props.get('GRD_NM')
            if layer == "LP_PA_CBND_BUBUN": return props.get('JIMOK', '미확인')
            return "정보 있음"
    except: pass
    return None

def calculate_ai_score(context):
    score = 50
    reasons, risks = [], []
    
    # 신뢰도
    required = ['zoning', 'jimok', 'eco', 'sun']
    valid_cnt = sum(1 for f in required if context.get(f) and context.get(f) not in ["확인불가", "미확인", "등급외", None])
    confidence = round((valid_cnt / len(required)) * 100)

    # 평가 로직
    zoning = context.get('zoning', '')
    if "계획관리" in zoning: score += 25; reasons.append("계획관리지역")
    elif "생산관리" in zoning: score += 15; reasons.append("생산관리지역")
    elif "농림" in zoning: score -= 20; risks.append("농림지역 규제")
    elif "보전" in zoning: score -= 30; risks.append("보전지역 규제")
        
    jimok = context.get('jimok', '')
    if '임' in jimok: score -= 20; risks.append("산지전용 필요")
    elif '전' in jimok or '답' in jimok: score += 5; reasons.append("농지전용 가능")
    elif '잡' in jimok or '대' in jimok: score += 15; reasons.append("개발 용이")

    sun = context.get('sun') or 3.6
    if sun >= 4.0: score += 15
    elif sun < 3.2: score -= 15; risks.append("일사량 부족")
        
    eco = context.get('eco', '')
    if "1등급" in eco: score -= 50; risks.append("생태 1등급")
    elif "2등급" in eco: score -= 15; risks.append("생태 2등급")
    else: score += 10
        
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
    if not GEMINI_API_KEY: return "AI 분석 키 미설정"
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"태양광 부지 분석. 주소:{context['address']}, 용도:{context['zoning']}, 지목:{context['jimok']}, 생태:{context['eco']}, 일사량:{context['sun']}h. 리스크/장점 3줄 요약."
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(str(e))
        return "AI 분석 지연"

@app.route('/api/analyze/comprehensive', methods=['POST'])
@limiter.limit("10/minute")
@login_required
def analyze_site():

    req = request.get_json()
    lat, lng, addr = req.get('lat'), req.get('lng'), req.get('address', '주소 미상')
    if not lat or not lng: return jsonify({"status": "ERROR"}), 400

    sun = get_solar_irradiance(lat, lng)
    zoning = fetch_vworld_info("LT_C_UQ111", lat, lng) or "확인불가"
    eco = fetch_vworld_info("LT_C_WISNAT", lat, lng) or "등급외"
    jimok = fetch_vworld_info("LP_PA_CBND_BUBUN", lat, lng) or "미확인"
    
    ai_score = calculate_ai_score({"zoning": zoning, "sun": sun, "eco": eco, "jimok": jimok})
    price = estimate_land_price(addr)
    
    gemini_ctx = {"address": addr, "zoning": zoning, "jimok": jimok, "eco": eco, "sun": sun or 3.6}
    comment = ask_gemini(gemini_ctx)

    kepco = "데이터 없음 (한전ON 확인)"
    env = "대상 아님"
    if "보전" in zoning or "농림" in zoning: env = "검토 필요"
    local = addr.split(' ')[1] if len(addr.split(' ')) > 1 else ""

    return jsonify({
        "status": "OK",
        "address": addr,
        "zoning": zoning, "jimok": jimok, "eco_grade": eco,
        "env_assessment": env, "kepco_capacity": kepco,
        "sun_hours": sun, "ai_comment": comment,
        "ai_score": ai_score, "price_estimate": price,
        "links": { 
            "elis": f"https://www.elis.go.kr/search/normSearch?searchType=ALL&searchKeyword={local}+태양광",
            "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
            "kepco": "https://online.kepco.co.kr/",
            "neins": "https://webgis.neins.go.kr/map.do",
            "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?"
        }
    })

@app.route('/api/vworld/address')
def proxy_addr(): return jsonify({"status":"FAIL"}), 200
@app.route('/api/vworld/data')
def proxy_data(): return jsonify({"status":"FAIL"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
