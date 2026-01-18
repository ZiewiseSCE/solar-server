# -*- coding: utf-8 -*-
import os
import requests
import sys
import json
import datetime
import logging
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import google.generativeai as genai

# SSL 경고 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 로깅 설정 (운영 환경 필수)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
# CORS: 모든 도메인 허용
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------
# 1. 설정 (환경변수 우선)
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyAp-VUCMqmiM5gRNjTMWkF07JJ1IpwOD3o") 

MY_DOMAIN_URL = os.environ.get("MY_DOMAIN_URL", "https://solar-server-jszy.onrender.com")

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

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)
else:
    logger.warning("GEMINI_API_KEY is not set. AI features will be disabled.")

# ---------------------------------------------------------
# 2. 라우트
# ---------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return "OK", 200

@app.route('/report', methods=['POST'])
def report_page():
    data = request.form.to_dict()
    try:
        if 'finance' in data: data['finance'] = json.loads(data['finance'])
        if 'ai_analysis' in data: data['ai_analysis'] = json.loads(data['ai_analysis'])
    except Exception as e:
        logger.error(f"Report parsing error: {e}")
    return render_template('report.html', data=data)

# ---------------------------------------------------------
# 3. 데이터 수집 함수들
# ---------------------------------------------------------
def get_solar_irradiance(lat, lng):
    """Open-Meteo API: 일사량 조회"""
    try:
        url = "https://archive-api.open-meteo.com/v1/archive"
        end_date = datetime.date.today() - datetime.timedelta(days=7)
        start_date = end_date - datetime.timedelta(days=365)
        
        params = {
            "latitude": lat, "longitude": lng,
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "daily": "shortwave_radiation_sum",
            "timezone": "auto"
        }
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            daily = data.get('daily', {}).get('shortwave_radiation_sum', [])
            valid = [x for x in daily if x is not None]
            if valid:
                return round((sum(valid) / len(valid)) * 0.2778, 2)
    except Exception as e:
        logger.warning(f"Solar API Error: {e}")
    return None # 실패 시 None 반환 (신뢰도 계산용)

def fetch_vworld_info(layer, lat, lng):
    """V-World API: 레이어 정보 조회"""
    url = "https://api.vworld.kr/req/data"
    delta = 0.0001
    bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
    params = {
        "service": "data", "request": "GetFeature", "data": layer,
        "key": VWORLD_KEY, "geomFilter": f"BOX({bbox})", "size": "1",
        "domain": MY_DOMAIN_URL, "format": "json"
    }
    try:
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        data = resp.json()
        if data['response']['status'] == 'OK':
            props = data['response']['result']['featureCollection']['features'][0]['properties']
            if layer == "LT_C_UQ111": return props.get('MNUM_NM')
            if layer == "LT_C_WISNAT": return props.get('GRD_NM')
            if layer == "LP_PA_CBND_BUBUN": return props.get('JIMOK', '미확인')
            return "정보 있음"
    except Exception as e:
        logger.warning(f"VWorld Error ({layer}): {e}")
    return None

def calculate_ai_score(context):
    """
    [서버 사이드 AI 엔진]
    규제 중심의 보수적 평가 + 데이터 신뢰도(Confidence) 계산
    """
    score = 50
    reasons = []
    risks = []
    
    # 1. 신뢰도 계산 (Confidence)
    required_fields = ['zoning', 'jimok', 'eco', 'sun']
    valid_count = 0
    for field in required_fields:
        val = context.get(field)
        if val and val not in ["확인불가", "미확인", "등급외", None]:
            valid_count += 1
    confidence = round((valid_count / len(required_fields)) * 100)

    # 2. 용도지역 평가
    zoning = context.get('zoning', '')
    if "계획관리" in zoning:
        score += 25
        reasons.append("계획관리지역: 인허가 최적")
    elif "생산관리" in zoning:
        score += 15
        reasons.append("생산관리지역: 개발 가능성 높음")
    elif "농림" in zoning:
        score -= 20
        risks.append("농림지역: 농지법 저촉 가능성")
    elif "보전" in zoning:
        score -= 30
        risks.append("보전지역: 개발행위 제한 매우 높음")
        
    # 3. 지목(Jimok) 평가 - [신규 반영]
    jimok = context.get('jimok', '')
    if '임' in jimok: # 임야
        score -= 20
        risks.append("임야: 산지전용허가 및 경사도 주의 필요")
    elif '전' in jimok or '답' in jimok:
        score += 5
        reasons.append("농지: 개발행위 비교적 용이 (농지전용부담금 고려)")
    elif '잡' in jimok or '대' in jimok: # 잡종지, 대지
        score += 15
        reasons.append("잡종지/대지: 개발 용이성 높음")

    # 4. 일사량 평가
    sun = context.get('sun') or 3.6 # Fallback for scoring
    if sun >= 4.0:
        score += 15
        reasons.append(f"일사량 매우 우수 ({sun}h)")
    elif sun >= 3.6:
        score += 5
    elif sun < 3.2:
        score -= 15
        risks.append(f"일사량 부족 ({sun}h)")
        
    # 5. 생태등급 평가
    eco = context.get('eco', '')
    if "1등급" in eco:
        score -= 50
        risks.append("생태자연도 1등급: 사실상 개발 불가")
    elif "2등급" in eco:
        score -= 15
        risks.append("생태자연도 2등급: 환경청 협의 필수")
    else:
        score += 10
        
    # 점수 보정 (0~100) 및 등급 산정
    score = max(0, min(100, score))
    
    if score >= 90: grade = "A+"
    elif score >= 80: grade = "A"
    elif score >= 70: grade = "B"
    elif score >= 50: grade = "C"
    elif score >= 30: grade = "D"
    else: grade = "E"
    
    return {
        "score": score,
        "grade": grade,
        "confidence": confidence,
        "reasons": reasons,
        "risk_flags": risks
    }

def estimate_land_price(addr):
    """지역별 추정 땅값 계산"""
    base_price = 30 
    if "경기" in addr: base_price = 85
    elif "충청" in addr: base_price = 45
    elif "강원" in addr: base_price = 35
    elif "전라" in addr or "경상" in addr: base_price = 28
    
    min_p = int(base_price * 0.7)
    max_p = int(base_price * 1.3)
    
    return f"약 {min_p}~{max_p}만원/평"

def ask_gemini(context):
    """
    Gemini에게 정성적 평가 요청 
    [중요] 점수를 주입하지 않고 객관적 평가만 요청하여 확증편향 방지
    """
    if not GEMINI_API_KEY: return "AI 분석 키 미설정"
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"""
        태양광 발전 사업 부지 분석가로서 다음 토지의 장점과 리스크를 3줄로 요약해 주세요.
        점수나 등급을 언급하지 말고, 규제와 수익성 관점에서만 평가하세요.

        [토지 정보]
        주소: {context['address']}
        용도지역: {context['zoning']}
        지목: {context['jimok']}
        생태자연도: {context['eco']}
        일사량: {context['sun']} 시간/일
        """
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        logger.error(f"Gemini Error: {e}")
        return "AI 분석 서비스 일시 지연"

# ---------------------------------------------------------
# 4. 종합 분석 API (POST 방식 전환)
# ---------------------------------------------------------
@app.route('/api/analyze/comprehensive', methods=['POST'])
def analyze_site():
    # POST Body에서 데이터 추출
    req_data = request.get_json()
    lat = req_data.get('lat')
    lng = req_data.get('lng')
    addr = req_data.get('address', '주소 미상')

    if not lat or not lng: return jsonify({"status": "ERROR", "msg": "Missing coordinates"}), 400

    # 1. 데이터 수집
    sun_hours = get_solar_irradiance(lat, lng)
    zoning = fetch_vworld_info("LT_C_UQ111", lat, lng) or "확인불가"
    eco = fetch_vworld_info("LT_C_WISNAT", lat, lng) or "등급외"
    jimok = fetch_vworld_info("LP_PA_CBND_BUBUN", lat, lng) or "미확인"
    
    # 2. AI 점수 계산 (서버 엔진)
    ai_score_data = calculate_ai_score({
        "zoning": zoning, "sun": sun_hours, "eco": eco, "jimok": jimok
    })
    
    # 3. 땅값 추정
    price_est = estimate_land_price(addr)

    # 4. Gemini 코멘트 (점수 주입 제외)
    gemini_context = {
        "address": addr, "zoning": zoning, "jimok": jimok, "eco": eco, "sun": sun_hours or 3.6
    }
    ai_comment = ask_gemini(gemini_context)

    # 5. 기타 정보
    kepco_msg = "데이터 없음 (한전ON 확인)"
    env_check = "대상 아님 (소규모)"
    if "보전" in zoning or "농림" in zoning: env_check = "검토 필요"

    local_name = addr.split(' ')[1] if len(addr.split(' ')) > 1 else ""

    return jsonify({
        "status": "OK",
        "address": addr,
        "zoning": zoning,
        "jimok": jimok,
        "eco_grade": eco,
        "env_assessment": env_check,
        "kepco_capacity": kepco_msg,
        "sun_hours": sun_hours, # None일 수 있음 (프론트에서 처리)
        "ai_comment": ai_comment,
        "ai_score": ai_score_data, 
        "price_estimate": price_est,
        "links": { 
            "elis": f"https://www.elis.go.kr/search/normSearch?searchType=ALL&searchKeyword={local_name}+태양광",
            "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
            "kepco": "https://online.kepco.co.kr/",
            "neins": "https://webgis.neins.go.kr/map.do",
            "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?"
        }
    })

# Proxy (GET 유지)
@app.route('/api/vworld/address')
def proxy_addr(): return jsonify({"status":"FAIL"}), 200
@app.route('/api/vworld/data')
def proxy_data(): return jsonify({"status":"FAIL"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
