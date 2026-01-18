# -*- coding: utf-8 -*-
import os
import requests
import sys
import json
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import datetime
# -*- coding: utf-8 -*-
import os
import requests
import sys
import json
import datetime
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import google.generativeai as genai

# SSL 경고 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# CORS: 모든 도메인 허용
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------
# 1. 설정 (환경변수에서 가져오기)
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")
# [중요] Gemini API 키 (Cloudtype 환경변수에 설정 필요)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyAp-VUCMqmiM5gRNjTMWkF07JJ1IpwOD3o") 

# 배포된 Cloudtype 주소 (프론트엔드에서의 요청 허용을 위해 참조용으로 사용)
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

# Gemini 설정
if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

# ---------------------------------------------------------
# 2. 라우트
# ---------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return "OK", 200

# [상세 리포트 페이지 렌더링]
@app.route('/report', methods=['POST'])
def report_page():
    data = request.form.to_dict()
    try:
        if 'finance' in data: data['finance'] = json.loads(data['finance'])
        if 'ai_analysis' in data: data['ai_analysis'] = json.loads(data['ai_analysis'])
    except: pass
    return render_template('report.html', data=data)

# ---------------------------------------------------------
# 3. 데이터 수집 함수들
# ---------------------------------------------------------
def get_solar_irradiance(lat, lng):
    """Open-Meteo API를 통해 지난 1년간의 평균 일사량 조회"""
    try:
        url = "https://archive-api.open-meteo.com/v1/archive"
        end_date = datetime.date.today() - datetime.timedelta(days=7)
        start_date = end_date - datetime.timedelta(days=365)
        
        params = {
            "latitude": lat,
            "longitude": lng,
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "daily": "shortwave_radiation_sum", # 단위: MJ/m²
            "timezone": "auto"
        }
        
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            daily_radiation = data.get('daily', {}).get('shortwave_radiation_sum', [])
            valid_data = [x for x in daily_radiation if x is not None]
            
            if valid_data:
                avg_mj = sum(valid_data) / len(valid_data)
                # MJ/m² -> kWh/m² 변환 (1 MJ ≈ 0.2778 kWh) -> 일평균 발전시간으로 환산
                avg_kwh = avg_mj * 0.2778
                return round(avg_kwh, 2)
    except Exception as e:
        print(f"[Solar API Error] {e}", file=sys.stderr)
    
    return 3.6 # 실패 시 기본값 (한국 평균)

def fetch_vworld_info(layer, lat, lng):
    """V-World 데이터 API를 통해 지점 정보 조회"""
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
            
            if layer == "LT_C_UQ111": return props.get('MNUM_NM') # 용도지역
            if layer == "LT_C_WISNAT": return props.get('GRD_NM') # 생태자연도
            if layer == "LP_PA_CBND_BUBUN": return props.get('JIMOK', '미확인') # 지목 (지적도)
            
            return "정보 있음"
    except: pass
    return None

def fetch_kepco_capacity(addr):
    """한전 API 연계 용량 조회 (모의 로직 포함)"""
    try:
        # V-World로 행정구역 코드 조회 (법정동/리)
        v_url = "https://api.vworld.kr/req/address"
        v_params = {
            "service": "address", "request": "getcoord", "version": "2.0", 
            "crs": "epsg:4326", "address": addr, "refine": "true", 
            "simple": "false", "type": "PARCEL", "key": VWORLD_KEY, 
            "domain": MY_DOMAIN_URL, "format": "json"
        }
        v_resp = session.get(v_url, params=v_params, headers=COMMON_HEADERS, timeout=3, verify=False)
        v_data = v_resp.json()
        
        if v_data['response']['status'] == 'OK':
            st = v_data['response']['refined']['structure']
            
            # 한전 API 호출 준비
            k_url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
            lidong = st.get('level4L') or st.get('level4A', '')
            jibun = f"{st.get('mainNum','')}-{st.get('subNum','')}" if st.get('subNum')!='0' else st.get('mainNum','')
            
            k_params = {"apiKey": KEPCO_KEY, "returnType": "json", "addrLidong": lidong, "addrJibun": jibun}
            k_resp = requests.get(k_url, params=k_params, timeout=5)
            
            if k_resp.status_code == 200:
                d = k_resp.json()
                if "data" in d and len(d["data"]) > 0:
                    return d["data"][0] # 데이터 있으면 반환
    except: pass
    return None

def ask_gemini(context):
    """Gemini AI에게 종합 분석 요청"""
    if not GEMINI_API_KEY: return "AI 분석 키가 설정되지 않아 분석할 수 없습니다."
    
    try:
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"""
        당신은 태양광 발전 사업 인허가 전문 컨설턴트입니다. 
        아래 토지 정보를 바탕으로 사업성 및 규제 분석을 **3줄 요약**으로 명확하게 작성해주세요.

        [분석 대상 정보]
        - 주소: {context['address']}
        - 용도지역: {context['zoning']}
        - 지목: {context['jimok']}
        - 생태자연도: {context['eco']}
        - 평균 일사량: {context['sun']} 시간/일

        [요청사항]
        1. 해당 용도지역과 지목에서 태양광 설치 가능성 (상/중/하) 및 난이도 평가
        2. 예상되는 주요 규제 (이격거리, 개발행위허가 등) 언급
        3. 종합적인 투자 의견 (추천/보류/비추천)
        """
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"AI 분석 중 오류 발생: {str(e)}"

# ---------------------------------------------------------
# 4. 종합 분석 API (핵심 엔드포인트)
# ---------------------------------------------------------
@app.route('/api/analyze/comprehensive')
def analyze_site():
    lat = request.args.get('lat')
    lng = request.args.get('lng')
    addr = request.args.get('address', '주소 미상')

    if not lat or not lng: return jsonify({"status": "ERROR"}), 200

    # 1. 일사량 데이터 수집
    sun_hours = get_solar_irradiance(lat, lng)
    
    # 2. V-World 데이터 수집
    zoning = fetch_vworld_info("LT_C_UQ111", lat, lng) or "확인불가"
    eco = fetch_vworld_info("LT_C_WISNAT", lat, lng) or "등급외"
    jimok = fetch_vworld_info("LP_PA_CBND_BUBUN", lat, lng) or "미확인"
    
    # 3. 한전 선로 용량 확인
    kepco_data = fetch_kepco_capacity(addr)
    kepco_msg = "데이터 없음 (한전ON 확인 필요)"
    if kepco_data:
        kepco_msg = f"변전소: {kepco_data.get('substNm','-')} / DL여유: {kepco_data.get('vol3','-')}"

    # 4. 환경영향평가 대상 약식 검토
    env_check = "대상 아님 (소규모)"
    if "보전" in zoning or "농림" in zoning: 
        env_check = "검토 필요 (규제 지역 가능성)"

    # 5. Gemini AI 분석 요청
    ai_context = {
        "address": addr, "zoning": zoning, "jimok": jimok, "eco": eco, "sun": sun_hours
    }
    ai_comment = ask_gemini(ai_context)

    # 6. 스마트 링크 생성 (지자체명 추출)
    region_name = addr.split(' ')[0] if addr else "" 
    local_name = addr.split(' ')[1] if len(addr.split(' ')) > 1 else ""
    
    return jsonify({
        "status": "OK",
        "address": addr,
        "zoning": zoning,
        "jimok": jimok,
        "eco_grade": eco,
        "env_assessment": env_check,
        "kepco_capacity": kepco_msg,
        "sun_hours": sun_hours,
        "ai_comment": ai_comment,
        "messages": [
            f"📌 용도지역: {zoning} / 지목: {jimok}",
            f"🌿 생태등급: {eco}",
            f"☀️ 평균 발전시간: {sun_hours}시간/일 (Open-Meteo)",
            f"⚡ 한전 선로: {kepco_msg}"
        ],
        "links": { 
            "elis": f"https://www.elis.go.kr/search/normSearch?searchType=ALL&searchKeyword={local_name}+태양광",
            "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
            "kepco": "https://online.kepco.co.kr/",
            "neins": "https://webgis.neins.go.kr/map.do",
            "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?"
        }
    })

# Proxy API (프론트엔드 JSONP 사용 시에는 사용되지 않으나, 백업용으로 유지)
@app.route('/api/vworld/address')
def proxy_address():
    # V-World 차단 시 프론트엔드 JSONP로 우회하므로 여기는 에러 반환해도 무방
    return jsonify({"status": "VWORLD_BLOCK", "message": "Use JSONP"}), 200

@app.route('/api/vworld/data')
def proxy_data():
    return jsonify({"status": "VWORLD_BLOCK", "message": "Use JSONP"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
# SSL 경고 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# CORS 허용
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------
# 설정
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")
# Cloudtype 주소 (사용자 환경에 맞게 수정됨)
MY_DOMAIN_URL = "https://port-0-solar-server-mkiol9jsc308f567.sel3.cloudtype.app"

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

# ---------------------------------------------------------
# 라우트
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
    except: pass
    return render_template('report.html', data=data)

# ---------------------------------------------------------
# [핵심] 일사량 분석 (Open-Meteo API)
# ---------------------------------------------------------
def get_solar_irradiance(lat, lng):
    try:
        # 지난 1년간의 데이터 요청
        url = "https://archive-api.open-meteo.com/v1/archive"
        end_date = datetime.date.today() - datetime.timedelta(days=7)
        start_date = end_date - datetime.timedelta(days=365)
        
        params = {
            "latitude": lat,
            "longitude": lng,
            "start_date": start_date.strftime("%Y-%m-%d"),
            "end_date": end_date.strftime("%Y-%m-%d"),
            "daily": "shortwave_radiation_sum", # MJ/m²
            "timezone": "auto"
        }
        
        resp = requests.get(url, params=params, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            daily_radiation = data.get('daily', {}).get('shortwave_radiation_sum', [])
            # null 값 제거 및 평균 계산
            valid_data = [x for x in daily_radiation if x is not None]
            if valid_data:
                avg_mj = sum(valid_data) / len(valid_data)
                # MJ/m² -> kWh/m² 변환 (1 MJ = 0.2778 kWh)
                avg_kwh = avg_mj * 0.2778
                return round(avg_kwh, 2) # 평균 발전시간 (예: 3.6)
    except Exception as e:
        print(f"[Solar API Error] {e}", file=sys.stderr)
    
    return 3.6 # 실패 시 대한민국 평균값 반환

# ---------------------------------------------------------
# V-World 데이터 조회
# ---------------------------------------------------------
def fetch_vworld_info(layer, lat, lng):
    url = "https://api.vworld.kr/req/data"
    # 작은 버퍼를 주어 점 검색 시 누락 방지
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
            # 레이어별 리턴 필드 처리
            if layer == "LT_C_UQ111": return props.get('MNUM_NM') # 용도지역
            if layer == "LT_C_WISNAT": return props.get('GRD_NM') # 생태자연도
            return "정보 있음"
    except: pass
    return None

# ---------------------------------------------------------
# 종합 분석 API
# ---------------------------------------------------------
@app.route('/api/analyze/comprehensive')
def analyze_site():
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        addr = request.args.get('address', '')
        
        if not lat or not lng: return jsonify({"status": "ERROR"}), 200

        # 1. 일사량 (실제 데이터 조회)
        sun_hours = get_solar_irradiance(lat, lng)
        
        # 2. 용도지역 (V-World)
        zoning = fetch_vworld_info("LT_C_UQ111", lat, lng) or "확인불가 (V-World)"
        
        # 3. 생태자연도 (V-World)
        eco = fetch_vworld_info("LT_C_WISNAT", lat, lng) or "등급외 (안전)"
        
        # 4. 환경영향평가 대상 여부 (간이 알고리즘)
        env_check = "대상 아님 (소규모)"
        if "보전" in zoning: env_check = "검토 필요 (보전관리지역)"
        
        # 5. 한전 정보 (주소 기반 추정)
        kepco_cap = "정보 없음"
        if addr:
            # 실시간 한전 API는 키가 있어야 함 (여기선 모의 로직)
            # 실제로는 addr을 파싱해 변전소 매칭
            pass
            
        # 6. 스마트 링크 생성
        region_name = addr.split(' ')[0] if addr else "" # 시/도
        local_name = addr.split(' ')[1] if len(addr.split(' ')) > 1 else "" # 시/군/구
        
        return jsonify({
            "status": "OK",
            "address": addr,
            "zoning": zoning,
            "eco_grade": eco,
            "env_assessment": env_check,
            "kepco_capacity": "한전ON 확인 필요",
            "sun_hours": sun_hours, # [중요] 계산된 일사량
            "messages": [
                f"📌 용도지역: {zoning}",
                f"🌿 생태등급: {eco}",
                f"☀️ 평균 발전시간: {sun_hours}시간/일",
                f"⚠️ 환경영향평가: {env_check}"
            ],
            "links": { 
                "elis": f"https://www.elis.go.kr/search/normSearch?searchType=ALL&searchKeyword={local_name}+태양광",
                "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
                "kepco": "https://online.kepco.co.kr/",
                "neins": "https://webgis.neins.go.kr/map.do",
                "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?"
            }
        })

    except Exception as e:
        print(f"[Analyze Error] {e}", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": str(e)}), 200

# Proxy APIs
@app.route('/api/vworld/address')
def proxy_address():
    # (기존 V-World 주소 검색 로직 유지)
    return jsonify({"status": "VWORLD_ERROR"}), 200 # 비상모드는 프론트엔드 JSONP가 처리함

@app.route('/api/vworld/data')
def proxy_data():
    # (기존 데이터 조회 로직 유지)
    return jsonify({"status": "VWORLD_ERROR"}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

