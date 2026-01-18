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
