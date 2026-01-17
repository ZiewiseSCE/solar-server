# -*- coding: utf-8 -*-
import os
import requests
import xml.etree.ElementTree as ET
import re
import sys
import json
from flask import Flask, render_template, request, jsonify, make_response
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RetryError, Timeout
import urllib3

# SSL 경고 메시지 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# [수정] CORS 설정 강화: 모든 출처, 모든 헤더, 모든 메소드 허용
# 이렇게 해야 백엔드가 에러를 뱉어도 브라우저가 차단하지 않습니다.
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": "*"}})

# ---------------------------------------------------------
# 1. 설정 (API 키 및 도메인)
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# [중요] V-World 관리자 페이지 '서비스 URL'에 등록된 주소
MY_DOMAIN_URL = "https://solar-server-jszy.onrender.com"

# 세션 설정
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("https://", adapter)
session.mount("http://", adapter)

COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": MY_DOMAIN_URL,
    "Origin": MY_DOMAIN_URL
}

# ---------------------------------------------------------
# 2. 기본 라우트
# ---------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return "OK", 200

# ---------------------------------------------------------
# [진단용] V-World 연동 상태 확인 API
# ---------------------------------------------------------
@app.route('/api/diagnose')
def diagnose_vworld():
    url = "https://api.vworld.kr/req/address"
    params = {
        "service": "address",
        "request": "getcoord",
        "version": "2.0",
        "crs": "epsg:4326",
        "address": "서울특별시 중구 세종대로 110",
        "refine": "true",
        "simple": "false",
        "type": "road",
        "key": VWORLD_KEY,
        "domain": MY_DOMAIN_URL, 
        "format": "json"
    }
    try:
        print(f"[Diagnose] Requesting...", file=sys.stdout)
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        return jsonify({
            "status": "CHECK_COMPLETED",
            "vworld_http_status": resp.status_code,
            "response_sample": resp.text[:300],
            "sent_referer": COMMON_HEADERS["Referer"]
        })
    except Exception as e:
        return jsonify({"status": "DIAGNOSE_FAILED", "error": str(e)})

# ---------------------------------------------------------
# 3. V-World 데이터 프록시
# ---------------------------------------------------------
@app.route('/api/vworld/data')
def proxy_data():
    try:
        layer = request.args.get('data', 'LT_C_SPBD')
        geom_filter = request.args.get('geomFilter')
        
        if not geom_filter:
            return jsonify({"status": "ERROR", "message": "Missing geomFilter"}), 400

        url = "https://api.vworld.kr/req/data"
        params = {
            "service": "data",
            "request": "GetFeature",
            "data": layer,
            "key": VWORLD_KEY,
            "geomFilter": geom_filter,
            "size": "1000",
            "domain": MY_DOMAIN_URL, 
            "format": "json"
        }

        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        if resp.status_code != 200:
            print(f"[Data Error] {resp.status_code} {resp.text[:100]}", file=sys.stderr)
            # [수정] 500 에러를 내지 않고 200 OK로 에러 메시지를 보냄 (CORS 방지)
            return jsonify({
                "status": "VWORLD_ERROR", 
                "message": f"V-World Error {resp.status_code}",
                "details": resp.text
            })
            
        return jsonify(resp.json())

    except Exception as e:
        print(f"[Data Exception] {str(e)}", file=sys.stderr)
        return jsonify({"status": "SERVER_ERROR", "message": str(e)})

# ---------------------------------------------------------
# 4. V-World 주소 검색 프록시
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    try:
        query = request.args.get('address')
        if not query:
            return jsonify({"status": "ERROR", "message": "Missing address"}), 400

        print(f"[Address] Query: {query}", file=sys.stdout)

        url = "https://api.vworld.kr/req/address"
        params = {
            "service": "address",
            "request": "getcoord",
            "version": "2.0",
            "crs": "epsg:4326",
            "address": query,
            "refine": "true",
            "simple": "false",
            "type": "road",
            "key": VWORLD_KEY,
            "domain": MY_DOMAIN_URL,
            "format": "json"
        }
        
        # 1차 시도
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        # 에러 응답 처리
        if resp.status_code != 200:
            print(f"[Address Error] {resp.status_code} {resp.text[:100]}", file=sys.stderr)
            # [수정] 500 대신 200으로 반환하여 프론트엔드가 JSON을 읽게 함
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World API Error ({resp.status_code})",
                "details": resp.text[:200]
            })

        try:
            data = resp.json()
            # 검색 결과 없음 -> 지번 검색 재시도
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 print("[Address] Retry parcel...", file=sys.stdout)
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
                 if resp_p.status_code == 200:
                     try:
                         data = resp_p.json()
                     except: pass
            
            return jsonify(data)

        except ValueError:
            # HTML이나 텍스트가 와서 JSON 변환 실패 시
            print(f"[Address JSON Fail] {resp.text[:100]}", file=sys.stderr)
            return jsonify({
                "status": "PARSING_ERROR",
                "message": "Invalid JSON response from V-World",
                "raw": resp.text[:200]
            })

    except Exception as e:
        print(f"[Address Exception] {str(e)}", file=sys.stderr)
        # [수정] 절대 500 에러를 내지 않음
        return jsonify({"status": "SERVER_ERROR", "message": str(e)})

# ---------------------------------------------------------
# 5. 종합 분석 및 기타 API
# ---------------------------------------------------------
@app.route('/api/analyze/comprehensive')
def analyze_site():
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        area_size = float(request.args.get('area', 0))
        address = request.args.get('address', '')

        if not lat or not lng:
            return jsonify({"status": "ERROR", "message": "좌표 정보 누락"})

        delta = 0.0001
        bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
        
        # 1. 용도지역
        zoning_info = fetch_vworld_feature("LT_C_UQ111", bbox) 
        zoning_name = zoning_info.get('properties', {}).get('MNUM_NM', '용도지역 미확인') if zoning_info else "확인 불가"

        # 2. 생태자연도
        eco_info = fetch_vworld_feature("LT_C_WISNAT", bbox) 
        eco_grade = eco_info.get('properties', {}).get('GRD_NM', '등급 외') if eco_info else "확인 불가"
        
        # 3. 환경영향평가
        env_impact_check = "대상 아님"
        if "보전관리" in zoning_name and area_size >= 5000: env_impact_check = "✅ 대상 (5,000m² 이상)"
        elif "생산관리" in zoning_name and area_size >= 7500: env_impact_check = "✅ 대상 (7,500m² 이상)"
        elif "계획관리" in zoning_name and area_size >= 10000: env_impact_check = "✅ 대상 (10,000m² 이상)"
        elif "농림" in zoning_name and area_size >= 7500: env_impact_check = "✅ 대상 (7,500m² 이상)"
        else: env_impact_check = f"미대상 ({int(area_size)}m²)" if area_size > 0 else "면적 정보 없음"

        # 4. 한전 용량
        kepco_dl_capacity = "확인 불가"
        kepco_info = "API 키 필요"
        if address:
            kepco_result = fetch_kepco_capacity_by_address(address)
            if kepco_result:
                kepco_dl_capacity = f"{kepco_result.get('vol3', '-')} (변전소 여유: {kepco_result.get('vol1', '-')})"
                kepco_info = f"변전소: {kepco_result.get('substNm','-')}"
            else:
                kepco_info = "데이터 없음 (한전ON 확인 요망)"

        return jsonify({
            "status": "OK",
            "address": address,
            "zoning": zoning_name,
            "eco_grade": eco_grade,
            "env_assessment": env_impact_check,
            "kepco_capacity": kepco_dl_capacity,
            "messages": [
                f"📌 용도지역: {zoning_name}",
                f"🌿 생태등급: {eco_grade}",
                f"⚡ 한전 용량: {kepco_dl_capacity} / {kepco_info}",
                f"⚠️ 환경영향평가: {env_impact_check}"
            ]
        })

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

def fetch_vworld_feature(layer, bbox):
    url = "https://api.vworld.kr/req/data"
    params = {"service": "data", "request": "GetFeature", "data": layer, "key": VWORLD_KEY, "geomFilter": f"BOX({bbox})", "size": "1", "domain": MY_DOMAIN_URL, "format": "json"}
    try:
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        data = resp.json()
        if data['response']['status'] == 'OK': return data['response']['result']['featureCollection']['features'][0]
    except: pass
    return None

def fetch_kepco_capacity_by_address(address_str):
    try:
        v_url = "https://api.vworld.kr/req/address"
        v_params = {"service": "address", "request": "getcoord", "version": "2.0", "crs": "epsg:4326", "address": address_str, "refine": "true", "simple": "false", "type": "PARCEL", "key": VWORLD_KEY, "domain": MY_DOMAIN_URL, "format": "json"}
        v_resp = session.get(v_url, params=v_params, headers=COMMON_HEADERS, timeout=5, verify=False)
        v_data = v_resp.json()
        
        if v_data['response']['status'] != 'OK': return None
        structure = v_data['response']['refined']['structure']
        
        kepco_url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
        addr_lidong = structure.get('level4L') or structure.get('level4A', '')
        addr_jibun = f"{structure.get('mainNum','')}-{structure.get('subNum','')}" if structure.get('subNum') != '0' else structure.get('mainNum','')

        k_params = {"apiKey": KEPCO_KEY, "returnType": "json", "addrLidong": addr_lidong, "addrJibun": addr_jibun}
        k_resp = requests.get(kepco_url, params=k_params, timeout=10)
        
        if k_resp.status_code == 200:
            k_data = k_resp.json()
            if "data" in k_data and len(k_data["data"]) > 0: return k_data["data"][0]
    except: pass
    return None

@app.route('/api/kepco')
def proxy_kepco():
    return jsonify({"result": "OK", "msg": "Logic Connected"})

@app.route('/api/ordinance')
def get_ordinance():
    return jsonify({"result": "OK", "articles": ["이격거리 규제 정보..."]})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
