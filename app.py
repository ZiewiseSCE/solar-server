# -*- coding: utf-8 -*-
import os
import requests
import sys
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# SSL 경고 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# CORS: 모든 출처 허용
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------
# 1. 설정
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")
# 도메인 설정: https://solar-server-jszy.onrender.com (뒤에 슬래시 없음)
MY_DOMAIN_URL = "https://solar-server-jszy.onrender.com"

# 세션 설정
session = requests.Session()
retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry)
session.mount("https://", adapter)
session.mount("http://", adapter)

# 헤더: 일반 브라우저처럼 위장
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
# 3. V-World 주소 검색 (핵심 수정)
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    try:
        query = request.args.get('address')
        if not query:
            return jsonify({"status": "ERROR", "message": "주소를 입력해주세요."}), 200

        print(f"[Address] Searching: {query}", file=sys.stdout)

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
            "domain": MY_DOMAIN_URL, # 전체 URL 전송
            "format": "json"
        }
        
        # 1차 시도 (Road)
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        # V-World 에러 응답 처리
        if resp.status_code != 200:
            return jsonify({
                "status": "VWORLD_ERROR", 
                "message": f"V-World Error ({resp.status_code})",
                "details": resp.text[:200]
            }), 200

        try:
            data = resp.json()
            # 검색 결과 없음 -> 지번(PARCEL)으로 재시도
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 print("[Address] Retry with PARCEL type...", file=sys.stdout)
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
                 if resp_p.status_code == 200:
                     try: data = resp_p.json()
                     except: pass
            return jsonify(data)
        except ValueError:
            return jsonify({"status": "PARSING_ERROR", "message": "V-World JSON 파싱 실패", "raw": resp.text[:200]}), 200

    except Exception as e:
        print(f"[Address Exception] {str(e)}", file=sys.stderr)
        # 중요: 서버 에러도 JSON으로 반환하여 CORB 방지
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 200

# ---------------------------------------------------------
# 4. V-World 데이터 조회
# ---------------------------------------------------------
@app.route('/api/vworld/data')
def proxy_data():
    try:
        layer = request.args.get('data', 'LT_C_SPBD')
        geom_filter = request.args.get('geomFilter')
        if not geom_filter:
            return jsonify({"status": "ERROR", "message": "geomFilter 누락"}), 200

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
            return jsonify({
                "status": "VWORLD_ERROR", 
                "message": f"V-World Error {resp.status_code}",
                "details": resp.text[:200]
            }), 200
            
        return jsonify(resp.json())

    except Exception as e:
        print(f"[Data Exception] {str(e)}", file=sys.stderr)
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 200

# ---------------------------------------------------------
# 5. 한전 & 종합 분석
# ---------------------------------------------------------
def fetch_kepco_capacity_by_address(address_str):
    # (이전 로직 유지: V-World로 지번 변환 후 한전 API 호출)
    try:
        # 1. 주소 변환
        v_url = "https://api.vworld.kr/req/address"
        v_params = {
            "service": "address", "request": "getcoord", "version": "2.0", "crs": "epsg:4326",
            "address": address_str, "refine": "true", "simple": "false", "type": "PARCEL",
            "key": VWORLD_KEY, "domain": MY_DOMAIN_URL, "format": "json"
        }
        v_resp = session.get(v_url, params=v_params, headers=COMMON_HEADERS, timeout=5, verify=False)
        v_data = v_resp.json()
        
        if v_data['response']['status'] != 'OK': return None
        structure = v_data['response']['refined']['structure']
        
        # 2. 한전 API
        kepco_url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
        addr_lidong = structure.get('level4L') or structure.get('level4A', '')
        addr_jibun = f"{structure.get('mainNum','')}-{structure.get('subNum','')}" if structure.get('subNum') != '0' else structure.get('mainNum','')

        k_params = {"apiKey": KEPCO_KEY, "returnType": "json", "addrLidong": addr_lidong, "addrJibun": addr_jibun}
        k_resp = requests.get(kepco_url, params=k_params, timeout=10)
        
        if k_resp.status_code == 200:
            k_data = k_resp.json()
            if "data" in k_data and len(k_data["data"]) > 0:
                return k_data["data"][0]
    except: pass
    return None

def fetch_vworld_feature(layer, bbox):
    url = "https://api.vworld.kr/req/data"
    params = {"service": "data", "request": "GetFeature", "data": layer, "key": VWORLD_KEY, "geomFilter": f"BOX({bbox})", "size": "1", "domain": MY_DOMAIN_URL, "format": "json"}
    try:
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        data = resp.json()
        if data['response']['status'] == 'OK': return data['response']['result']['featureCollection']['features'][0]
    except: pass
    return None

@app.route('/api/analyze/comprehensive')
def analyze_site():
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        area_size = float(request.args.get('area', 0))
        address = request.args.get('address', '')

        if not lat or not lng: return jsonify({"status": "ERROR", "message": "좌표 누락"}), 200

        delta = 0.0001
        bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
        
        zoning_info = fetch_vworld_feature("LT_C_UQ111", bbox) 
        zoning_name = zoning_info.get('properties', {}).get('MNUM_NM', '미확인') if zoning_info else "확인불가"

        eco_info = fetch_vworld_feature("LT_C_WISNAT", bbox) 
        eco_grade = eco_info.get('properties', {}).get('GRD_NM', '등급외') if eco_info else "확인불가"
        
        env_impact_check = "대상 아님"
        # (간소화된 로직 유지)

        kepco_dl_capacity = "확인 불가"
        kepco_info = "API 키 필요"
        if address:
            k_res = fetch_kepco_capacity_by_address(address)
            if k_res:
                kepco_dl_capacity = f"{k_res.get('vol3','-')}"
                kepco_info = f"변전소: {k_res.get('substNm','-')}"
            else:
                kepco_info = "데이터 없음 (한전ON 확인)"

        return jsonify({
            "status": "OK",
            "address": address,
            "zoning": zoning_name,
            "eco_grade": eco_grade,
            "env_assessment": env_impact_check,
            "kepco_capacity": kepco_dl_capacity,
            "messages": [f"용도: {zoning_name}", f"생태: {eco_grade}", f"한전: {kepco_dl_capacity}"],
            "links": { "kepco": "https://online.kepco.co.kr/" }
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 200

@app.route('/api/kepco')
def proxy_kepco():
    addr = request.args.get('address')
    if not addr: return jsonify({"result": "FAIL", "msg": "주소 필요"}), 200
    data = fetch_kepco_capacity_by_address(addr)
    if data: return jsonify({"result": "OK", "data": data})
    return jsonify({"result": "FAIL", "msg": "데이터 없음"})

@app.route('/api/ordinance')
def get_ordinance():
    return jsonify({"result": "OK", "articles": ["규제 정보 확인 필요"]})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
