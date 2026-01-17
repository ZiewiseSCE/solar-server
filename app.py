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
# CORS: 모든 도메인 허용
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------
# 1. 설정 (API 키 및 도메인)
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# [수정됨] Cloudtype 서버 주소 (V-World 등록 주소와 일치해야 함)
MY_DOMAIN_URL = "https://port-0-solar-server-mkiol9jsc308f567.sel3.cloudtype.app"

# 세션 설정
session = requests.Session()
retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retry)
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
# 3. V-World 주소 검색
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    try:
        query = request.args.get('address')
        if not query: return jsonify({"status": "ERROR", "message": "주소 필요"}), 200

        print(f"[Address] Searching: {query}", file=sys.stdout)
        url = "https://api.vworld.kr/req/address"
        params = {
            "service": "address", "request": "getcoord", "version": "2.0", "crs": "epsg:4326",
            "address": query, "refine": "true", "simple": "false", "type": "road",
            "key": VWORLD_KEY, "domain": MY_DOMAIN_URL, "format": "json"
        }
        
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        if resp.status_code != 200:
            return jsonify({"status": "VWORLD_ERROR", "details": resp.text[:200]}), 200

        try:
            data = resp.json()
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
                 if resp_p.status_code == 200:
                     try: data = resp_p.json()
                     except: pass
            return jsonify(data)
        except:
            return jsonify({"status": "PARSING_ERROR", "raw": resp.text[:200]}), 200
    except Exception as e:
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 200

# ---------------------------------------------------------
# 4. V-World 데이터 조회
# ---------------------------------------------------------
@app.route('/api/vworld/data')
def proxy_data():
    try:
        layer = request.args.get('data', 'LT_C_SPBD')
        geom = request.args.get('geomFilter')
        if not geom: return jsonify({"status": "ERROR", "message": "geomFilter 필요"}), 200

        url = "https://api.vworld.kr/req/data"
        params = {
            "service": "data", "request": "GetFeature", "data": layer,
            "key": VWORLD_KEY, "geomFilter": geom, "size": "1000",
            "domain": MY_DOMAIN_URL, "format": "json"
        }

        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=20, verify=False)
        
        if resp.status_code != 200:
            return jsonify({"status": "VWORLD_ERROR", "details": resp.text[:200]}), 200
            
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 200

# ---------------------------------------------------------
# 5. 종합 분석
# ---------------------------------------------------------
@app.route('/api/analyze/comprehensive')
def analyze_site():
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        area_size = float(request.args.get('area', 0))
        address = request.args.get('address', '')

        if not lat or not lng: return jsonify({"status": "ERROR"}), 200

        delta = 0.0001
        bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
        
        zoning_info = fetch_vworld_feature("LT_C_UQ111", bbox) 
        zoning_name = zoning_info.get('properties', {}).get('MNUM_NM', '확인불가') if zoning_info else "확인불가"

        eco_info = fetch_vworld_feature("LT_C_WISNAT", bbox) 
        eco_grade = eco_info.get('properties', {}).get('GRD_NM', '등급외') if eco_info else "확인불가"
        
        env_check = "대상 아님"
        if "보전" in zoning_name and area_size >= 5000: env_check = "✅ 대상 (5,000m²↑)"
        elif "생산" in zoning_name and area_size >= 7500: env_check = "✅ 대상 (7,500m²↑)"
        elif "계획" in zoning_name and area_size >= 10000: env_check = "✅ 대상 (10,000m²↑)"
        elif "농림" in zoning_name and area_size >= 7500: env_check = "✅ 대상 (7,500m²↑)"
        
        kepco_cap = "확인 불가"
        kepco_info = "API 키 필요"
        if address:
            k_res = fetch_kepco_capacity(address)
            if k_res:
                kepco_cap = f"{k_res.get('vol3','-')} (변전소 여유: {k_res.get('vol1','-')})"
                kepco_info = f"변전소: {k_res.get('substNm','-')}"
            else:
                kepco_cap = "데이터 없음 (한전ON 확인)"

        return jsonify({
            "status": "OK",
            "address": address,
            "zoning": zoning_name,
            "eco_grade": eco_grade,
            "env_assessment": env_check,
            "kepco_capacity": kepco_cap,
            "messages": [
                f"📌 용도지역: {zoning_name}",
                f"🌿 생태등급: {eco_grade}",
                f"⚡ 한전 선로: {kepco_cap} / {kepco_info}",
                f"⚠️ 환경영향평가: {env_check}"
            ],
            "links": { 
                "kepco": "https://online.kepco.co.kr/",
                "eum": "https://www.eum.go.kr/web/am/amMain.jsp"
            }
        })
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 200

# --- 헬퍼 함수 ---
def fetch_vworld_feature(layer, bbox):
    url = "https://api.vworld.kr/req/data"
    params = {"service": "data", "request": "GetFeature", "data": layer, "key": VWORLD_KEY, "geomFilter": f"BOX({bbox})", "size": "1", "domain": MY_DOMAIN_URL, "format": "json"}
    try:
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        data = resp.json()
        if data['response']['status'] == 'OK': return data['response']['result']['featureCollection']['features'][0]
    except: pass
    return None

def fetch_kepco_capacity(addr):
    try:
        v_url = "https://api.vworld.kr/req/address"
        v_params = {"service": "address", "request": "getcoord", "version": "2.0", "crs": "epsg:4326", "address": addr, "refine": "true", "simple": "false", "type": "PARCEL", "key": VWORLD_KEY, "domain": MY_DOMAIN_URL, "format": "json"}
        v_resp = session.get(v_url, params=v_params, headers=COMMON_HEADERS, timeout=5, verify=False)
        v_data = v_resp.json()
        if v_data['response']['status'] != 'OK': return None
        
        st = v_data['response']['refined']['structure']
        k_url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
        jibun = f"{st.get('mainNum','')}-{st.get('subNum','')}" if st.get('subNum')!='0' else st.get('mainNum','')
        k_params = {"apiKey": KEPCO_KEY, "returnType": "json", "addrLidong": st.get('level4L') or st.get('level4A',''), "addrJibun": jibun}
        
        k_resp = requests.get(k_url, params=k_params, timeout=10)
        if k_resp.status_code == 200:
            d = k_resp.json()
            if "data" in d and len(d["data"]) > 0: return d["data"][0]
    except: pass
    return None

@app.route('/api/kepco')
def proxy_kepco():
    return jsonify({"result": "OK", "msg": "Logic Connected"})

@app.route('/api/ordinance')
def get_ordinance():
    return jsonify({"result": "OK", "articles": []})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
