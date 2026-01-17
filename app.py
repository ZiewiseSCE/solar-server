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

# SSL 인증서 경고 무시 (Render <-> V-World 통신 시 필요)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
# 모든 도메인, 헤더, 메소드 허용 (CORS 차단 방지)
CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": "*"}})

# ---------------------------------------------------------
# 1. 설정 (API 키 및 도메인)
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
# 한전 API 키 (발급받은 키가 있다면 여기에 입력, 없다면 기본값)
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# V-World 관리자 페이지 '서비스 URL'에 등록된 주소
MY_DOMAIN_URL = "https://solar-server-jszy.onrender.com"

# 세션 및 재시도 설정
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
# 3. V-World 주소 검색 (안정성 강화)
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    try:
        query = request.args.get('address')
        if not query:
            return jsonify({"status": "ERROR", "message": "Missing address"}), 200

        url = "https://api.vworld.kr/req/address"
        params = {
            "service": "address", "request": "getcoord", "version": "2.0", "crs": "epsg:4326",
            "address": query, "refine": "true", "simple": "false", "type": "road",
            "key": VWORLD_KEY, "domain": MY_DOMAIN_URL, "format": "json"
        }
        
        print(f"[Address] Searching: {query}", file=sys.stdout)
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        # [중요] 500 에러 방지: V-World 에러도 200 OK로 감싸서 반환
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
                 print("[Address] Retry with parcel type...", file=sys.stdout)
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
                 if resp_p.status_code == 200:
                     try: data = resp_p.json()
                     except: pass
            return jsonify(data)
        except ValueError:
            return jsonify({"status": "PARSING_ERROR", "message": "Invalid JSON from V-World", "raw": resp.text[:200]}), 200

    except Exception as e:
        print(f"[Address Exception] {str(e)}", file=sys.stderr)
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 200

# ---------------------------------------------------------
# 4. V-World 데이터 조회 (안정성 강화)
# ---------------------------------------------------------
@app.route('/api/vworld/data')
def proxy_data():
    try:
        layer = request.args.get('data', 'LT_C_SPBD')
        geom_filter = request.args.get('geomFilter')
        if not geom_filter:
            return jsonify({"status": "ERROR", "message": "Missing geomFilter"}), 200

        url = "https://api.vworld.kr/req/data"
        params = {
            "service": "data", "request": "GetFeature", "data": layer,
            "key": VWORLD_KEY, "geomFilter": geom_filter, "size": "1000",
            "domain": MY_DOMAIN_URL, "format": "json"
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
# 5. 종합 분석 API (8대 항목 통합)
# ---------------------------------------------------------
@app.route('/api/analyze/comprehensive')
def analyze_site():
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        area_size = float(request.args.get('area', 0))
        address = request.args.get('address', '')

        if not lat or not lng:
            return jsonify({"status": "ERROR", "message": "좌표 정보 누락"}), 200

        delta = 0.0001
        bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
        
        # 1. 용도지역
        zoning_info = fetch_vworld_feature("LT_C_UQ111", bbox) 
        zoning_name = zoning_info.get('properties', {}).get('MNUM_NM', '용도지역 미확인') if zoning_info else "확인 불가"

        # 2. 생태자연도
        eco_info = fetch_vworld_feature("LT_C_WISNAT", bbox) 
        eco_grade = eco_info.get('properties', {}).get('GRD_NM', '등급 외') if eco_info else "확인 불가"
        
        # 3. 환경영향평가 대상 여부
        env_impact_check = "대상 아님"
        if "보전관리" in zoning_name and area_size >= 5000: env_impact_check = "✅ 대상 (5,000m² 이상)"
        elif "생산관리" in zoning_name and area_size >= 7500: env_impact_check = "✅ 대상 (7,500m² 이상)"
        elif "계획관리" in zoning_name and area_size >= 10000: env_impact_check = "✅ 대상 (10,000m² 이상)"
        elif "농림" in zoning_name and area_size >= 7500: env_impact_check = "✅ 대상 (7,500m² 이상)"
        else: env_impact_check = f"미대상 ({int(area_size)}m²)" if area_size > 0 else "면적 정보 없음"

        # 4. 한전 용량
        kepco_dl_capacity = "확인 불가"
        kepco_info = "API 키 필요"
        
        # 주소가 있으면 한전 API 조회 시도
        if address:
            kepco_result = fetch_kepco_capacity_by_address(address)
            if kepco_result:
                dl_margin = kepco_result.get('vol3', '정보없음')
                subst_name = kepco_result.get('substNm', '미확인')
                dl_name = kepco_result.get('dlNm', '미확인')
                kepco_info = f"변전소: {subst_name}, DL명: {dl_name}"
                kepco_dl_capacity = f"{dl_margin} (변전소 여유: {kepco_result.get('vol1', '-')})"
            else:
                kepco_info = "해당 지번 데이터 없음 (한전ON 확인 요망)"

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
            ],
            "links": {
                "elis": "https://www.elis.go.kr/",
                "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
                "aid": "https://aid.mcee.go.kr/",
                "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?",
                "neins": "https://webgis.neins.go.kr/map.do",
                "kepco": "https://online.kepco.co.kr/"
            }
        })

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 200

# ---------------------------------------------------------
# [헬퍼 함수] 내부 호출용
# ---------------------------------------------------------
def fetch_vworld_feature(layer, bbox):
    """V-World Data API 내부 호출용"""
    url = "https://api.vworld.kr/req/data"
    params = {
        "service": "data", "request": "GetFeature", "data": layer,
        "key": VWORLD_KEY, "geomFilter": f"BOX({bbox})", "size": "1",
        "domain": MY_DOMAIN_URL, "format": "json"
    }
    try:
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        data = resp.json()
        if data['response']['status'] == 'OK':
            return data['response']['result']['featureCollection']['features'][0]
    except: pass
    return None

def fetch_kepco_capacity_by_address(address_str):
    """주소 -> 지번 변환 -> 한전 API 호출"""
    try:
        # 1. 주소 변환 (V-World)
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
        
        # 2. 한전 API 호출
        kepco_url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
        addr_lidong = structure.get('level4L') or structure.get('level4A', '')
        addr_jibun = f"{structure.get('mainNum','')}-{structure.get('subNum','')}" if structure.get('subNum') != '0' else structure.get('mainNum','')

        k_params = {
            "apiKey": KEPCO_KEY, "returnType": "json",
            "addrLidong": addr_lidong, "addrJibun": addr_jibun
        }
        k_resp = requests.get(kepco_url, params=k_params, timeout=10)
        
        if k_resp.status_code == 200:
            k_data = k_resp.json()
            # 데이터가 리스트로 옴
            if "data" in k_data and len(k_data["data"]) > 0:
                return k_data["data"][0]
    except Exception as e:
        print(f"[KEPCO API Error] {e}", file=sys.stderr)
        pass
    return None

# ---------------------------------------------------------
# 6. 기타 API
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    address = request.args.get('address')
    if not address: return jsonify({"result": "FAIL", "msg": "주소 필요"}), 200
    data = fetch_kepco_capacity_by_address(address)
    if data: return jsonify({"result": "OK", "data": data})
    return jsonify({"result": "FAIL", "msg": "데이터 없음"})

@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    if not address: return jsonify({"result": "FAIL", "msg": "주소 정보 없음"}), 200

    try:
        tokens = address.split()
        region_name = tokens[0] if tokens else ""
        for t in tokens:
            if t.endswith("시") or t.endswith("군"):
                region_name = t
                break
        
        search_keyword = f"{region_name} 도시계획 조례"
        search_url = "http://www.law.go.kr/DRF/lawSearch.do"
        search_params = {"OC": LAW_API_ID, "target": "ordin", "type": "XML", "query": search_keyword, "display": 1}
        
        res = requests.get(search_url, params=search_params, timeout=5)
        root = ET.fromstring(res.content)
        
        target_law_id = None
        target_law_name = ""
        
        law_node = root.find(".//law")
        if law_node is not None:
            target_law_id = law_node.find("lawId").text
            target_law_name = law_node.find("lawNm").text
        else:
            return jsonify({"result": "NONE", "region": region_name, "msg": "조례 없음"})
            
        return jsonify({
            "result": "OK", 
            "region": region_name, 
            "law_name": target_law_name, 
            "articles": ["원문 확인 필요"],
            "link": f"http://www.law.go.kr/ordinSc.do?menuId=0&query={target_law_name}"
        })

    except Exception as e:
        return jsonify({"result": "ERROR", "msg": str(e)}), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
