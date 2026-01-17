# -*- coding: utf-8 -*-
import os
import requests
import xml.etree.ElementTree as ET
import re
import sys
import json
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from requests.exceptions import RetryError, Timeout
import urllib3

# SSL 경고 메시지 억제
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# 1. 설정 (API 키 및 도메인)
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
# [수정] 사용자가 제공한 한전 빅데이터 센터 API 인증키 적용
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
# [핵심] 종합 입지 분석 API (8대 항목 통합)
# ---------------------------------------------------------
@app.route('/api/analyze/comprehensive')
def analyze_site():
    try:
        lat = request.args.get('lat')
        lng = request.args.get('lng')
        area_size = float(request.args.get('area', 0)) # m2 단위
        address = request.args.get('address', '')

        if not lat or not lng:
            return jsonify({"status": "ERROR", "message": "좌표 정보가 없습니다."}), 400

        # V-World 데이터 조회용 박스
        delta = 0.0001
        bbox = f"{float(lng)-delta},{float(lat)-delta},{float(lng)+delta},{float(lat)+delta}"
        
        # 1. 토지이음 (용도지역) 확인
        zoning_info = fetch_vworld_feature("LT_C_UQ111", bbox) 
        zoning_name = zoning_info.get('properties', {}).get('MNUM_NM', '용도지역 미확인') if zoning_info else "확인 불가"

        # 2. 생태자연도 확인
        eco_info = fetch_vworld_feature("LT_C_WISNAT", bbox) 
        eco_grade = eco_info.get('properties', {}).get('GRD_NM', '등급 외') if eco_info else "확인 불가"
        
        # 3. 환경영향평가 대상 여부 판단
        env_impact_check = "대상 아님"
        if "보전관리" in zoning_name and area_size >= 5000: env_impact_check = "✅ 대상 (5,000m² 이상)"
        elif "생산관리" in zoning_name and area_size >= 7500: env_impact_check = "✅ 대상 (7,500m² 이상)"
        elif "계획관리" in zoning_name and area_size >= 10000: env_impact_check = "✅ 대상 (10,000m² 이상)"
        elif "농림" in zoning_name and area_size >= 7500: env_impact_check = "✅ 대상 (7,500m² 이상)"
        else:
             if area_size > 0: env_impact_check = f"미대상 ({int(area_size)}m²)"
             else: env_impact_check = "면적 정보 없음"

        # 4. 한전 선로 용량 조회 (자동 지번 변환 포함)
        kepco_info = "API 키 확인 필요"
        kepco_dl_capacity = "확인 불가"
        
        if address:
            kepco_result = fetch_kepco_capacity_by_address(address)
            if kepco_result:
                dl_margin = kepco_result.get('vol3', '정보없음') # DL 여유용량
                subst_name = kepco_result.get('substNm', '미확인')
                dl_name = kepco_result.get('dlNm', '미확인')
                kepco_info = f"변전소: {subst_name}, DL명: {dl_name}"
                kepco_dl_capacity = f"{dl_margin} (변전소 여유: {kepco_result.get('vol1', '-')})"
            else:
                kepco_info = "해당 지번 데이터 없음 (한전ON 확인 요망)"
        
        # 5. 종합 리포트 생성
        report = {
            "status": "OK",
            "address": address,
            "zoning": zoning_name,
            "eco_grade": eco_grade,
            "env_assessment": env_impact_check,
            "kepco_capacity": kepco_dl_capacity,
            "links": {
                "elis": "https://www.elis.go.kr/",
                "eum": "https://www.eum.go.kr/web/am/amMain.jsp",
                "aid": "https://aid.mcee.go.kr/",
                "heritage": "https://www.nie-ecobank.kr/cmmn/Index.do?",
                "neins": "https://webgis.neins.go.kr/map.do",
                "kepco": "https://online.kepco.co.kr/"
            },
            "messages": [
                f"📌 용도지역: {zoning_name}",
                f"🌿 생태등급: {eco_grade} (1등급지 주의)",
                f"⚡ 한전 용량: {kepco_dl_capacity} / {kepco_info}",
                f"⚠️ 환경영향평가: {env_impact_check}",
                "⛰️ 경사도: [국토환경성평가지도]에서 정밀 확인 필요"
            ]
        }
        
        return jsonify(report)

    except Exception as e:
        print(f"[Analysis Error] {str(e)}", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

def fetch_vworld_feature(layer, bbox):
    """V-World Data API 내부 호출용 헬퍼 함수"""
    url = "https://api.vworld.kr/req/data"
    params = {
        "service": "data",
        "request": "GetFeature",
        "data": layer,
        "key": VWORLD_KEY,
        "geomFilter": f"BOX({bbox})",
        "size": "1",
        "domain": MY_DOMAIN_URL,
        "format": "json"
    }
    try:
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        data = resp.json()
        if data['response']['status'] == 'OK':
            return data['response']['result']['featureCollection']['features'][0]
    except:
        pass
    return None

def fetch_kepco_capacity_by_address(address_str):
    """
    주소 문자열을 받아 V-World에서 지번으로 변환 후 한전 API 호출
    """
    try:
        # 1. V-World 주소 API로 '지번 주소(Parcel)' 상세 정보 획득
        v_url = "https://api.vworld.kr/req/address"
        v_params = {
            "service": "address",
            "request": "getcoord",
            "version": "2.0",
            "crs": "epsg:4326",
            "address": address_str,
            "refine": "true",
            "simple": "false",
            "type": "PARCEL", # 지번으로 강제 변환
            "key": VWORLD_KEY,
            "domain": MY_DOMAIN_URL,
            "format": "json"
        }
        
        v_resp = session.get(v_url, params=v_params, headers=COMMON_HEADERS, timeout=5, verify=False)
        v_data = v_resp.json()
        
        if v_data['response']['status'] != 'OK':
            print(f"[KEPCO] V-World Address failed: {v_data}", file=sys.stderr)
            return None
            
        structure = v_data['response']['refined']['structure']
        
        # 2. 한전 API 파라미터 구성 (한전 빅데이터 포털)
        kepco_url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
        
        # 동/리 추출 (level4L: 법정동/리)
        # 예: '행신동' -> addrLidong='행신동', addrLi=''
        # 예: '광덕면 광덕리' -> V-World는 level4L='광덕리', level3='...면' 등으로 줌
        # 한전 API는 addrLidong에 '면'을, addrLi에 '리'를 요구할 수 있음.
        # 여기서는 단순화를 위해 level4L(법정동)을 addrLidong에 넣음. (대부분의 도심지)
        addr_lidong = structure.get('level4L') or structure.get('level4A', '')
        addr_li = ""
        
        # 만약 '리'로 끝난다면 상위 행정구역(level3 등)이 면/읍일 가능성
        if addr_lidong.endswith("리"):
            addr_li = addr_lidong
            # level3가 읍/면일 경우 사용 (V-World 구조에 따라 다름)
            # 일단 addrLidong에는 상위 주소를 넣어야 하나 V-World 구조상 복잡하므로
            # addrLidong에 읍/면 정보를 넣으려면 추가 파싱 필요.
            # 간소화를 위해 addrLidong에 그대로 둠 (한전 API가 유연하길 기대)
        
        # 번지 추출 (mainNum-subNum)
        main_num = structure.get('mainNum', '')
        sub_num = structure.get('subNum', '')
        addr_jibun = f"{main_num}-{sub_num}" if sub_num and sub_num != '0' else main_num

        k_params = {
            "apiKey": KEPCO_KEY,
            "returnType": "json",
            "addrLidong": addr_lidong, 
            "addrJibun": addr_jibun,
            "addrLi": addr_li
        }
        
        # 3. 한전 API 호출
        print(f"[KEPCO] Requesting: {k_params}", file=sys.stdout)
        k_resp = requests.get(kepco_url, params=k_params, timeout=10)
        
        if k_resp.status_code == 200:
            k_data = k_resp.json()
            if "data" in k_data and len(k_data["data"]) > 0:
                return k_data["data"][0] # 첫 번째 결과 반환
            else:
                print(f"[KEPCO] No data found: {k_data}", file=sys.stdout)
                
    except Exception as e:
        print(f"[KEPCO API Error] {str(e)}", file=sys.stderr)
        
    return None

# ---------------------------------------------------------
# 3. V-World 데이터 프록시 (기존 유지)
# ---------------------------------------------------------
@app.route('/api/vworld/data')
def proxy_data():
    try:
        layer = request.args.get('data', 'LT_C_SPBD')
        geom_filter = request.args.get('geomFilter')
        if not geom_filter: return jsonify({"status": "ERROR", "message": "Missing geomFilter"}), 400
        url = "https://api.vworld.kr/req/data"
        params = {"service": "data", "request": "GetFeature", "data": layer, "key": VWORLD_KEY, "geomFilter": geom_filter, "size": "1000", "domain": MY_DOMAIN_URL, "format": "json"}
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        if resp.status_code != 200:
             return jsonify({"status": "VWORLD_ERROR", "details": resp.text[:500]}), resp.status_code
        return jsonify(resp.json())
    except Exception as e: return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 4. V-World 주소 검색 프록시 (기존 유지)
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    try:
        query = request.args.get('address')
        if not query: return jsonify({"status": "ERROR", "message": "Missing address"}), 400
        print(f"[Address] Searching: {query}", file=sys.stdout)
        url = "https://api.vworld.kr/req/address"
        params = {"service": "address", "request": "getcoord", "version": "2.0", "crs": "epsg:4326", "address": query, "refine": "true", "simple": "false", "type": "road", "key": VWORLD_KEY, "domain": MY_DOMAIN_URL, "format": "json"}
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        if resp.status_code != 200:
            return jsonify({"status": "VWORLD_ERROR", "details": resp.text[:500]}), resp.status_code
            
        try:
            data = resp.json()
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
                 if resp_p.status_code == 200: try: data = resp_p.json() 
                 except: pass
            return jsonify(data)
        except ValueError:
            return jsonify({"status": "PARSING_ERROR", "raw_response": resp.text[:200]}), 500
            
    except Exception as e:
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) 직접 호출 엔드포인트 (주소 기반)
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    """
    프론트엔드에서 주소를 보내면 한전 용량을 조회하는 엔드포인트
    """
    address = request.args.get('address')
    if not address:
        return jsonify({"result": "FAIL", "msg": "주소를 입력해주세요."})
    
    # 헬퍼 함수를 통해 조회
    data = fetch_kepco_capacity_by_address(address)
    
    if data:
        return jsonify({"result": "OK", "data": data})
    else:
        return jsonify({"result": "FAIL", "msg": "해당 주소의 한전 선로 정보를 찾을 수 없습니다."})

# ---------------------------------------------------------
# 6. 조례 정보 검색 API (기존 유지)
# ---------------------------------------------------------
@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    if not address: return jsonify({"result": "FAIL", "msg": "주소 정보 없음"})
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
        law_node = root.find(".//law")
        if law_node is not None:
            target_law_id = law_node.find("lawId").text
            target_law_name = law_node.find("lawNm").text
        else:
            return jsonify({"result": "NONE", "region": region_name, "msg": "조례 없음"})
        
        detail_url = "http://www.law.go.kr/DRF/lawService.do"
        detail_params = {"OC": LAW_API_ID, "target": "ordin", "type": "XML", "ID": target_law_id}
        det_res = requests.get(detail_url, params=detail_params, timeout=5)
        det_root = ET.fromstring(det_res.content)
        relevant_articles = []
        for article in det_root.findall(".//jo"):
            raw_text = "".join(list(article.itertext()))
            if "태양" in raw_text or "발전" in raw_text or "이격" in raw_text:
                highlighted = re.sub(r'(\d+(?:m|미터))', r'<b style="color:#f87171;">\1</b>', raw_text)
                relevant_articles.append(highlighted.strip())
        return jsonify({"result": "OK", "region": region_name, "law_name": target_law_name, "articles": relevant_articles[:3], "link": f"http://www.law.go.kr/ordinSc.do?menuId=0&query={target_law_name}"})
    except Exception as e:
        return jsonify({"result": "ERROR", "msg": str(e)})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
