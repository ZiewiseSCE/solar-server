# -*- coding: utf-8 -*-
import os
import requests
import xml.etree.ElementTree as ET
import re
import sys
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
# V-World API 키
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
# 법제처 API 아이디 (공공데이터)
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
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        return jsonify({
            "status": "CHECK_COMPLETED",
            "vworld_http_status": resp.status_code,
            "response_sample": resp.text[:300]
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

        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        if resp.status_code != 200:
            print(f"[Data API Error] Status: {resp.status_code}", file=sys.stderr)
            return jsonify({"status": "VWORLD_ERROR", "details": resp.text[:500]}), resp.status_code
            
        return jsonify(resp.json())

    except Exception as e:
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 4. V-World 주소 검색 프록시
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    try:
        query = request.args.get('address')
        if not query:
            return jsonify({"status": "ERROR", "message": "Missing address"}), 400

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
            "domain": MY_DOMAIN_URL,
            "format": "json"
        }
        
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        if resp.status_code != 200:
            return jsonify({"status": "VWORLD_ERROR", "details": resp.text[:500]}), resp.status_code

        try:
            data = resp.json()
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
                 if resp_p.status_code == 200:
                     try: data = resp_p.json()
                     except: pass
            return jsonify(data)
        except ValueError:
            return jsonify({"status": "PARSING_ERROR", "raw_response": resp.text[:200]}), 500

    except Exception as e:
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) API (간소화)
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    return jsonify({"result": "OK", "msg": "KEPCO Logic Connected"})

# ---------------------------------------------------------
# 6. [복구됨] 조례 정보 검색 API (국가법령정보센터 실시간 연동)
# ---------------------------------------------------------
@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    if not address:
        return jsonify({"result": "FAIL", "msg": "주소 정보 없음"})

    try:
        # 1. 주소에서 지역명 추출 (예: "경기 고양시 덕양구..." -> "고양시")
        tokens = address.split()
        region_name = ""
        for t in tokens:
            if t.endswith("시") or t.endswith("군"):
                region_name = t
                break
        if not region_name and tokens:
            region_name = tokens[0] # 시/군이 없으면 첫 단어 사용

        print(f"[Ordinance] Region: {region_name}", file=sys.stdout)

        # 2. 법제처 검색 API 호출
        search_keyword = f"{region_name} 도시계획 조례"
        search_url = "http://www.law.go.kr/DRF/lawSearch.do"
        search_params = {
            "OC": LAW_API_ID,
            "target": "ordin",
            "type": "XML",
            "query": search_keyword,
            "display": 1
        }
        
        # XML 데이터 요청
        res = requests.get(search_url, params=search_params, timeout=5)
        root = ET.fromstring(res.content)
        
        target_law_id = None
        target_law_name = ""
        
        # 검색 결과에서 조례 ID 찾기
        law_node = root.find(".//law")
        if law_node is not None:
            target_law_id = law_node.find("lawId").text
            target_law_name = law_node.find("lawNm").text
        else:
            return jsonify({
                "result": "NONE", 
                "region": region_name, 
                "msg": f"{region_name} 관련 조례를 찾을 수 없습니다."
            })

        # 3. 조례 상세 내용 가져오기
        detail_url = "http://www.law.go.kr/DRF/lawService.do"
        detail_params = {
            "OC": LAW_API_ID,
            "target": "ordin",
            "type": "XML",
            "ID": target_law_id
        }
        
        det_res = requests.get(detail_url, params=detail_params, timeout=5)
        det_root = ET.fromstring(det_res.content)
        
        relevant_articles = []
        # '태양광', '발전', '이격' 키워드가 있는 조항만 추출
        for article in det_root.findall(".//jo"):
            raw_text = "".join(list(article.itertext()))
            if "태양" in raw_text or "발전" in raw_text or "이격" in raw_text:
                # 숫자+m 부분 강조 (HTML 태그 삽입)
                highlighted = re.sub(r'(\d+(?:m|미터))', r'<b style="color:#f87171;">\1</b>', raw_text)
                relevant_articles.append(highlighted.strip())

        if not relevant_articles:
            relevant_articles.append("검색된 조례 내에서 '태양광/이격거리' 관련 키워드를 찾지 못했습니다. 원문을 확인하세요.")

        return jsonify({
            "result": "OK",
            "region": region_name,
            "law_name": target_law_name,
            "articles": relevant_articles[:3], # 너무 길면 상위 3개만
            "link": f"http://www.law.go.kr/ordinSc.do?menuId=0&query={target_law_name}"
        })

    except Exception as e:
        print(f"[Ordinance Error] {str(e)}", file=sys.stderr)
        return jsonify({"result": "ERROR", "msg": "법령 데이터 서버 통신 오류"})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
