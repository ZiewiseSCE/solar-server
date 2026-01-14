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
import urllib3

# SSL 경고 메시지 억제 (로그 지저분해짐 방지)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# 1. 설정
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# [핵심] V-World 관리자 페이지에 등록된 주소와 100% 일치해야 함 (http/https 구분)
# 끝에 슬래시(/)가 없어야 함.
MY_DOMAIN = "solar-server-jszy.onrender.com"

# 세션 설정
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("https://", adapter)
session.mount("http://", adapter)

# 헤더 설정: V-World는 Referer를 철저히 검사합니다.
COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": f"https://{MY_DOMAIN}",  # 중요: 등록된 도메인 프로토콜에 맞춤
    "Origin": f"https://{MY_DOMAIN}"
}

# ---------------------------------------------------------
# 2. 라우트
# ---------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return "OK", 200

# ---------------------------------------------------------
# [신규] V-World 연동 상태 진단 API
# ---------------------------------------------------------
@app.route('/api/diagnose')
def diagnose_vworld():
    """V-World API 키와 도메인 설정이 올바른지 테스트하는 전용 함수"""
    url = "https://api.vworld.kr/req/address"
    # 테스트용 파라미터 (서울시청)
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
        "domain": MY_DOMAIN,
        "format": "json"
    }
    
    try:
        # 1. 요청 정보 출력
        print(f"[Diagnose] Requesting V-World with Referer: {COMMON_HEADERS['Referer']}", file=sys.stdout)
        
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        # 2. 응답 상태 및 본문 확인
        result = {
            "my_server_domain": MY_DOMAIN,
            "vworld_status_code": resp.status_code,
            "vworld_response_body": resp.text,  # 여기에 "인증 실패" 같은 진짜 이유가 들어있음
            "used_headers": dict(resp.request.headers) # 실제 전송된 헤더 확인
        }
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

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
            "domain": MY_DOMAIN,
            "format": "json"
        }

        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        # V-World 에러 메시지 그대로 전달 (디버깅용)
        if resp.status_code != 200:
            print(f"[Data Error] V-World Response: {resp.text}", file=sys.stderr)
            return jsonify({
                "status": "VWORLD_ERROR", 
                "http_code": resp.status_code,
                "vworld_message": resp.text 
            }), 500 # 프론트엔드에서 에러 내용을 볼 수 있게 500으로 던짐 (내용은 JSON)
            
        try:
            return jsonify(resp.json())
        except ValueError:
            # JSON이 아닌 응답(XML 에러 등)이 왔을 때
            return jsonify({
                "status": "PARSING_ERROR",
                "message": "V-World returned non-JSON data. Check API Key/Domain.",
                "raw_response": resp.text
            }), 500

    except Exception as e:
        print(f"[Data Exception] {str(e)}", file=sys.stderr)
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
            "domain": MY_DOMAIN,
            "format": "json"
        }
        
        print(f"[Address] Searching: {query}", file=sys.stdout)
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        # 에러 발생 시 V-World가 보낸 진짜 메시지 확인
        if resp.status_code != 200:
            print(f"[Address Error] V-World Response: {resp.text}", file=sys.stderr)
            return jsonify({
                "status": "VWORLD_ERROR", 
                "http_code": resp.status_code,
                "vworld_message": resp.text
            }), 500

        try:
            data = resp.json()
            # 검색 결과 없음 처리 (지번 검색 재시도)
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 print("[Address] Retry with parcel type", file=sys.stdout)
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
                 if resp_p.status_code == 200:
                     try:
                         data = resp_p.json()
                     except: pass
            
            return jsonify(data)

        except ValueError:
            print(f"[Address Parsing Error] Raw: {resp.text}", file=sys.stderr)
            return jsonify({
                "status": "PARSING_ERROR",
                "message": "V-World response is not JSON. Likely authentication error.",
                "raw_response": resp.text
            }), 500
            
    except Exception as e:
        print(f"[Address Exception] {str(e)}", file=sys.stderr)
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) 및 6. 조례 정보
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    pnu = request.args.get('pnu')
    if not pnu: return jsonify({"result": "FAIL", "msg": "PNU 누락"})
    return jsonify({"result": "OK", "msg": "Logic Connected"})

@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    return jsonify({
        "result": "OK", 
        "region": "조회 지역", 
        "law_name": "도시계획 조례",
        "articles": ["도로 및 주거지로부터 일정 거리 이격 필요(지자체 조례 확인)"],
        "link": "https://www.law.go.kr"
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
