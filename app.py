# -*- coding: utf-8 -*-
import os
import requests
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
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# [중요] V-World 관리자 페이지 '서비스 URL'에 등록된 주소와 일치
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

        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        if resp.status_code != 200:
            print(f"[Data Error] {resp.status_code} {resp.text[:100]}", file=sys.stderr)
            return jsonify({
                "status": "VWORLD_ERROR", 
                "message": f"V-World Error {resp.status_code}",
                "details": resp.text
            }), resp.status_code
            
        return jsonify(resp.json())

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
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        # 에러 응답 처리
        if resp.status_code != 200:
            print(f"[Address Error] {resp.status_code} {resp.text[:100]}", file=sys.stderr)
            # 프론트엔드가 JSON으로 파싱할 수 있도록 항상 JSON 반환
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World API Error ({resp.status_code})",
                "details": resp.text[:200]
            }), 200 # 200으로 보내서 프론트에서 err check 하도록 유도

        try:
            data = resp.json()
            # 검색 결과 없음 -> 지번 검색 재시도
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 print("[Address] Retry parcel...", file=sys.stdout)
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
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
            }), 200

    except Exception as e:
        print(f"[Address Exception] {str(e)}", file=sys.stderr)
        # 절대 500 HTML 페이지를 내보내지 않고 JSON 에러 반환
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 200

# ---------------------------------------------------------
# 5. 기타 API
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    return jsonify({"result": "OK", "msg": "Logic Connected"})

@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    return jsonify({
        "result": "OK", 
        "region": "조회 지역", 
        "law_name": "도시계획 조례",
        "articles": ["도로 및 주거지로부터 이격 거리 확인 필요"],
        "link": "https://www.law.go.kr"
    })

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
