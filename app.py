# -*- coding: utf-8 -*-
import os
import requests
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
# 1. 설정 (API 키 강제 적용)
# ---------------------------------------------------------
# [수정] 환경변수보다 코드가 우선하도록 순서를 바꿈 (확실한 해결을 위해)
# 만약 Render 환경변수에 옛날 키가 있어도, 이 코드는 무조건 새 키를 씁니다.
VWORLD_KEY = "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F"

# 나머지 설정
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")
MY_DOMAIN_HOST = "solar-server-jszy.onrender.com"
MY_DOMAIN_URL = f"https://{MY_DOMAIN_HOST}"

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

# 헤더 설정
COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": MY_DOMAIN_URL,
    "Origin": MY_DOMAIN_URL
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
        print(f"[Diagnose] Key used: {VWORLD_KEY[:8]}...", file=sys.stdout)
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        return jsonify({
            "status": "CHECK_COMPLETED",
            "key_used_prefix": VWORLD_KEY[:8], # 실제 사용된 키 앞부분 확인용
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

        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        if resp.status_code != 200:
            print(f"[Data API Error] Status: {resp.status_code}, Body: {resp.text[:200]}", file=sys.stderr)
            return jsonify({
                "status": "VWORLD_ERROR", 
                "http_code": resp.status_code,
                "message": "V-World API rejected request",
                "details": resp.text[:500]
            }), resp.status_code
            
        return jsonify(resp.json())

    except RetryError:
        return jsonify({"status": "ERROR", "message": "V-World Server Unstable (Retry Failed)"}), 502
    except Timeout:
        return jsonify({"status": "ERROR", "message": "V-World API Timeout"}), 504
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
            "domain": MY_DOMAIN_URL,
            "format": "json"
        }
        
        print(f"[Address] Key: {VWORLD_KEY[:8]}... Query: {query}", file=sys.stdout)
        
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
        
        if resp.status_code != 200:
            error_body = resp.text[:500] if resp.text else "No content"
            print(f"[Address API Error] {resp.status_code} {error_body}", file=sys.stderr)
            return jsonify({
                "status": "VWORLD_ERROR", 
                "http_code": resp.status_code,
                "message": "V-World API Error",
                "details": error_body
            }), resp.status_code

        try:
            data = resp.json()
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=10, verify=False)
                 if resp_p.status_code == 200:
                     try: data = resp_p.json()
                     except: pass
            return jsonify(data)

        except ValueError:
            raw_text = resp.text[:500] if resp.text else "Empty response"
            return jsonify({
                "status": "PARSING_ERROR",
                "message": "V-World returned non-JSON response.",
                "raw_response": raw_text
            }), 500

    except Exception as e:
        return jsonify({"status": "SERVER_ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 5. 기타 API
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    return jsonify({"result": "OK", "msg": "Logic Connected"})

@app.route('/api/ordinance')
def get_ordinance():
    return jsonify({"result": "OK", "articles": ["이격거리 규제 정보..."]})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
