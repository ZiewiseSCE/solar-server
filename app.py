# -*- coding: utf-8 -*-
import os
import requests
import sys
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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
# 5. 기타 API (한전, 조례 등)
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    # 한전 API 키가 없어도 에러가 나지 않도록 더미 응답
    return jsonify({"result": "OK", "msg": "Logic Connected"})

@app.route('/api/ordinance')
def get_ordinance():
    return jsonify({"result": "OK", "articles": ["조례 정보 확인 필요"]})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
