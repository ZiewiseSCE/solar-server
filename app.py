# -*- coding: utf-8 -*-
import os
import requests
import xml.etree.ElementTree as ET
import re
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# 모든 도메인에서의 요청 허용 (CORS 해결)
CORS(app)

# ---------------------------------------------------------
# 1. API 키 및 도메인 설정
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# V-World 관리자 페이지에 등록된 '활용 URL'과 정확히 일치해야 합니다.
MY_DOMAIN = "solar-server-jszy.onrender.com"

# 공통 헤더 설정 (브라우저처럼 보이게 하여 차단 방지)
COMMON_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": f"https://{MY_DOMAIN}",
    "Origin": f"https://{MY_DOMAIN}"
}

# ---------------------------------------------------------
# 2. 라우트 설정
# ---------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return "OK", 200

# ---------------------------------------------------------
# 3. V-World 데이터 프록시 (건물/지적도 데이터)
# ---------------------------------------------------------
@app.route('/api/vworld/data')
def proxy_data():
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

    try:
        # timeout을 늘리고 SSL 검증 우회, 브라우저 헤더 추가
        resp = requests.get(url, params=params, headers=COMMON_HEADERS, timeout=20, verify=False)
        
        if resp.status_code != 200:
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World Data API rejected (Status {resp.status_code})",
                "details": resp.text[:500]
            }), resp.status_code
            
        return jsonify(resp.json())
    except Exception as e:
        print(f"Proxy Data Error: {str(e)}")
        return jsonify({"status": "ERROR", "message": f"Server side error: {str(e)}"}), 500

# ---------------------------------------------------------
# 4. V-World 주소 검색 프록시 (주소 -> 좌표)
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
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
    
    try:
        resp = requests.get(url, params=params, headers=COMMON_HEADERS, timeout=20, verify=False)
        
        if resp.status_code != 200:
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World Address API rejected (Status {resp.status_code})",
                "details": resp.text[:500]
            }), resp.status_code

        try:
            data = resp.json()
            # 검색 결과가 없을 경우 지번(parcel)으로 자동 재시도
            if data.get("response", {}).get("status") == "NOT_FOUND" and params["type"] == "road":
                params["type"] = "parcel"
                resp_p = requests.get(url, params=params, headers=COMMON_HEADERS, timeout=20, verify=False)
                if resp_p.status_code == 200:
                    data = resp_p.json()
            return jsonify(data)
        except Exception as parse_err:
            return jsonify({
                "status": "ERROR", 
                "message": "Failed to parse V-World JSON response",
                "raw": resp.text[:200]
            }), 500
            
    except Exception as e:
        print(f"Proxy Address Error: {str(e)}")
        return jsonify({"status": "ERROR", "message": f"Internal server error: {str(e)}"}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) 및 6. 조례 정보 (기능 유지)
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
    # Render 환경 PORT 대응
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
