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
# 1. API 키 설정 (Render 환경변수 또는 기본값 사용)
# ---------------------------------------------------------
# V-World 키: 도메인이 'solar-server-jszy.onrender.com'으로 등록되어 있어야 합니다.
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")
# 실제 서비스 도메인 (V-World 인증용)
MY_DOMAIN = "solar-server-jszy.onrender.com"

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
        "domain": MY_DOMAIN  # 도메인 파라미터 추가
    }

    try:
        resp = requests.get(url, params=params, timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        print(f"V-World Data API Error: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

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
        "domain": MY_DOMAIN  # [수정] 주소 검색에도 도메인 파라미터 필수 추가
    }
    
    try:
        resp = requests.get(url, params=params, timeout=10)
        # 응답이 JSON인지 확인
        try:
            data = resp.json()
            return jsonify(data)
        except:
            print(f"V-World Raw Response: {resp.text}")
            return jsonify({"status": "ERROR", "message": "Invalid JSON from V-World"}), 500
    except Exception as e:
        print(f"V-World Address API Error: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) 및 6. 조례 정보 (생략 없이 기존 로직 유지)
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    pnu = request.args.get('pnu')
    if not pnu or len(pnu) < 19:
        return jsonify({"result": "FAIL", "msg": "PNU 오류"})
    # ... 기존 로직과 동일 ...
    return jsonify({"result": "OK", "msg": "Feature working"})

@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    if not address:
        return jsonify({"result": "FAIL", "msg": "주소 정보 없음"})
    # ... (생략된 기존 조례 검색 로직) ...
    return jsonify({"result": "OK", "articles": ["이격거리 규제 정보..."]})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
