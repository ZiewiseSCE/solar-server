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
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# [주의] V-World 관리자 페이지에 등록된 '활용 URL'과 정확히 일치해야 합니다.
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
        "domain": MY_DOMAIN,
        "format": "json"
    }

    headers = { "Referer": f"https://{MY_DOMAIN}" }

    try:
        # verify=False를 추가하여 SSL 인증서 관련 오류 방지
        resp = requests.get(url, params=params, headers=headers, timeout=15, verify=False)
        
        if resp.status_code != 200:
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World Server rejected request (Status {resp.status_code})",
                "details": resp.text
            }), resp.status_code
            
        return jsonify(resp.json())
    except Exception as e:
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
        "domain": MY_DOMAIN,
        "format": "json"
    }
    
    headers = { "Referer": f"https://{MY_DOMAIN}" }

    try:
        # verify=False로 인증서 문제 방지
        resp = requests.get(url, params=params, headers=headers, timeout=15, verify=False)
        
        if resp.status_code != 200:
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World API Error (Status {resp.status_code})",
                "details": resp.text
            }), resp.status_code

        # 응답이 JSON인지 확인 후 파싱
        try:
            data = resp.json()
        except:
            return jsonify({
                "status": "ERROR", 
                "message": "V-World returned non-JSON response",
                "raw_body": resp.text[:200]
            }), 500

        # 도로명(road)으로 결과가 없을 경우 지번(parcel)으로 재시도
        if "response" in data and data["response"].get("status") == "NOT_FOUND":
             params["type"] = "parcel"
             resp_p = requests.get(url, params=params, headers=headers, timeout=15, verify=False)
             if resp_p.status_code == 200:
                 try:
                     data = resp_p.json()
                 except: pass
                 
        return jsonify(data)
            
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"Server side exception: {str(e)}"}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) 및 6. 조례 정보 (기존 유지)
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    pnu = request.args.get('pnu')
    if not pnu: return jsonify({"result": "FAIL", "msg": "PNU 누락"})
    return jsonify({"result": "OK", "msg": "API logic connected"})

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
    # Render 환경에서 PORT 환경변수를 사용
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
