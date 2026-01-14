# -*- coding: utf-8 -*-
import os
import requests
import xml.etree.ElementTree as ET
import re
import sys
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# 1. 설정
# ---------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")
MY_DOMAIN = "solar-server-jszy.onrender.com"

# 세션 객체 생성 (연결 재사용으로 안정성 향상)
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Referer": f"https://{MY_DOMAIN}",
    "Origin": f"https://{MY_DOMAIN}"
})

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

        # 타임아웃을 5초로 줄여서 502 발생 전 처리
        resp = session.get(url, params=params, timeout=5, verify=False)
        
        if resp.status_code != 200:
            print(f"[Data Error] Status: {resp.status_code}, Body: {resp.text[:100]}", file=sys.stderr)
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World API Error {resp.status_code}",
                "details": resp.text[:200]
            }), resp.status_code
            
        return jsonify(resp.json())

    except requests.exceptions.Timeout:
        print("[Data Timeout] V-World took too long", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": "V-World API Timeout (5s)"}), 504
    except Exception as e:
        print(f"[Data Exception] {str(e)}", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 4. V-World 주소 검색 프록시
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    try:
        query = request.args.get('address')
        if not query:
            return jsonify({"status": "ERROR", "message": "Missing address"}), 400

        print(f"[Address Request] Query: {query}", file=sys.stdout)

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
        
        # 1차 시도 (도로명)
        resp = session.get(url, params=params, timeout=5, verify=False)
        
        if resp.status_code != 200:
            print(f"[Address Error] Status: {resp.status_code}, Body: {resp.text[:100]}", file=sys.stderr)
            return jsonify({
                "status": "ERROR", 
                "message": f"V-World API rejected (Status {resp.status_code})",
                "details": resp.text[:200]
            }), resp.status_code

        try:
            data = resp.json()
        except:
            print(f"[Address JSON Error] Body: {resp.text[:100]}", file=sys.stderr)
            return jsonify({"status": "ERROR", "message": "Invalid JSON", "raw": resp.text[:200]}), 500

        # 2차 시도 (지번 검색으로 재시도)
        if "response" in data and data["response"].get("status") == "NOT_FOUND":
             print("[Address Retry] Switching to parcel type", file=sys.stdout)
             params["type"] = "parcel"
             resp_p = session.get(url, params=params, timeout=5, verify=False)
             if resp_p.status_code == 200:
                 try:
                     data = resp_p.json()
                 except: pass
                 
        return jsonify(data)

    except requests.exceptions.Timeout:
        print("[Address Timeout] V-World took too long", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": "V-World API Timeout (5s)"}), 504
    except Exception as e:
        print(f"[Address Exception] {str(e)}", file=sys.stderr)
        return jsonify({"status": "ERROR", "message": str(e)}), 500

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
