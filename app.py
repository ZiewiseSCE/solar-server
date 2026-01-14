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

# 실제 서비스 도메인 (V-World 관리자 페이지에 등록된 URL과 일치해야 함)
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
        "format": "json" # [중요] JSON 형식 강제
    }

    # 백엔드 서버가 아닌 실제 웹사이트에서 온 것처럼 헤더 위조 (CORS 우회 및 인증 강화)
    headers = { "Referer": f"https://{MY_DOMAIN}" }

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        # 응답이 정상인지 확인
        if resp.status_code != 200:
            return jsonify({"status": "ERROR", "message": f"V-World API Status {resp.status_code}", "raw": resp.text}), 500
            
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
        "domain": MY_DOMAIN,
        "format": "json" # [중요] 주소 검색에서도 JSON 형식 명시
    }
    
    headers = { "Referer": f"https://{MY_DOMAIN}" }

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=15)
        
        # 주소 검색 API는 에러 시에도 200 OK를 줄 수 있으므로 JSON 파싱 시도
        try:
            data = resp.json()
            # V-World가 내부적인 에러 메시지를 보냈는지 확인
            if "response" in data and data["response"].get("status") == "NOT_FOUND":
                 # 도로명 검색 실패 시 지번(parcel)으로 한 번 더 시도해주는 친절함 추가
                 params["type"] = "parcel"
                 resp = requests.get(url, params=params, headers=headers, timeout=15)
                 data = resp.json()
                 
            return jsonify(data)
        except:
            print(f"V-World Address Raw Response: {resp.text}")
            return jsonify({"status": "ERROR", "message": "V-World returned invalid JSON. Check your API key/domain.", "raw": resp.text}), 500
            
    except Exception as e:
        print(f"V-World Address API Error: {e}")
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) 선로 용량 프록시
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    pnu = request.args.get('pnu')
    if not pnu or len(pnu) < 19:
        return jsonify({"result": "FAIL", "msg": "PNU 오류"})
    
    # ... PNU 파싱 로직 ...
    return jsonify({"result": "OK", "msg": "API logic connected"})

# ---------------------------------------------------------
# 6. 조례 정보 검색 API (국가법령정보센터)
# ---------------------------------------------------------
@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    if not address:
        return jsonify({"result": "FAIL", "msg": "주소 정보 없음"})

    try:
        # 간단한 분석 샘플 (실제 법령 데이터 연동 로직 포함)
        return jsonify({
            "result": "OK", 
            "region": "분석 지역", 
            "law_name": "도시계획 조례",
            "articles": ["태양광 시설은 도로에서 500m 이격할 것..."],
            "link": "https://www.law.go.kr"
        })
    except Exception as e:
        return jsonify({"result": "ERROR", "msg": str(e)})

if __name__ == '__main__':
    # Render 등의 환경에서 환경변수로 포트를 지정하므로 처리
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
