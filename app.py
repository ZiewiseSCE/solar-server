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

# SSL 경고 메시지 억제 (로그 정리)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ---------------------------------------------------------
# 1. 설정 (API 키 및 도메인)
# ---------------------------------------------------------
# V-World API 키 (새로 발급받은 키 적용됨)
VWORLD_KEY = os.environ.get("VWORLD_KEY", "2ABF83F5-5D52-322D-B58C-6B6655D1CB0F")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# [중요] V-World 관리자 페이지 '서비스 URL'에 등록된 주소와 정확히 일치해야 함
MY_DOMAIN_URL = "https://solar-server-jszy.onrender.com"

# 세션 설정: 연결 재사용 및 자동 재시도
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1, # 1초 간격으로 재시도
    status_forcelist=[500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("https://", adapter)
session.mount("http://", adapter)

# 공통 헤더: 브라우저처럼 보이게 하고 Referer 인증 통과
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
        "domain": MY_DOMAIN_URL, 
        "format": "json"
    }
    
    try:
        print(f"[Diagnose] Sending request to V-World...", file=sys.stdout)
        # 타임아웃 5초, SSL 검증 무시
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        return jsonify({
            "status": "CHECK_COMPLETED",
            "vworld_http_status": resp.status_code,
            "response_sample": resp.text[:300], # 응답 내용 앞부분 확인
            "sent_domain_param": MY_DOMAIN_URL,
            "sent_referer_header": COMMON_HEADERS["Referer"]
        })
        
    except Exception as e:
        return jsonify({"status": "DIAGNOSE_FAILED", "error": str(e)})

# ---------------------------------------------------------
# 3. V-World 데이터 프록시 (건물/지적도)
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

        # 타임아웃 5초
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        # V-World가 거부한 경우 (인증 오류 등)
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
        return jsonify({"status": "ERROR", "message": "V-World API Timeout (5s)"}), 504
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
        
        print(f"[Address] Searching: {query}", file=sys.stdout)
        
        # 1차 시도 (도로명)
        resp = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
        
        if resp.status_code != 200:
            error_body = resp.text[:500] if resp.text else "No content"
            print(f"[Address API Error] Status: {resp.status_code}, Body: {error_body}", file=sys.stderr)
            return jsonify({
                "status": "VWORLD_ERROR", 
                "http_code": resp.status_code,
                "message": "V-World API Error",
                "details": error_body
            }), resp.status_code

        try:
            data = resp.json()
            # 검색 결과 없음 처리 (지번 검색 재시도)
            if data.get("response", {}).get("status") == "NOT_FOUND":
                 print("[Address] Retry with parcel type...", file=sys.stdout)
                 params["type"] = "parcel"
                 resp_p = session.get(url, params=params, headers=COMMON_HEADERS, timeout=5, verify=False)
                 if resp_p.status_code == 200:
                     try:
                         data = resp_p.json()
                     except: pass
            
            return jsonify(data)

        except ValueError:
            # JSON 파싱 실패 시 원본 텍스트 반환 (디버깅용)
            raw_text = resp.text[:500] if resp.text else "Empty response"
            print(f"[Address Parsing Error] Raw: {raw_text}", file=sys.stderr)
            return jsonify({
                "status": "PARSING_ERROR",
                "message": "V-World returned non-JSON response. Check API Key/Domain.",
                "raw_response": raw_text
            }), 500

    except RetryError:
        print("[Address] Max Retries Exceeded", file=sys.stderr)
        return jsonify({
            "status": "EXTERNAL_ERROR", 
            "message": "V-World API is currently unstable (502 Bad Gateway)."
        }), 502
    except Timeout:
        print("[Address] Timeout", file=sys.stderr)
        return jsonify({"status": "TIMEOUT", "message": "V-World API took too long (5s)."}), 504
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
