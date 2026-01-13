import os
import requests
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Render.com 환경 변수에서 키를 가져옵니다. (없으면 기본값 사용)
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")

@app.route('/')
def home():
    # templates/index.html 파일을 보여줍니다.
    return render_template('index.html')

# [API 1] V-World 주소 검색 프록시
@app.route('/api/vworld/address')
def proxy_address():
    query = request.args.get('address')
    # 백엔드에서 V-World로 요청 (CORS 해결)
    url = "https://api.vworld.kr/req/address"
    params = {
        "service": "address",
        "request": "getcoord",
        "version": "2.0",
        "crs": "epsg:4326",
        "address": query,
        "refine": "true",
        "simple": "false",
        "type": "ROAD",
        "key": VWORLD_KEY
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

# [API 2] V-World 데이터(건물/토지) 조회 프록시
@app.route('/api/vworld/data')
def proxy_data():
    layer = request.args.get('data', 'LT_C_SPBD')
    geom_filter = request.args.get('geomFilter')
    
    url = "https://api.vworld.kr/req/data"
    params = {
        "service": "data",
        "request": "GetFeature",
        "data": layer,
        "key": VWORLD_KEY,
        "geomFilter": geom_filter,
        "size": "200",
        "domain": "render_app"
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

# [API 3] 한전 선로 용량 조회 프록시 (핵심 기능)
@app.route('/api/kepco')
def proxy_kepco():
    pnu = request.args.get('pnu')
    if not pnu or len(pnu) < 19:
        return jsonify({"result": "FAIL", "msg": "PNU 오류"})

    # PNU 파싱
    legaldong = pnu[0:10]
    land_type = pnu[10:11]
    bunji = int(pnu[11:15])
    ho = int(pnu[15:19])
    
    # URL 인코딩 해제된 키 사용
    service_key = requests.utils.unquote(KEPCO_KEY)

    url = "https://apis.data.go.kr/1230000/KepcoSystem/getCapacity"
    params = {
        "serviceKey": service_key,
        "legaldongCode": legaldong,
        "bunji": bunji,
        "ho": ho,
        "landType": land_type,
        "numOfRows": 1,
        "pageNo": 1,
        "type": "json"
    }

    try:
        # verify=False로 공공데이터포털 인증서 문제 해결
        resp = requests.get(url, params=params, verify=False, timeout=10)
        try:
            data = resp.json()
            return jsonify(data)
        except:
            return jsonify({"result": "FAIL", "msg": "API 응답 오류(XML)"})
    except Exception as e:
        return jsonify({"result": "FAIL", "msg": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)