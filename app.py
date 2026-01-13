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
# 3. V-World 데이터 프록시
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
        "domain": "render_app"
    }

    try:
        resp = requests.get(url, params=params, timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 4. V-World 주소 검색 프록시
# ---------------------------------------------------------
@app.route('/api/vworld/address')
def proxy_address():
    query = request.args.get('address')
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
        "key": VWORLD_KEY
    }
    
    try:
        resp = requests.get(url, params=params, timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 5. 한전(KEPCO) 선로 용량 프록시
# ---------------------------------------------------------
@app.route('/api/kepco')
def proxy_kepco():
    pnu = request.args.get('pnu')
    if not pnu or len(pnu) < 19:
        return jsonify({"result": "FAIL", "msg": "PNU 오류"})

    legaldong = pnu[0:10]
    land_type = pnu[10:11]
    bunji = int(pnu[11:15])
    ho = int(pnu[15:19])

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
        resp = requests.get(url, params=params, verify=False, timeout=10)
        try:
            return jsonify(resp.json())
        except:
            return resp.text
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

# ---------------------------------------------------------
# 6. 조례 정보 검색 API (국가법령정보센터)
# ---------------------------------------------------------
@app.route('/api/ordinance')
def get_ordinance():
    address = request.args.get('address', '')
    if not address:
        return jsonify({"result": "FAIL", "msg": "주소 정보 없음"})

    # 주소 파싱
    tokens = address.split()
    region_name = ""
    for t in tokens:
        if t.endswith("시") or t.endswith("군"):
            region_name = t
            break
        if t.endswith("구") and len(tokens) > 1:
             idx = tokens.index(t)
             if idx > 0 and tokens[idx-1].endswith("시"):
                 region_name = tokens[idx-1]
                 break
    
    if not region_name:
        region_name = tokens[0] if tokens else ""

    # 조례 검색
    search_keyword = f"{region_name} 도시계획 조례"
    search_url = "http://www.law.go.kr/DRF/lawSearch.do"
    search_params = {
        "OC": LAW_API_ID,
        "target": "ordin",
        "type": "XML",
        "query": search_keyword,
        "display": 5
    }

    try:
        res = requests.get(search_url, params=search_params, timeout=5)
        root = ET.fromstring(res.content)
        
        target_law_id = None
        target_law_name = ""
        
        for law in root.findall(".//law"):
            name = law.find("lawNm").text
            if "도시계획" in name or "개발행위" in name:
                target_law_id = law.find("lawId").text
                target_law_name = name
                break
        
        if not target_law_id:
            first_law = root.find(".//law")
            if first_law is not None:
                target_law_id = first_law.find("lawId").text
                target_law_name = first_law.find("lawNm").text
            else:
                return jsonify({"result": "NONE", "region": region_name, "msg": "조례 없음"})

        # 상세 검색
        detail_url = "http://www.law.go.kr/DRF/lawService.do"
        detail_params = {
            "OC": LAW_API_ID,
            "target": "ordin",
            "type": "XML",
            "ID": target_law_id
        }
        
        det_res = requests.get(detail_url, params=detail_params, timeout=5)
        det_root = ET.fromstring(det_res.content)
        
        relevant_articles = []
        for article in det_root.findall(".//jo"):
            raw_text = "".join(list(article.itertext()))
            if "태양" in raw_text or "발전시설" in raw_text or "이격" in raw_text:
                highlighted = re.sub(r'(\d+(?:m|미터))', r'<span style="color:#f87171; font-weight:bold;">\1</span>', raw_text)
                relevant_articles.append(highlighted)

        if not relevant_articles:
            relevant_articles.append("관련 키워드(태양광/이격) 검색 실패. 원문을 확인하세요.")

        return jsonify({
            "result": "OK",
            "region": region_name,
            "law_name": target_law_name,
            "articles": relevant_articles,
            "link": f"http://www.law.go.kr/ordinSc.do?menuId=0&query={target_law_name}"
        })

    except Exception as e:
        print(f"API Error: {e}")
        return jsonify({"result": "ERROR", "msg": str(e)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
