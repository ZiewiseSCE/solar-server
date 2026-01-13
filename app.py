import os
import re
import requests
import json
import xml.etree.ElementTree as ET
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

# [3단계 필수] Google Gemini 라이브러리 설치 필요: pip install google-generativeai
try:
    import google.generativeai as genai
    HAS_GEMINI = True
except ImportError:
    HAS_GEMINI = False
    print("Google Gemini 라이브러리가 없습니다. 'pip install google-generativeai'를 실행하세요.")

app = Flask(__name__)
CORS(app) 

# --------------------------------------------------------------------------
# 환경 변수 설정
# --------------------------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang")

# [3단계] Google Gemini API 키 설정 (사용자가 제공한 키 적용)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyAp-VUCMqmiM5gRNjTMWkF07JJ1IpwOD3o")

# Gemini 설정 초기화
if HAS_GEMINI:
    genai.configure(api_key=GEMINI_API_KEY)

@app.route('/')
def home():
    return render_template('index.html')

# --------------------------------------------------------------------------
# [API 1] V-World 주소 검색 프록시
# --------------------------------------------------------------------------
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
        "type": "ROAD",
        "key": VWORLD_KEY
    }
    try:
        resp = requests.get(url, params=params, timeout=10)
        return jsonify(resp.json())
    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)})

# --------------------------------------------------------------------------
# [API 2] V-World 데이터(건물/토지) 조회 프록시
# --------------------------------------------------------------------------
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

# --------------------------------------------------------------------------
# [API 3] 한전 선로 용량 조회 프록시
# --------------------------------------------------------------------------
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
            data = resp.json()
            return jsonify(data)
        except:
            return jsonify({"result": "FAIL", "msg": "API 응답 오류(XML)"})
    except Exception as e:
        return jsonify({"result": "FAIL", "msg": str(e)})

# --------------------------------------------------------------------------
# [API 4] 국가법령정보센터 조례 검색 및 파싱
# --------------------------------------------------------------------------
def clean_html(raw_html):
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', raw_html)
    return cleantext.strip()

def highlight_distance(text):
    # 패턴: 숫자 + (공백) + m 또는 미터
    pattern = r"(\d+(?:\.\d+)?)\s*(m|미터|M)"
    highlighted_text = re.sub(pattern, r'<mark style="background-color: #ffeb3b; font-weight: bold;">\g<0></mark>', text)
    return highlighted_text

@app.route('/api/law/ordinance')
def check_ordinance():
    region = request.args.get('region')
    if not region:
        return jsonify({"result": "FAIL", "msg": "지역명이 필요합니다."})

    search_url = "http://www.law.go.kr/DRF/lawSearch.do"
    query_text = f"{region} 도시계획 조례"
    
    search_params = {
        "OC": LAW_API_ID,
        "target": "ordin",
        "type": "XML",
        "query": query_text
    }

    try:
        # 1. 조례 목록 검색
        search_resp = requests.get(search_url, params=search_params, timeout=10)
        if search_resp.status_code != 200:
            return jsonify({"result": "FAIL", "msg": "법령 검색 API 응답 오류"})

        root = ET.fromstring(search_resp.content)
        total_cnt = root.find('totalCnt')
        if total_cnt is None or int(total_cnt.text) == 0:
            return jsonify({"result": "FAIL", "msg": f"'{region}'의 도시계획 조례를 찾을 수 없습니다."})

        law_id = root.find('.//law/MST').text
        law_name = root.find('.//law/lawNm').text

        # 2. 본문 상세 조회
        detail_url = "http://www.law.go.kr/DRF/lawService.do"
        detail_params = {
            "OC": LAW_API_ID,
            "target": "ordin",
            "type": "XML",
            "MST": law_id
        }

        detail_resp = requests.get(detail_url, params=detail_params, timeout=15)
        detail_root = ET.fromstring(detail_resp.content)

        relevant_articles = []
        raw_text_for_ai = []

        for jo in detail_root.findall('.//Jo'):
            jo_no = jo.find('JoNo').text if jo.find('JoNo') is not None else ""
            jo_title = jo.find('JoT').text if jo.find('JoT') is not None else ""
            
            full_text = jo_title
            jo_cts = jo.find('JoCts')
            if jo_cts is not None and jo_cts.text:
                full_text += " " + clean_html(jo_cts.text)
            
            for sub in jo.findall('JoSub'):
                sub_cts = sub.find('JoSubCts')
                if sub_cts is not None and sub_cts.text:
                    full_text += " " + clean_html(sub_cts.text)

            if "태양광" in full_text or "발전시설" in full_text:
                processed_text = highlight_distance(full_text)
                relevant_articles.append({
                    "article_no": f"제{jo_no}조",
                    "title": jo_title,
                    "content": processed_text
                })
                # AI 분석을 위해 원본 텍스트 저장
                raw_text_for_ai.append(f"[제{jo_no}조] {full_text}")

        return jsonify({
            "result": "SUCCESS",
            "region": region,
            "law_name": law_name,
            "articles": relevant_articles,
            "ai_context": "\n".join(raw_text_for_ai)
        })

    except Exception as e:
        return jsonify({"result": "FAIL", "msg": f"법령 파싱 오류: {str(e)}"})


# --------------------------------------------------------------------------
# [API 5] Google Gemini AI 이격거리 분석
# --------------------------------------------------------------------------
@app.route('/api/law/ai_analyze', methods=['POST'])
def analyze_law_with_ai():
    if not HAS_GEMINI:
        return jsonify({"result": "FAIL", "msg": "Gemini 라이브러리가 설치되지 않았습니다."})

    # 프론트엔드에서 받은 텍스트
    data = request.json
    context_text = data.get('context', '')

    if not context_text:
        return jsonify({"result": "FAIL", "msg": "분석할 텍스트가 없습니다."})

    try:
        # 무료 모델인 gemini-1.5-flash 사용 (빠르고 정확함)
        model = genai.GenerativeModel('gemini-1.5-flash')

        prompt = f"""
        당신은 도시계획 조례 전문가입니다. 아래 제공된 조례 텍스트를 분석하여 태양광 발전시설의 이격거리 규제를 찾아내세요.

        [분석할 텍스트]
        {context_text}

        [지시사항]
        1. '도로'와 '주거지(주택)'에 대한 이격거리를 찾아 미터(m) 단위 숫자로 추출하세요.
        2. 조건부(예: 10호 이상, 미만 등)가 있다면 가장 큰(보수적인) 숫자를 선택하세요.
        3. 해당 내용을 찾을 수 없으면 0으로 표시하세요.
        4. 반드시 아래의 JSON 형식으로만 응답하세요. (마크다운이나 추가 설명 없이 순수 JSON만)

        [JSON 출력 형식]
        {{
            "road_distance": 숫자,
            "housing_distance": 숫자,
            "summary": "한 줄 요약 (예: 도로에서 200m, 주거지에서 100m 이내 입지 불가)"
        }}
        """

        response = model.generate_content(prompt)
        
        # Gemini가 가끔 ```json ... ``` 형태의 마크다운을 포함할 수 있으므로 제거
        cleaned_text = response.text.replace("```json", "").replace("```", "").strip()
        
        # JSON 변환
        result_json = json.loads(cleaned_text)
        
        return jsonify({"result": "SUCCESS", "data": result_json})

    except Exception as e:
        return jsonify({"result": "FAIL", "msg": f"Gemini 분석 오류: {str(e)}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### 필수 확인 사항
1.  **라이브러리 설치:** 서버 터미널에서 아래 명령어를 꼭 실행해주세요.
    ```bash
    pip install google-generativeai
