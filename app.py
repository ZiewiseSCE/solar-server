import os
import re
import requests
import xml.etree.ElementTree as ET
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
# 보안을 위해 특정 도메인만 허용하는 것이 좋으나, 개발 단계에서는 전체 허용
CORS(app) 

# --------------------------------------------------------------------------
# 환경 변수 설정 (Render.com 등 배포 환경에서 설정 필요)
# --------------------------------------------------------------------------
VWORLD_KEY = os.environ.get("VWORLD_KEY", "8D526307-78EE-3281-8AB3-0D36115D17C3")
KEPCO_KEY = os.environ.get("KEPCO_KEY", "19BZ8JWfae590LQCR6f2tEIyyD94wBBYEzY3UpYp")

# [국가법령정보센터] Open API ID (회원가입 후 발급받은 아이디)
# 실제 서비스 시 https://open.law.go.kr/ 에서 신청 필요
LAW_API_ID = os.environ.get("LAW_API_ID", "kennyyang") # 사용자 키 적용

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
# [API 4 - 신규] 국가법령정보센터 조례 검색 및 이격거리 파싱
# --------------------------------------------------------------------------
def clean_html(raw_html):
    """HTML 태그 제거 정규식"""
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', raw_html)
    return cleantext.strip()

def highlight_distance(text):
    """
    [2단계 기능] 정규식을 사용하여 거리 제한(미터) 관련 텍스트를 찾아 하이라이팅 태그를 입힘
    패턴: 숫자 + (공백) + m 또는 미터
    """
    # 패턴: 숫자(소수점 포함) 뒤에 m 또는 미터가 오는 경우 (예: 200m, 50 미터)
    pattern = r"(\d+(?:\.\d+)?)\s*(m|미터|M)"
    
    # 해당 패턴을 찾아서 <mark> 태그로 감싸서 반환 (HTML로 프론트에 전달)
    # \g<0>은 매칭된 전체 문자열을 의미
    highlighted_text = re.sub(pattern, r'<mark style="background-color: #ffeb3b; font-weight: bold;">\g<0></mark>', text)
    return highlighted_text

@app.route('/api/law/ordinance')
def check_ordinance():
    # 프론트엔드에서 region(시/군/구 이름, 예: 여주시, 강릉시)을 받음
    region = request.args.get('region')
    if not region:
        return jsonify({"result": "FAIL", "msg": "지역명이 필요합니다."})

    # 1. 국가법령정보센터 검색 API URL (자치법규 목록 검색)
    # 태양광 이격거리는 보통 '도시계획 조례'에 포함되어 있음
    search_url = "http://www.law.go.kr/DRF/lawSearch.do"
    query_text = f"{region} 도시계획 조례"
    
    search_params = {
        "OC": LAW_API_ID,
        "target": "ordin",  # 자치법규
        "type": "XML",
        "query": query_text
    }

    try:
        # 1-1. 조례 목록 검색
        search_resp = requests.get(search_url, params=search_params, timeout=10)
        
        if search_resp.status_code != 200:
            return jsonify({"result": "FAIL", "msg": "법령 검색 API 응답 오류"})

        # XML 파싱하여 상세 법령 ID(MST) 추출
        root = ET.fromstring(search_resp.content)
        
        # 검색 결과가 없는 경우 처리
        total_cnt = root.find('totalCnt')
        if total_cnt is None or int(total_cnt.text) == 0:
            return jsonify({"result": "FAIL", "msg": f"'{region}'의 도시계획 조례를 찾을 수 없습니다."})

        # 첫 번째 검색 결과의 ID 사용 (가장 정확도 높음)
        law_id = root.find('.//law/MST').text
        law_name = root.find('.//law/lawNm').text

        # 2. 자치법규 본문 상세 조회 API
        detail_url = "http://www.law.go.kr/DRF/lawService.do"
        detail_params = {
            "OC": LAW_API_ID,
            "target": "ordin",
            "type": "XML",
            "MST": law_id
        }

        detail_resp = requests.get(detail_url, params=detail_params, timeout=15)
        detail_root = ET.fromstring(detail_resp.content)

        # 3. 조항(Article) 필터링 및 데이터 가공
        # '태양광' 또는 '발전시설'이라는 단어가 포함된 조항만 추출
        relevant_articles = []
        
        # XML 구조: Law -> Jo(조문) -> JoCts(조문내용), JoSub(항)
        for jo in detail_root.findall('.//Jo'):
            jo_no = jo.find('JoNo').text if jo.find('JoNo') is not None else ""
            jo_title = jo.find('JoT').text if jo.find('JoT') is not None else ""
            
            # 조문 내용 합치기 (본문 + 항 내용)
            full_text = jo_title
            
            jo_cts = jo.find('JoCts')
            if jo_cts is not None and jo_cts.text:
                full_text += " " + clean_html(jo_cts.text)
                
            # 하위 항(SubParagraph) 내용도 확인
            for sub in jo.findall('JoSub'):
                sub_cts = sub.find('JoSubCts')
                if sub_cts is not None and sub_cts.text:
                    full_text += " " + clean_html(sub_cts.text)

            # [핵심 로직] 키워드 필터링
            if "태양광" in full_text or "발전시설" in full_text:
                # [2단계] 정규식 하이라이팅 적용
                processed_text = highlight_distance(full_text)
                
                relevant_articles.append({
                    "article_no": f"제{jo_no}조",
                    "title": jo_title,
                    "content": processed_text,  # HTML 태그가 포함된 텍스트
                    "raw_text": full_text       # 나중에 AI 분석용 원본
                })

        return jsonify({
            "result": "SUCCESS",
            "region": region,
            "law_name": law_name,
            "law_url": f"http://www.law.go.kr/lsInfoP.do?lsiSeq=0&efYd=&ancYd=&urlMode=lsInfoP&viewCls=lsInfoP&id={law_id}",
            "articles": relevant_articles,
            "count": len(relevant_articles)
        })

    except Exception as e:
        print(f"Error parsing law API: {str(e)}")
        return jsonify({"result": "FAIL", "msg": f"법령 파싱 중 오류 발생: {str(e)}"})


if __name__ == '__main__':
    # 호스트 0.0.0.0으로 설정하여 외부 접속 허용
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### 코드 주요 변경 사항 및 설명

1.  **국가법령정보센터 API 추가 (`/api/law/ordinance`)**:
    * **검색 로직**: 사용자가 선택한 지역명(예: `여주시`)을 받아 `"{지역명} 도시계획 조례"`로 검색합니다. 태양광 이격거리는 99% 확률로 해당 지자체의 **도시계획 조례** 내의 '개발행위 허가 기준' 별표나 본문에 있습니다.
    * **XML 파싱**: Python 내장 라이브러리인 `xml.etree.ElementTree`를 사용하여 별도의 추가 라이브러리 설치 없이 XML 응답을 처리합니다.

2.  **데이터 가공 및 필터링 (Backend Logic)**:
    * **필터링**: 조례 전체를 프론트엔드로 보내면 데이터가 너무 큽니다. 백엔드에서 `태양광` 또는 `발전시설`이라는 키워드가 포함된 조항(`Jo`)만 리스트(`relevant_articles`)에 담아 보냅니다.
    * **HTML 정제**: `clean_html` 함수를 통해 API 원본 데이터에 섞여 있는 불필요한 태그를 정리합니다.

3.  **정규식 하이라이팅 (2단계 구현)**:
    * `highlight_distance` 함수 추가: `r"(\d+(?:\.\d+)?)\s*(m|미터)"` 정규식을 사용합니다.
    * 텍스트 내에서 "200m", "100 미터" 같은 패턴을 찾으면 `<mark>` 태그로 감싸서 프론트엔드로 전달합니다. 프론트엔드에서는 `innerHTML`로 뿌려주기만 하면 노란색 형광펜 효과가 적용됩니다.

### 사용 시 주의사항 (환경 변수)

Render.com이나 로컬 환경의 `.env`에 다음 키를 반드시 추가해야 합니다.
(국가법령정보센터 아이디가 없다면 테스트가 불가능할 수 있으므로, 임시로 `test` 계정을 사용하거나 직접 가입해야 합니다.)

```bash
LAW_API_ID=본인의_국가법령센터_아이디
