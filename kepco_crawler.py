import requests
import datetime
import json

class KepcoCapacityCrawler:
    """
    한전 분산전원 연계정보 사이트(online.kepco.co.kr)의 비공개 API를 역이용하여
    실시간 선로 용량을 조회하는 크롤러입니다.
    """
    BASE_URL = "https://online.kepco.co.kr/ew/api/energy"
    # 브라우저인 척 위장하기 위한 헤더
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Content-Type": "application/json",
        "Referer": "https://online.kepco.co.kr/EWM104D04"
    }

    def __init__(self):
        # 세션 유지 (Cookie, JSESSIONID 자동 관리)
        self.session = requests.Session()
        self.session.headers.update(self.HEADERS)

    def get_capacity(self, address_str):
        """
        주소 문자열(예: '대구광역시 중구 동성로3가')을 받아 실시간 용량을 조회합니다.
        """
        # 1. 주소 파싱 (공백 기준 단순 분리)
        parts = address_str.split()
        if len(parts) < 3:
            return None, "주소 형식이 올바르지 않습니다. (예: 대구광역시 중구 동성로3가)"
        
        sido_name = parts[0] # 예: 대구광역시
        sigg_name = parts[1] # 예: 중구
        dong_name = parts[2] # 예: 동성로3가

        try:
            # Step 1: 시/도 코드 가져오기 (selectDo)
            sido_code = self._fetch_code(f"{self.BASE_URL}/selectDo", {}, "dma_Dolist", sido_name)
            if not sido_code: return None, f"시/도({sido_name}) 식별 실패"

            # Step 2: 시/군/구 코드 가져오기 (selectGu)
            # Payload: {dma_viewMap: {Do: "27"}}
            full_sigg_code = self._fetch_code(
                f"{self.BASE_URL}/selectGu", 
                {"dma_viewMap": {"Do": sido_code}}, 
                "dma_Gulist", 
                sigg_name
            )
            if not full_sigg_code: return None, f"시/군/구({sigg_name}) 식별 실패"
            
            # API 특성상 subSt154에는 뒷자리 3글자(또는 110)만 쓰지만, selectLiDong엔 전체가 필요함
            # 대구(27) + 중구(110) = 27110
            real_sigg_code = full_sigg_code[len(sido_code):] # 앞의 시도코드 제외한 뒷부분

            # Step 3: 읍/면/동 코드 가져오기 (selectLiDong)
            # Payload: {dma_viewMap: {Do: "27110"}}
            # 주의: 응답의 NSDIP_ALL_ADDR_CD(법정동코드)와 실제 subSt154가 쓰는 EMD_CD가 다를 수 있음
            dong_item = self._fetch_item(
                f"{self.BASE_URL}/selectLiDong",
                {"dma_viewMap": {"Do": full_sigg_code}},
                "dma_Silist",
                dong_item_name=dong_name
            )
            if not dong_item: return None, f"읍/면/동({dong_name}) 식별 실패"

            # 여기서 EMD_CD를 찾아야 함. 보통 응답 데이터 안에 숨겨져 있거나 NSDIP 코드의 끝자리 활용
            # (발견하신 데이터에서는 119였으나, 코드 규칙상 NSDIP의 끝자리일 수도 있음)
            # 우선순위: API 응답 내 'EMD_CD' > 'NSDIP_ALL_ADDR_CD'의 뒤 3자리
            emd_code = dong_item.get("EMD_CD") or dong_item.get("NSDIP_ALL_ADDR_CD", "")[-3:]

            # Step 4: 최종 용량 조회 (subSt154) !!!
            return self._fetch_final_capacity(sido_code, real_sigg_code, emd_code)

        except Exception as e:
            return None, f"한전 서버 통신 오류: {str(e)}"

    def _fetch_code(self, url, payload, list_key, match_name):
        """API 호출 후 이름이 일치하는 항목의 코드를 반환"""
        res = self.session.post(url, json=payload, timeout=5)
        if res.status_code != 200: return None
        for item in res.json().get(list_key, []):
            if match_name in item.get("ADDR_NM", ""):
                return item.get("NSDIP_ALL_ADDR_CD")
        return None

    def _fetch_item(self, url, payload, list_key, dong_item_name):
        """API 호출 후 이름이 일치하는 항목 전체(Dict)를 반환"""
        res = self.session.post(url, json=payload, timeout=5)
        if res.status_code != 200: return None
        for item in res.json().get(list_key, []):
            if dong_item_name in item.get("ADDR_NM", ""):
                return item
        return None

    def _fetch_final_capacity(self, sido, sigg, emd):
        url = f"{self.BASE_URL}/subSt154"
        current_year = str(datetime.datetime.now().year)
        
        # 찾아내신 Payload 구조 그대로 사용
        payload = {
            "dma_subSt154": {
                "sidoCode": sido,
                "siggCode": sigg,
                "emdCode": emd,
                "year": current_year
            }
        }
        
        res = self.session.post(url, json=payload, timeout=5)
        data = res.json()
        
        items = data.get("dma_subSt154list", [])
        if not items:
            return None, "해당 지역 변전소 정보 없음"

        # 첫 번째 변전소 정보 사용
        target = items[0]
        
        # PSSMINOVPLSCPCT: 찾아내신 '여유 용량' 필드 (추정)
        margin_mw = target.get("PSSMINOVPLSCPCT", 0) 
        subst_name = target.get("PSPWPNM", "미확인")
        
        result_text = f"{margin_mw} MW (변전소: {subst_name})"
        return {
            "capacity": result_text,
            "raw_data": target
        }, None