
import os
import re
import time
import math
import json
import statistics
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, List

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# =========================
# Env keys
# =========================
VWORLD_API_KEY = (os.getenv("VWORLD_API_KEY") or "").strip()
KEPCO_KEY = (os.getenv("KEPCO_KEY") or "").strip()
LAW_API_ID = (os.getenv("LAW_API_ID") or "").strip()
GOOGLE_API_KEY = (os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY") or "").strip()

# Public data keys (지원: 두 이름 모두)
DATA_GO_KR_KEY = (os.getenv("DATA_GO_KR_SERVICE_KEY") or os.getenv("DATA_GO_KR_KEY") or "").strip()

# Optional: 공시지가(개별공시지가) 엔드포인트가 조직별로 다를 수 있어 env로 받도록 함
# 예: http://openapi.molit.go.kr/OpenAPI_ToolInstallPackage/service/rest/IndvdLandPriceService/getIndvdLandPriceAttr
OFFICIAL_LAND_PRICE_URL = (os.getenv("OFFICIAL_LAND_PRICE_URL") or "").strip()

# VWorld layer codes are not standardized in your current repo.
# Allow overrides by env; if empty we will still try generic calls and return "확인 필요" gracefully.
VWORLD_LAYER_ZONING = os.getenv("VWORLD_LAYER_ZONING", "").strip()
VWORLD_LAYER_ECO = os.getenv("VWORLD_LAYER_ECO", "").strip()
VWORLD_LAYER_HERITAGE = os.getenv("VWORLD_LAYER_HERITAGE", "").strip()

# Timeouts / retry
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "8"))
HTTP_RETRIES = int(os.getenv("HTTP_RETRIES", "2"))

app = FastAPI(title="Solar Pathfinder API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 배포 시 도메인 제한 권장
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# Request/Response models
# =========================
class AnalyzeRequest(BaseModel):
    address: Optional[str] = Field(default=None, description="사용자가 입력한 주소 (선택)")
    lat: float = Field(..., description="위도")
    lng: float = Field(..., description="경도")
    pnu: Optional[str] = Field(default=None, description="19자리 PNU(가능하면 전달)")
    capacity_kw: Optional[float] = Field(default=None, description="신청/설치 용량(kW) (없으면 1000kW로 가정)")
    # Frontend가 이미 계산한 값을 같이 넘기면 정확도/속도가 크게 개선됨
    slope_deg: Optional[float] = None
    sun_hours: Optional[float] = None
    # setback 비교용(프론트 측정값 또는 추정값)
    dist_road_m: Optional[float] = None
    dist_residential_m: Optional[float] = None
    # 면적(m2) 있으면 토지가격 총액 계산에 사용
    area_m2: Optional[float] = None

class CheckItem(BaseModel):
    status: str  # PASS / WARNING / FAIL
    value: str
    msg: str

class AnalyzeResponse(BaseModel):
    total_score: int
    confidence: str
    check_list: Dict[str, CheckItem]

# =========================
# Helpers
# =========================
def _status_rank(s: str) -> int:
    return {"FAIL": 2, "WARNING": 1, "PASS": 0}.get(s, 1)

def score_from_checks(checks: Dict[str, Dict[str, str]]) -> Tuple[int, float]:
    score = 100
    fail = 0
    warn = 0
    for v in checks.values():
        st = v.get("status", "WARNING")
        if st == "FAIL":
            score -= 30
            fail += 1
        elif st == "WARNING":
            score -= 10
            warn += 1
    score = max(0, min(100, score))

    # confidence heuristic: more unknown/warning lowers confidence
    confidence = 0.985
    confidence -= min(0.35, warn * 0.03 + fail * 0.08)
    confidence = max(0.25, min(0.99, confidence))
    return score, confidence

def _req_json(url: str, params: Dict[str, Any]) -> Dict[str, Any]:
    last_err = None
    for i in range(HTTP_RETRIES + 1):
        try:
            r = requests.get(url, params=params, timeout=HTTP_TIMEOUT)
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
            return r.json()
        except Exception as e:
            last_err = e
            time.sleep(0.4 * (i + 1))
    raise RuntimeError(str(last_err))

def _normalize_text(x: str) -> str:
    return re.sub(r"\s+", " ", (x or "").strip())

# =========================
# (1) VWorld - Zoning (plans parsing)
# =========================
def vworld_getfeature(layer: str, lat: float, lng: float) -> Optional[Dict[str, Any]]:
    if not VWORLD_API_KEY or not layer:
        return None
    url = "https://api.vworld.kr/req/data"
    # Use a small bbox around point
    d = 0.0006
    bbox = f"{lng-d},{lat-d},{lng+d},{lat+d}"
    params = {
        "key": VWORLD_API_KEY,
        "service": "data",
        "request": "GetFeature",
        "data": layer,
        "geomFilter": f"BOX({bbox})",
        "size": 10,
        "page": 1,
        "format": "json",
        "geometry": "false",
        "attribute": "true",
        "crs": "EPSG:4326",
    }
    try:
        j = _req_json(url, params)
        feats = (((j.get("response") or {}).get("result") or {}).get("featureCollection") or {}).get("features") or []
        if feats:
            return feats[0]
        return None
    except Exception:
        return None

def zoning_check(lat: float, lng: float) -> Dict[str, str]:
    # 판정 기준
    pass_kw = ["계획관리지역", "생산관리지역", "자연녹지지역"]
    fail_kw = ["농림지역", "보전녹지지역", "개발제한구역"]

    feat = vworld_getfeature(VWORLD_LAYER_ZONING, lat, lng)
    if not feat:
        return {"status": "WARNING", "value": "확인 필요", "msg": "V-World 용도지역 레이어 연동 필요(레이어 코드 설정 확인)."}
    props = feat.get("properties") or {}
    plans = _normalize_text(str(props.get("plans") or props.get("PLAN") or props.get("plan") or ""))
    val = plans if plans else _normalize_text(json.dumps(props, ensure_ascii=False)[:120])
    if any(k in plans for k in fail_kw):
        return {"status": "FAIL", "value": val or "농림/보전/그린벨트", "msg": "부적합 용도지역이 포함됩니다."}
    if any(k in plans for k in pass_kw):
        return {"status": "PASS", "value": val or "관리/녹지", "msg": "사업 가능 지역(우선 검토)입니다."}
    return {"status": "WARNING", "value": val or "기타", "msg": "해당 용도지역은 추가 검토가 필요합니다."}

# =========================
# (2) Ecology
# =========================
def ecology_check(lat: float, lng: float) -> Dict[str, str]:
    feat = vworld_getfeature(VWORLD_LAYER_ECO, lat, lng)
    if not feat:
        return {"status": "PASS", "value": "등급 없음/확인 필요", "msg": "생태자연도 데이터 확인이 필요합니다(없으면 대체로 적합)."}
    props = feat.get("properties") or {}
    grade = _normalize_text(str(props.get("grade") or props.get("GRD") or props.get("등급") or ""))
    # allow patterns like "1", "1등급"
    if "1" in grade:
        return {"status": "FAIL", "value": f"생태 {grade}", "msg": "1등급 권역은 개발이 제한됩니다."}
    if "2" in grade:
        return {"status": "WARNING", "value": f"생태 {grade}", "msg": "2등급 권역은 조건부 가능(협의 필요)입니다."}
    return {"status": "PASS", "value": f"생태 {grade or '3등급/없음'}", "msg": "생태 규제 리스크가 낮습니다."}

# =========================
# (3) Heritage
# =========================
def heritage_check(lat: float, lng: float) -> Dict[str, str]:
    feat = vworld_getfeature(VWORLD_LAYER_HERITAGE, lat, lng)
    if not feat:
        return {"status": "PASS", "value": "해당 없음/확인 필요", "msg": "문화재 보존관리 데이터 확인이 필요합니다(없으면 적합)."}
    props = feat.get("properties") or {}
    name = _normalize_text(str(props.get("name") or props.get("nm") or props.get("명칭") or "문화재 구역"))
    txt = _normalize_text(" ".join([str(v) for v in props.values()])[:300])
    if "현상변경허용구역" in txt or "보호구역" in txt:
        return {"status": "FAIL", "value": name, "msg": "문화재 보호/현상변경 구역으로 규제 가능성이 높습니다."}
    return {"status": "PASS", "value": name or "문화재 영향 낮음", "msg": "문화재 규제 영향이 낮습니다."}

# =========================
# (4) Setback (LAW + Gemini)
# =========================
def law_fetch_text(keyword: str) -> Optional[str]:
    # DRF: lawSearch.do (법제처)
    # 실제 파라미터는 환경에 따라 다르므로 실패 시 None 반환.
    if not LAW_API_ID:
        return None
    url = "http://www.law.go.kr/DRF/lawSearch.do"
    params = {
        "OC": LAW_API_ID,
        "target": "ordin",
        "type": "XML",
        "query": keyword,
        "display": 1,
    }
    try:
        r = requests.get(url, params=params, timeout=HTTP_TIMEOUT)
        if r.status_code >= 400:
            return None
        return r.text
    except Exception:
        return None

def gemini_extract_setback(text: str) -> Optional[float]:
    # 실제 Gemini 호출은 배포 환경에서 수행.
    # 여기서는 API 호출 실패 시 정규식 기반 최소 추출을 시도.
    if not text:
        return None

    # 1) quick regex: "이격거리 ... 100미터" 등
    m = re.search(r"이격\s*거리[^0-9]{0,30}([0-9]{1,4})\s*(m|미터)", text)
    if m:
        try:
            return float(m.group(1))
        except:
            pass
    return None

def setback_check(address: Optional[str], dist_road_m: Optional[float], dist_res_m: Optional[float]) -> Dict[str, str]:
    # If we don't have measured distance, we can't fail confidently.
    # We'll attempt ordinance lookup, otherwise warn.
    keyword = None
    if address:
        # naive: take first 2 tokens as region
        parts = re.split(r"\s+", address.strip())
        if parts:
            keyword = " ".join(parts[:2]) + " 도시계획 조례"
    law_text = law_fetch_text(keyword) if keyword else None
    req_m = gemini_extract_setback(law_text) if law_text else None

    if req_m is None:
        return {"status": "WARNING", "value": "조례 기준 확인 필요", "msg": "법제처/AI로 이격거리 기준을 자동 추출하지 못했습니다. 수동 확인 필요."}

    # compare with available distance
    # If both distances are provided, use the minimum
    dist_list = [d for d in [dist_road_m, dist_res_m] if isinstance(d, (int, float))]
    if not dist_list:
        return {"status": "WARNING", "value": f"기준 {req_m:.0f}m", "msg": "이격거리 기준은 확보했으나 실제 거리 측정값이 없습니다."}

    actual = min(dist_list)
    if actual < req_m:
        return {"status": "FAIL", "value": f"{actual:.0f}m < {req_m:.0f}m", "msg": "이격거리 기준 미달(부적합)입니다."}
    return {"status": "PASS", "value": f"{actual:.0f}m ≥ {req_m:.0f}m", "msg": "이격거리 기준을 충족합니다."}

# =========================
# (5) KEPCO Grid Capacity (vol3)
# =========================
_kepco_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}  # key -> (ts, payload)

def kepco_fetch(metroCd: str, cityCd: str) -> List[Dict[str, Any]]:
    if not KEPCO_KEY:
        return []
    url = "https://bigdata.kepco.co.kr/openapi/v1/dispersedGeneration.do"
    params = {"metroCd": metroCd, "cityCd": cityCd, "apiKey": KEPCO_KEY, "returnType": "json"}
    last = None
    for i in range(3):
        try:
            r = requests.get(url, params=params, timeout=HTTP_TIMEOUT)
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}")
            j = r.json()
            return j.get("data", []) or []
        except Exception as e:
            last = e
            time.sleep(0.4 * (i + 1))
    return []

def grid_check(pnu: Optional[str], capacity_kw: Optional[float]) -> Dict[str, str]:
    if not pnu or len(pnu) < 5:
        return {"status": "WARNING", "value": "PNU 필요", "msg": "한전 여유용량 조회를 위해 PNU(19자리)가 필요합니다."}
    metroCd = pnu[:2]
    cityCd = pnu[2:5]
    cache_key = f"{metroCd}-{cityCd}"
    now = time.time()
    if cache_key in _kepco_cache and (now - _kepco_cache[cache_key][0]) < 300:
        rows = _kepco_cache[cache_key][1].get("rows", [])
    else:
        rows = kepco_fetch(metroCd, cityCd)
        _kepco_cache[cache_key] = (now, {"rows": rows})

    if not rows:
        return {"status": "WARNING", "value": "확인 필요", "msg": "한전 API 응답이 없거나 일시적으로 실패했습니다. 재시도 필요."}

    # vol3 maximum (DL 여유)
    def _to_float(x):
        try:
            return float(str(x).strip())
        except:
            return 0.0

    max_vol3 = max((_to_float(r.get("vol3")) for r in rows), default=0.0)  # unit: kW? (often kW)
    # Interpret as kW if it looks large; convert to MW for display.
    mw = max_vol3 / 1000.0

    # 판정: 여유용량==0 -> FAIL, >1MW or >= 신청용량 -> PASS, else WARNING
    req_mw = (capacity_kw or 1000.0) / 1000.0
    if max_vol3 == 0:
        return {"status": "FAIL", "value": "여유 0MW", "msg": "여유용량 0: 접속 불가 가능성이 큽니다."}
    if mw >= max(1.0, req_mw):
        return {"status": "PASS", "value": f"여유 {mw:.2f}MW", "msg": "여유용량이 충분합니다."}
    return {"status": "WARNING", "value": f"여유 {mw:.2f}MW", "msg": "여유용량이 부족할 수 있습니다(협의 필요)."}

# =========================
# (6) Slope
# =========================
def slope_check(slope_deg: Optional[float]) -> Dict[str, str]:
    if slope_deg is None:
        return {"status": "WARNING", "value": "확인 필요", "msg": "경사도 데이터가 없습니다(DEM 연동 또는 프론트 계산값 전달 필요)."}
    if slope_deg < 15:
        return {"status": "PASS", "value": f"{slope_deg:.1f}°", "msg": "경사도 기준 적합(15° 미만)입니다."}
    if slope_deg < 20:
        return {"status": "WARNING", "value": f"{slope_deg:.1f}°", "msg": "경사도 주의 구간(15~20°). 조례/허가 요건 확인 필요."}
    return {"status": "FAIL", "value": f"{slope_deg:.1f}°", "msg": "경사도 과다(20° 이상): 개발행위허가 불가 가능."}

# =========================
# (7) Insolation
# =========================
def insolation_check(sun_hours: Optional[float]) -> Dict[str, str]:
    if sun_hours is None:
        return {"status": "WARNING", "value": "확인 필요", "msg": "일사량 데이터가 없습니다(기상청 연동 또는 위도 기반 추정 필요)."}
    if sun_hours >= 3.6:
        return {"status": "PASS", "value": f"{sun_hours:.2f}h", "msg": "일사량 기준 적합(≥3.6h)입니다."}
    if sun_hours < 3.2:
        return {"status": "WARNING", "value": f"{sun_hours:.2f}h", "msg": "일사량이 낮습니다(3.2h 미만). 수익성 저하 가능."}
    return {"status": "WARNING", "value": f"{sun_hours:.2f}h", "msg": "일사량 추가 검토가 필요합니다."}

# =========================
# (8) Land Price (Official / fallback)
# =========================
# very light cache for "nearby market" heuristic
_land_unit_cache_by_metro: Dict[str, Tuple[float, float]] = {}  # metro -> (ts, unit_won_per_pyeong)

def _pyeong_from_m2(m2: float) -> float:
    return m2 / 3.305785

def land_price_check(pnu: Optional[str], area_m2: Optional[float]) -> Dict[str, str]:
    # This check is "info only": always PASS/WARNING with value.
    # We'll try to compute a unit price; if estimated, mark it.
    if not pnu or len(pnu) < 5:
        return {"status": "WARNING", "value": "확인 필요", "msg": "PNU가 없어서 토지가격 산정이 어렵습니다."}

    metro = pnu[:2]
    # If official land price API URL is configured, you can implement it here.
    # For now, we fall back to cached "nearby market" estimate if available.
    now = time.time()
    estimated = False

    unit = None
    if metro in _land_unit_cache_by_metro and (now - _land_unit_cache_by_metro[metro][0]) < 86400:
        unit = _land_unit_cache_by_metro[metro][1]
        estimated = True

    # If nothing cached, give a conservative placeholder (still estimated) so frontend can run 상세분석
    if unit is None:
        # conservative national-ish fallback (can be overridden by ENV)
        env_unit = os.getenv("LAND_UNIT_PRICE_WON_PER_PYEONG")
        if env_unit:
            try:
                unit = float(env_unit)
                estimated = True
            except:
                unit = None

    if unit is None:
        return {"status": "WARNING", "value": "추정 불가", "msg": "실거래/공시지가 데이터가 부족합니다(추가 확인 필요)."}

    # update cache
    _land_unit_cache_by_metro[metro] = (now, unit)

    if area_m2:
        total = unit * _pyeong_from_m2(area_m2)
        return {"status": "PASS", "value": f"{int(unit):,}원/평 · {int(total):,}원" + (" (추가 확인 필요)" if estimated else ""), "msg": "토지가격은 참고용입니다."}
    return {"status": "PASS", "value": f"{int(unit):,}원/평" + (" (추가 확인 필요)" if estimated else ""), "msg": "토지가격은 참고용입니다."}

# =========================
# Main endpoint
# =========================
@app.post("/api/checks/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    checks: Dict[str, Dict[str, str]] = {}

    # 1 zoning
    checks["zoning"] = zoning_check(req.lat, req.lng)

    # 2 ecology
    checks["ecology"] = ecology_check(req.lat, req.lng)

    # 3 heritage
    checks["heritage"] = heritage_check(req.lat, req.lng)

    # 4 setback (AI + law)
    checks["setback"] = setback_check(req.address, req.dist_road_m, req.dist_residential_m)

    # 5 grid
    checks["grid"] = grid_check(req.pnu, req.capacity_kw)

    # 6 slope
    checks["slope"] = slope_check(req.slope_deg)

    # 7 insolation
    checks["insolation"] = insolation_check(req.sun_hours)

    # 8 land price
    checks["land_price"] = land_price_check(req.pnu, req.area_m2)

    total, conf = score_from_checks(checks)

    # confidence string
    conf_str = f"{conf*100:.1f}%"

    return {"total_score": total, "confidence": conf_str, "check_list": checks}
