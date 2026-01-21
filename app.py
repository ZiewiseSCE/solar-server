import os, json, secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from io import BytesIO

from flask import Flask, request, jsonify, make_response, render_template_string, redirect, send_file
from flask_cors import CORS

# Optional ReportLab (PDF)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
except Exception:
    A4 = None

app = Flask(__name__)

# CORS
CORS(app, supports_credentials=True)

APP_DIR = Path(__file__).resolve().parent

# -----------------------------
# Config
# -----------------------------
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "admin1234").strip()

def _pick_license_db_path():
    # Persist-friendly path order:
    # 1) LICENSE_DB_FILE env
    # 2) /data/licenses_db.json (if writable)
    # 3) ./licenses_db.json
    # 4) /tmp/licenses_db.json
    env = (os.getenv("LICENSE_DB_FILE") or "").strip()
    if env:
        return Path(env)
    p_data = Path("/data/licenses_db.json")
    try:
        p_data.parent.mkdir(parents=True, exist_ok=True)
        # test writable
        with open(p_data, "a", encoding="utf-8"):
            pass
        return p_data
    except Exception:
        pass
    return APP_DIR / "licenses_db.json"

LICENSE_DB_FILE = _pick_license_db_path()

# -----------------------------
# Helpers
# -----------------------------
def json_ok(**kwargs):
    d = {"ok": True, "status": "OK"}
    d.update(kwargs)
    return jsonify(d)

def json_bad(msg: str, code: int = 400, **kwargs):
    d = {"ok": False, "status": "ERROR", "msg": msg}
    d.update(kwargs)
    return jsonify(d), code

def _require_admin():
    # allow header or query
    key = (request.headers.get("X-Admin-Key") or request.args.get("admin_key") or "").strip()
    return key == ADMIN_API_KEY

def _load_json(path: Path, default):
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

def _now_utc():
    return datetime.now(timezone.utc)

def _iso(dt: datetime):
    return dt.astimezone(timezone.utc).isoformat()

# -----------------------------
# License DB (admin)
# -----------------------------
def load_licenses():
    return _load_json(LICENSE_DB_FILE, [])

def save_licenses(items):
    _save_json(LICENSE_DB_FILE, items)

def _find_license(items, token):
    for it in items:
        if it.get("token") == token:
            return it
    return None

@app.route("/api/admin/licenses", methods=["GET", "OPTIONS"])
def admin_list_licenses():
    if request.method == "OPTIONS":
        return ("", 204)
    if not _require_admin():
        return json_bad("unauthorized", 401)
    return json_ok(items=load_licenses())

@app.route("/api/admin/license/create", methods=["POST", "OPTIONS"])
def admin_create_license():
    if request.method == "OPTIONS":
        return ("", 204)
    if not _require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
    note = (data.get("note") or "").strip()
    days = int(data.get("days") or 365)
    token = "SCE-" + secrets.token_hex(5).upper()
    now = _now_utc()
    item = {
        "token": token,
        "created_at": _iso(now),
        "expires_at": _iso(now + timedelta(days=days)),
        "note": note,
        "fingerprints": [],
    }
    items = load_licenses()
    items.append(item)
    save_licenses(items)
    return json_ok(item=item)

@app.route("/api/admin/license/reset", methods=["POST", "OPTIONS"])
def admin_license_reset():
    if request.method == "OPTIONS":
        return ("", 204)
    if not _require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    items = load_licenses()
    it = _find_license(items, token)
    if not it:
        return json_bad("not found", 404)
    it["fingerprints"] = []
    save_licenses(items)
    return json_ok()

@app.route("/api/admin/license/extend", methods=["POST", "OPTIONS"])
def admin_license_extend():
    if request.method == "OPTIONS":
        return ("", 204)
    if not _require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    days = int(data.get("days") or 30)
    items = load_licenses()
    it = _find_license(items, token)
    if not it:
        return json_bad("not found", 404)
    try:
        old = datetime.fromisoformat(it["expires_at"])
    except Exception:
        old = _now_utc()
    it["expires_at"] = _iso(old + timedelta(days=days))
    save_licenses(items)
    return json_ok(item=it)

@app.route("/api/admin/license/delete", methods=["POST", "OPTIONS"])
def admin_license_delete():
    if request.method == "OPTIONS":
        return ("", 204)
    if not _require_admin():
        return json_bad("unauthorized", 401)
    data = request.get_json(force=True, silent=True) or {}
    token = (data.get("token") or "").strip()
    items = [x for x in load_licenses() if x.get("token") != token]
    save_licenses(items)
    return json_ok()

# -----------------------------
# AI Analysis
# -----------------------------
def _build_ai_result(lat: float, lng: float, address: str, mode: str = "", area_m2: float = 0.0):
    # Mocked checklist (data source 확정 시 교체)
    checks = [
        {"title":"1. 도시/자치 조례 (이격거리)", "result":"확인 필요 (지자체 조례 참조)", "link":"https://www.elis.go.kr/"},
        {"title":"2. 용도지역 (토지이음)", "result":"확인 필요", "link":"https://www.eum.go.kr/web/am/amMain.jsp"},
        {"title":"3. 상위법 규제 (환경/농지)", "result":"확인 필요", "link":"https://www.law.go.kr/"},
        {"title":"4. 자연/생태 등급", "result":"확인 필요", "link":"https://aid.mcee.go.kr/"},
        {"title":"5. 문화재/국가유산", "result":"확인 필요", "link":"https://www.nie-ecobank.kr/"},
        {"title":"6. 국토환경성평가 (경사도)", "result":"평균 경사도: 확인 필요 (정확도 확인필요)", "link":"https://webgis.neins.go.kr/map.do"},
        {"title":"7. 소규모 환경영향평가", "result":"면적/용도지역 기반 확인 필요", "link":"https://www.law.go.kr/"},
        {"title":"8. 한전 선로 용량", "result":"확인 필요 (한전ON)", "link":"https://online.kepco.co.kr/"},
    ]

    # conservative scoring
    score = 70
    reasons = []
    # penalize uncertainties
    uncertain = sum(1 for c in checks if "확인 필요" in (c.get("result") or ""))
    score -= min(35, uncertain * 4)
    if area_m2 and area_m2 < 300:
        score -= 10; reasons.append("면적이 작아 경제성이 낮을 수 있음 (-10)")
    if mode == "land":
        score -= 5; reasons.append("토지형은 인허가 변수/리스크가 커 보수적으로 감점 (-5)")
    if score < 0: score = 0

    ai_score = {
        "score": score,
        "grade": ("A" if score>=85 else "B" if score>=70 else "C" if score>=55 else "D"),
        "confidence": max(55, 90-uncertain*4),
        "reasons": reasons if reasons else ["체크리스트 확인 필요 항목이 다수 존재하여 보수적 평가"]
    }

    return {
        "checks": checks,
        "sun_hours": 3.8,
        "kepco_capacity": "확인 필요",
        "ai_score": ai_score,
        "ai_comment": "데이터 확정 전까지는 보수적 점수이며, 체크리스트 링크에서 필수 확인이 필요합니다."
    }

@app.route("/api/analyze/comprehensive", methods=["POST","OPTIONS"])
def analyze_comprehensive():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    lat = float(data.get("lat") or 0)
    lng = float(data.get("lng") or 0)
    address = (data.get("address") or "").strip()
    mode = (data.get("mode") or "").strip()
    area_m2 = float(data.get("area_m2") or 0)
    result = _build_ai_result(lat, lng, address, mode, area_m2)
    return json_ok(**result)

# Spec endpoint alias: /api/ai/analyze
@app.route("/api/ai/analyze", methods=["POST","OPTIONS"])
def ai_analyze():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    lat = float(data.get("lat") or 0)
    lng = float(data.get("lng") or 0)
    address = (data.get("address") or "").strip()
    mode = (data.get("mode") or "").strip()
    area_m2 = float(data.get("area_m2") or 0)
    result = _build_ai_result(lat, lng, address, mode, area_m2)

    # spec-friendly shape + backward compatible fields
    checklist = []
    for c in result["checks"]:
        checklist.append({
            "category": c["title"],
            "status": c["result"],
            "link": c.get("link",""),
            "needs_review": ("확인 필요" in (c.get("result") or "")) or ("확인필요" in (c.get("result") or ""))
        })

    return jsonify({
        "ok": True,
        "checklist": checklist,
        "attractiveness_score": result["ai_score"]["score"],
        "reasons": result["ai_score"].get("reasons", []),
        # compatibility
        **result
    })

# -----------------------------
# Finance (PF)
# -----------------------------
@app.route("/api/finance/pf", methods=["POST","OPTIONS"])
def finance_pf():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    try:
        principal = float(data.get("principal") or 0)
        rate = float(data.get("rate") or 0) / 100.0
        years = int(data.get("years") or 0)
        if principal <= 0 or rate < 0 or years <= 0:
            return json_bad("invalid inputs", 400)
        n = years * 12
        r = rate / 12.0
        if r == 0:
            monthly = principal / n
        else:
            monthly = principal * (r * (1+r)**n) / ((1+r)**n - 1)
        total_payment = monthly * n
        total_interest = total_payment - principal
        return json_ok(
            monthly_payment=round(monthly),
            total_payment=round(total_payment),
            total_interest=round(total_interest),
            schedule="원리금균등"
        )
    except Exception as e:
        return json_bad("calc failed", 500, detail=str(e))

# -----------------------------
# Report HTML/PDF
# -----------------------------
def _load_report_template() -> str:
    p = APP_DIR / "report.html"
    if p.exists():
        return p.read_text(encoding="utf-8", errors="ignore")
    # embedded fallback (never 404)
    return """<!doctype html><html lang='ko'><meta charset='utf-8'>
    <body style='font-family:Arial'>
    <h1>태양광 상세 리포트</h1>
    <pre id='d'></pre>
    <script>
      const data = window.data || {};
      document.getElementById('d').innerText = JSON.stringify(data, null, 2);
    </script>
    </body></html>"""

def _parse_report_form(form) -> dict:
    def _json_field(*names):
        for name in names:
            v = form.get(name)
            if not v:
                continue
            try:
                return json.loads(v)
            except Exception:
                continue
        return {}

    return {
        "address": form.get("address") or "",
        "capacity": form.get("capacity") or "",
        "kepco_capacity": form.get("kepco_capacity") or form.get("kepco") or "",
        "date": form.get("date") or "",
        "finance": _json_field("finance"),
        "ai_analysis": _json_field("ai_analysis","ai"),
        "ai_score": _json_field("ai_score","score"),
        "land_price": form.get("land_price") or form.get("price") or "",
    }

@app.route("/report", methods=["GET","POST"])
def report_html():
    if request.method == "GET":
        # allow direct open
        tpl = _load_report_template()
        html = render_template_string(tpl, data={})
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        return resp

    data = _parse_report_form(request.form)
    tpl = _load_report_template()
    html = render_template_string(tpl, data=data)
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp

@app.route("/report.html", methods=["GET"])
def report_alias():
    return redirect("/report")

def _render_pdf(data: dict) -> bytes:
    if A4 is None:
        # ReportLab missing
        return b""
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4
    x0 = 18 * mm
    y = h - 18 * mm
    lh = 7 * mm

    c.setFont("Helvetica-Bold", 16)
    c.drawString(x0, y, "Solar PV Analysis Report")
    y -= lh*2

    c.setFont("Helvetica", 10)
    c.drawString(x0, y, f"Address: {data.get('address','')}")
    y -= lh
    c.drawString(x0, y, f"Date: {data.get('date','')}")
    y -= lh*2

    fin = data.get("finance") or {}
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x0, y, "[Financial Summary]")
    y -= lh
    c.setFont("Helvetica", 10)
    for k in ["acCapacity","dcCapacity","totalCost","annualRev","annualKwh","loan","equity","payback"]:
        c.drawString(x0+10, y, f"{k}: {fin.get(k,'-')}")
        y -= lh
    y -= lh

    ai = data.get("ai_analysis") or {}
    score = (data.get("ai_score") or {}).get("score")
    if score is None and isinstance(ai, dict):
        score = (ai.get("ai_score") or {}).get("score")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(x0, y, "[AI Analysis]")
    y -= lh
    c.setFont("Helvetica", 10)
    c.drawString(x0+10, y, f"AI Score: {score if score is not None else '-'} / 100")
    y -= lh
    c.drawString(x0+10, y, f"KEPCO: {data.get('kepco_capacity','') or '확인 필요'}")
    y -= lh

    c.showPage()
    c.save()
    pdf = buf.getvalue()
    buf.close()
    return pdf

@app.route("/report/pdf", methods=["POST"])
def report_pdf():
    data = _parse_report_form(request.form)
    pdf = _render_pdf(data)
    resp = make_response(pdf)
    resp.headers["Content-Type"] = "application/pdf"
    resp.headers["Content-Disposition"] = 'attachment; filename="solar_report.pdf"'
    return resp

# Spec alias endpoint: /api/report/pdf (JSON body)
@app.route("/api/report/pdf", methods=["POST","OPTIONS"])
def api_report_pdf():
    if request.method == "OPTIONS":
        return ("", 204)
    data = request.get_json(force=True, silent=True) or {}
    pdf = _render_pdf(data)
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True, download_name="solar_report.pdf")

# -----------------------------
# Health
# -----------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return json_ok(ts=_iso(_now_utc()), license_db=str(LICENSE_DB_FILE))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT") or 5000))
