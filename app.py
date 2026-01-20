import json
import os
import secrets
import threading
from datetime import datetime, timezone

from flask import Flask, request, jsonify
from flask_cors import CORS

# -------------------------------------------------
# Flask App
# -------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-me")

# -------------------------------------------------
# CORS Config ✅ FIXED + HARD PREFLIGHT FIX
# -------------------------------------------------
cors_origins_env = (os.getenv("CORS_ORIGINS", "") or "").strip()
origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] if cors_origins_env else []

if not origins:
    origins = [
        "https://pathfinder.scenergy.co.kr",
        "https://www.scenergy.co.kr",
    ]

# Flask-CORS (기본 CORS 처리)
CORS(
    app,
    resources={r"/api/*": {"origins": origins}},
    supports_credentials=False,
    allow_headers=[
        "Content-Type",
        "X-CLIENT-TOKEN",
        "X-CLIENT-FP",
        "X-ADMIN-KEY",
    ],
    methods=["GET", "POST", "DELETE", "OPTIONS"],
    max_age=86400,
)

# -------------------------------------------------
# HARD CORS PREFLIGHT (브라우저가 막는 케이스 확정 대응)
# - OPTIONS 프리플라이트는 무조건 204 + CORS 헤더
# - 401/404 같은 에러 응답에도 CORS 헤더 강제 부착
# -------------------------------------------------
ALLOWED_ORIGINS = origins

def _apply_cors_headers(resp):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,DELETE,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-ADMIN-KEY, X-CLIENT-TOKEN, X-CLIENT-FP"
        resp.headers["Access-Control-Max-Age"] = "86400"
    return resp

@app.before_request
def _handle_preflight():
    # 프리플라이트(OPTIONS)는 인증/라이선스 체크 전에 무조건 통과시켜야 함
    if request.method == "OPTIONS" and (request.path or "").startswith("/api/"):
        resp = app.make_response(("", 204))
        return _apply_cors_headers(resp)
    return None

@app.after_request
def _after(resp):
    # 모든 응답(200/401/404 포함)에 CORS 헤더 강제 부착
    return _apply_cors_headers(resp)

# -------------------------------------------------
# License DB
# -------------------------------------------------
LICENSE_DB_PATH = os.getenv("LICENSE_DB_PATH", "./licenses_db.json")
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()
_db_lock = threading.Lock()

# -------------------------------------------------
# Utils
# -------------------------------------------------
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _parse_iso(dt_str: str) -> datetime:
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def _load_db() -> dict:
    if not os.path.exists(LICENSE_DB_PATH):
        return {"licenses": {}}
    with open(LICENSE_DB_PATH, "r", encoding="utf-8") as f:
        return json.load(f) or {"licenses": {}}

def _save_db(db: dict) -> None:
    tmp_path = LICENSE_DB_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp_path, LICENSE_DB_PATH)

def _require_admin() -> bool:
    if not ADMIN_API_KEY:
        return False
    key = (request.headers.get("X-ADMIN-KEY") or "").strip()
    return key == ADMIN_API_KEY

def get_client_token() -> str:
    return (request.headers.get("X-CLIENT-TOKEN") or "").strip()

def get_client_fp() -> str:
    return (request.headers.get("X-CLIENT-FP") or "").strip()

# -------------------------------------------------
# License logic
# -------------------------------------------------
def _license_status(db: dict, token: str, fp: str):
    lic = (db.get("licenses") or {}).get(token)
    if not lic:
        return False, "NOT_FOUND", None
    if lic.get("revoked"):
        return False, "REVOKED", lic

    expires_at = lic.get("expires_at")
    if not expires_at:
        return False, "NO_EXPIRY", lic

    try:
        exp = _parse_iso(expires_at)
    except Exception:
        return False, "BAD_EXPIRY", lic

    if _now_utc() > exp:
        return False, "EXPIRED", lic

    bound_fp = (lic.get("bound_fp") or "").strip()
    if not bound_fp:
        return False, "NOT_ACTIVATED", lic
    if not fp:
        return False, "MISSING_FP", lic
    if fp != bound_fp:
        return False, "FP_MISMATCH", lic

    return True, "OK", lic

# -------------------------------------------------
# API Guard
# -------------------------------------------------
PUBLIC_API_PATHS = {
    "/api/health",
    "/api/auth/verify",
    "/api/license/activate",
}

@app.before_request
def _require_license_for_api():
    # OPTIONS는 위 _handle_preflight()에서 이미 처리되지만,
    # 혹시라도 다른 경로로 들어오면 여기서도 한 번 더 안전하게 스킵
    if request.method == "OPTIONS":
        return None

    path = request.path or ""
    if not path.startswith("/api/"):
        return None
    if path.startswith("/api/admin/"):
        return None
    if path in PUBLIC_API_PATHS:
        return None

    token = get_client_token()
    fp = get_client_fp()

    with _db_lock:
        db = _load_db()
        ok, code, _ = _license_status(db, token, fp)

    if not ok:
        return jsonify({"ok": False, "code": code}), 401

    return None

# -------------------------------------------------
# Health
# -------------------------------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "solar-server"})

@app.get("/api/health")
def health():
    return jsonify({"ok": True})

# -------------------------------------------------
# Verify / Activate
# -------------------------------------------------
@app.get("/api/auth/verify")
def verify():
    token = get_client_token()
    fp = get_client_fp()

    with _db_lock:
        db = _load_db()
        ok, code, lic = _license_status(db, token, fp)

    if not ok:
        return jsonify({"ok": False, "code": code}), 200

    return jsonify({"ok": True, "expires_at": lic.get("expires_at")})

@app.post("/api/license/activate")
def activate():
    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip()
    fp = (body.get("fingerprint") or "").strip()

    if not token or not fp:
        return jsonify({"ok": False}), 400

    with _db_lock:
        db = _load_db()
        lic = (db.get("licenses") or {}).get(token)
        if not lic:
            return jsonify({"ok": False}), 404

        lic["bound_fp"] = fp
        lic["bound_at"] = _now_utc().isoformat()
        db["licenses"][token] = lic
        _save_db(db)

    return jsonify({"ok": True, "expires_at": lic.get("expires_at")})

# -------------------------------------------------
# Admin APIs
# -------------------------------------------------
@app.get("/api/admin/licenses")
def admin_list_licenses():
    if not _require_admin():
        return jsonify({"ok": False}), 401

    with _db_lock:
        db = _load_db()
        items = []
        for token, lic in (db.get("licenses") or {}).items():
            items.append({
                "token": token,
                "expires_at": lic.get("expires_at"),
                "revoked": lic.get("revoked", False),
                "note": lic.get("note", ""),
                "bound": bool((lic.get("bound_fp") or "").strip()),
            })

    return jsonify({"ok": True, "licenses": items})

@app.post("/api/admin/licenses")
def admin_issue_license():
    if not _require_admin():
        return jsonify({"ok": False}), 401

    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip() or f"SCE-{secrets.token_urlsafe(10)}"
    expires_at = (body.get("expires_at") or "").strip()
    note = (body.get("note") or "").strip()

    if not expires_at:
        return jsonify({"ok": False, "msg": "expires_at is required (ISO8601)"}), 400

    with _db_lock:
        db = _load_db()
        db.setdefault("licenses", {})
        if token in db["licenses"]:
            return jsonify({"ok": False, "msg": "token already exists"}), 409
        db["licenses"][token] = {
            "expires_at": expires_at,
            "revoked": False,
            "note": note,
            "bound_fp": "",
            "bound_at": "",
        }
        _save_db(db)

    return jsonify({"ok": True, "token": token, "expires_at": expires_at})

# -------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
