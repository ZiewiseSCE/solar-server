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
# CORS Config
# -------------------------------------------------
cors_origins_env = (os.getenv("CORS_ORIGINS", "") or "").strip()
origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()] if cors_origins_env else []
if not origins:
    origins = [
        "https://pathfinder.scenergy.co.kr",
        "https://www.scenergy.co.kr",
    ]

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
)

# -------------------------------------------------
# License DB (Token + Expiry + Fingerprint Binding)
# -------------------------------------------------
LICENSE_DB_PATH = os.getenv("LICENSE_DB_PATH", "./licenses_db.json")
ADMIN_API_KEY = (os.getenv("ADMIN_API_KEY") or "").strip()

_db_lock = threading.Lock()


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_iso(dt_str: str) -> datetime:
    """Parse ISO8601 with timezone. Raises ValueError if invalid."""
    dt = datetime.fromisoformat(dt_str)
    if dt.tzinfo is None:
        # Treat naive as UTC to avoid accidental local-time issues.
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

    # Prefer header, fallback to query string (to avoid CORS preflight issues on some ingresses)
    key = (request.headers.get("X-ADMIN-KEY") or request.headers.get("X-Admin-Key") or "").strip()
    if not key:
        key = (request.args.get("admin_key") or "").strip()

    return key == ADMIN_API_KEY


def get_client_token() -> str:
    return (
        request.headers.get("X-CLIENT-TOKEN")
        or request.headers.get("X-Client-Token")
        or ""
    ).strip()


def get_client_fp() -> str:
    return (
        request.headers.get("X-CLIENT-FP")
        or request.headers.get("X-Client-Fp")
        or request.headers.get("X-Client-FP")
        or ""
    ).strip()


def _license_status(db: dict, token: str, fp: str) -> tuple[bool, str, dict | None]:
    """Returns (ok, code, license_dict_or_none)."""
    lic = (db.get("licenses") or {}).get(token)
    if not lic:
        return False, "NOT_FOUND", None

    if lic.get("revoked") is True:
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
# Protect /api/* (except public endpoints)
# -------------------------------------------------
PUBLIC_API_PATHS = {
    "/api/health",
    "/api/auth/verify",
    "/api/license/activate",
}


@app.before_request
def _require_license_for_api():
    path = request.path or ""
    if not path.startswith("/api/"):
        return None
    # Admin endpoints are protected by ADMIN_API_KEY, not end-user license.
    if path.startswith("/api/admin/") or path == "/api/admin/licenses":
        return None
    if path in PUBLIC_API_PATHS:
        return None

    token = get_client_token()
    fp = get_client_fp()

    with _db_lock:
        db = _load_db()
        ok, code, _lic = _license_status(db, token, fp)

    if not ok:
        return jsonify({"ok": False, "code": code, "msg": _code_to_message(code)}), 401

    return None


def _code_to_message(code: str) -> str:
    return {
        "NOT_FOUND": "라이선스 키를 찾을 수 없습니다.",
        "REVOKED": "라이선스가 폐기(차단)되었습니다.",
        "NO_EXPIRY": "라이선스 만료 정보가 없습니다.",
        "BAD_EXPIRY": "라이선스 만료 정보가 올바르지 않습니다.",
        "EXPIRED": "라이선스가 만료되었습니다. 새 키를 발급받아 다시 등록해 주세요.",
        "NOT_ACTIVATED": "라이선스가 아직 이 기기에 등록(활성화)되지 않았습니다.",
        "MISSING_FP": "기기 식별 정보를 확인할 수 없습니다.",
        "FP_MISMATCH": "이 라이선스는 다른 기기에 등록되어 있어 사용할 수 없습니다.",
        "OK": "정상",
    }.get(code, "인증에 실패했습니다.")


# -------------------------------------------------
# Root / Health
# -------------------------------------------------
@app.get("/")
def root():
    return jsonify({"ok": True, "service": "solar-server"}), 200


@app.get("/api/health")
def health():
    return jsonify({"ok": True}), 200


# -------------------------------------------------
# Verify
# -------------------------------------------------
@app.get("/api/auth/verify")
def verify():
    token = get_client_token()
    fp = get_client_fp()

    with _db_lock:
        db = _load_db()
        ok, code, lic = _license_status(db, token, fp)

    # If license exists but not activated yet, return 200 with ok=false so UI can guide activation.
    if not ok and code in {"NOT_ACTIVATED", "MISSING_FP"}:
        return (
            jsonify(
                {
                    "ok": False,
                    "code": code,
                    "msg": _code_to_message(code),
                    "expires_at": (lic or {}).get("expires_at"),
                }
            ),
            200,
        )

    if not ok:
        return jsonify({"ok": False, "code": code, "msg": _code_to_message(code)}), 401

    return jsonify({"ok": True, "expires_at": (lic or {}).get("expires_at")}), 200


# -------------------------------------------------
# Activate (Bind token -> fingerprint)
# -------------------------------------------------
@app.post("/api/license/activate")
def activate():
    # Accept both JSON and form-urlencoded
    body = request.get_json(silent=True)
    if not body:
        body = request.form.to_dict(flat=True) if request.form else {}
    body = body or {}

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


@app.get("/api/admin/licenses")
def admin_list_licenses():
    """List all licenses (admin only)."""
    if not _require_admin():
        return jsonify({"ok": False, "msg": "admin key required"}), 401

    with _db_lock:
        db = _load_db()
        items = []
        for token, lic in (db.get("licenses") or {}).items():
            items.append(
                {
                    "token": token,
                    "expires_at": lic.get("expires_at"),
                    "revoked": bool(lic.get("revoked")),
                    "note": lic.get("note") or "",
                    "bound": bool((lic.get("bound_fp") or "").strip()),
                    "bound_at": lic.get("bound_at") or "",
                }
            )

    # Sort by expiry then token for convenience
    def _sort_key(x):
        try:
            return (_parse_iso(x.get("expires_at") or "1970-01-01T00:00:00+00:00"), x.get("token") or "")
        except Exception:
            return (datetime(1970, 1, 1, tzinfo=timezone.utc), x.get("token") or "")

    items.sort(key=_sort_key)
    return jsonify({"ok": True, "count": len(items), "licenses": items}), 200


@app.post("/api/admin/licenses/<token>/revoke")
def admin_revoke(token: str):
    if not _require_admin():
        return jsonify({"ok": False, "msg": "admin key required"}), 401

    with _db_lock:
        db = _load_db()
        lic = (db.get("licenses") or {}).get(token)
        if not lic:
            return jsonify({"ok": False, "msg": "not found"}), 404
        lic["revoked"] = True
        (db.get("licenses") or {})[token] = lic
        _save_db(db)

    return jsonify({"ok": True}), 200


@app.post("/api/admin/licenses/<token>/reset")
def admin_reset_binding(token: str):
    if not _require_admin():
        return jsonify({"ok": False, "msg": "admin key required"}), 401

    with _db_lock:
        db = _load_db()
        lic = (db.get("licenses") or {}).get(token)
        if not lic:
            return jsonify({"ok": False, "msg": "not found"}), 404
        lic["bound_fp"] = ""
        lic["bound_at"] = ""
        (db.get("licenses") or {})[token] = lic
        _save_db(db)

    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")))
