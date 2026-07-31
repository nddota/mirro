"""
ОКУЛЯР — backend

Реальная модель доступа:
  - роль хранится в подписанном JWT, который лежит в httpOnly/Secure cookie
    (JS на фронтенде токен вообще не видит и не может его прочитать/подделать)
  - пароль администратора никогда не хранится в открытом виде — только bcrypt-хеш
    в переменной окружения ADMIN_PASSWORD_HASH
  - admin-only ресурсы (сохранение калибровки) проверяются на сервере в каждом
    запросе — скрытие кнопок на фронтенде это лишь UX, а не защита
  - вход администратора ограничен по частоте (rate limit), чтобы затруднить подбор пароля
"""

import base64
import binascii
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from face_compare import FaceNotFoundError, compare_faces

app = Flask(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH")
COOKIE_NAME = "oculus_session"
TOKEN_TTL_MINUTES = 120
# In production behind HTTPS (Render/Fly give you this by default) keep True.
# Only set to False for local http://localhost testing.
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() != "false"

if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET env var is required (long random string)")
if not ADMIN_PASSWORD_HASH:
    raise RuntimeError("ADMIN_PASSWORD_HASH env var is required (bcrypt hash, see generate_admin_hash.py)")

limiter = Limiter(get_remote_address, app=app, default_limits=[])

# ---------- photo storage ----------
# SQLite файл. На Render/Fly для настоящей сохранности между деплоями примонтируйте
# сюда persistent disk (см. README) — иначе при пересборке контейнера данные теряются.
DATA_DIR = os.environ.get("DATA_DIR", "data")
DB_PATH = os.path.join(DATA_DIR, "oculus.db")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_IMAGE_BYTES = 6 * 1024 * 1024  # 6MB decoded, generous for a phone/webcam JPEG


def get_db():
    if "db" not in g:
        os.makedirs(DATA_DIR, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.execute(
            """CREATE TABLE IF NOT EXISTS photos (
                taken_date TEXT PRIMARY KEY,
                content BLOB NOT NULL,
                content_type TEXT NOT NULL,
                uploaded_at TEXT NOT NULL
            )"""
        )
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# ---------- token helpers ----------

def make_token(role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def current_role() -> str | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("role")
    except jwt.PyJWTError:
        return None


def set_session_cookie(resp, role: str):
    resp.set_cookie(
        COOKIE_NAME,
        make_token(role),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Strict",
        max_age=TOKEN_TTL_MINUTES * 60,
        path="/",
    )
    return resp


def require_role(role: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if current_role() != role:
                return jsonify({"error": "forbidden"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if current_role() is None:
            return jsonify({"error": "unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


# ---------- pages ----------

@app.route("/")
def index():
    return render_template("index.html")


# ---------- auth ----------

@app.route("/api/login/user", methods=["POST"])
@limiter.limit("30/minute")
def login_user():
    resp = jsonify({"role": "user"})
    return set_session_cookie(resp, "user")


@app.route("/api/login/admin", methods=["POST"])
@limiter.limit("5/minute")  # slow down password guessing
def login_admin():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password or not bcrypt.checkpw(password.encode("utf-8"), ADMIN_PASSWORD_HASH.encode("utf-8")):
        return jsonify({"error": "invalid credentials"}), 401
    resp = jsonify({"role": "admin"})
    return set_session_cookie(resp, "admin")


@app.route("/api/logout", methods=["POST"])
def logout():
    resp = jsonify({"ok": True})
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


@app.route("/api/me")
def me():
    return jsonify({"role": current_role()})


# ---------- photo diary + face comparison ----------
# Доступно любой вошедшей роли — это личный дневник фото, а не настройка системы.

def _decode_data_url(data_url: str) -> tuple[bytes, str]:
    """'data:image/jpeg;base64,....' -> (bytes, content_type)"""
    match = re.match(r"^data:(image/[a-zA-Z]+);base64,(.+)$", data_url or "")
    if not match:
        raise ValueError("ожидается data URL с изображением")
    content_type, b64 = match.group(1), match.group(2)
    try:
        raw = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("некорректные base64-данные")
    if len(raw) > MAX_IMAGE_BYTES:
        raise ValueError("файл слишком большой")
    return raw, content_type


@app.route("/api/photos", methods=["POST"])
@require_login
@limiter.limit("20/minute")
def upload_photo():
    data = request.get_json(silent=True) or {}
    taken_date = data.get("date", "")
    if not DATE_RE.match(taken_date):
        return jsonify({"error": "date must be YYYY-MM-DD"}), 400
    try:
        raw, content_type = _decode_data_url(data.get("image", ""))
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    db = get_db()
    db.execute(
        """INSERT INTO photos (taken_date, content, content_type, uploaded_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(taken_date) DO UPDATE SET
             content=excluded.content,
             content_type=excluded.content_type,
             uploaded_at=excluded.uploaded_at""",
        (taken_date, raw, content_type, datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return jsonify({"ok": True, "date": taken_date})


@app.route("/api/photos", methods=["GET"])
@require_login
def list_photos():
    db = get_db()
    rows = db.execute(
        "SELECT taken_date, uploaded_at FROM photos ORDER BY taken_date DESC"
    ).fetchall()
    return jsonify([{"date": r[0], "uploaded_at": r[1]} for r in rows])


@app.route("/api/photos/<date>/image", methods=["GET"])
@require_login
def get_photo_image(date):
    if not DATE_RE.match(date):
        return jsonify({"error": "bad date"}), 400
    db = get_db()
    row = db.execute(
        "SELECT content, content_type FROM photos WHERE taken_date = ?", (date,)
    ).fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404
    content, content_type = row
    return app.response_class(content, mimetype=content_type)


@app.route("/api/photos/<date>", methods=["DELETE"])
@require_login
def delete_photo(date):
    if not DATE_RE.match(date):
        return jsonify({"error": "bad date"}), 400
    db = get_db()
    db.execute("DELETE FROM photos WHERE taken_date = ?", (date,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/compare", methods=["POST"])
@require_login
@limiter.limit("15/minute")
def compare():
    data = request.get_json(silent=True) or {}
    date_a, date_b = data.get("date_a", ""), data.get("date_b", "")
    if not (DATE_RE.match(date_a) and DATE_RE.match(date_b)):
        return jsonify({"error": "date_a/date_b must be YYYY-MM-DD"}), 400

    db = get_db()
    row_a = db.execute("SELECT content FROM photos WHERE taken_date = ?", (date_a,)).fetchone()
    row_b = db.execute("SELECT content FROM photos WHERE taken_date = ?", (date_b,)).fetchone()
    if not row_a or not row_b:
        return jsonify({"error": "one of the dates has no saved photo"}), 404

    try:
        result = compare_faces(row_a[0], row_b[0])
    except FaceNotFoundError as e:
        return jsonify({"error": str(e)}), 422
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    def to_data_url(jpg_bytes):
        return "data:image/jpeg;base64," + base64.b64encode(jpg_bytes).decode("ascii")

    return jsonify(
        {
            "similarity": result["similarity"],
            "face_a": to_data_url(result["face_a_jpg"]),
            "face_b": to_data_url(result["face_b_jpg"]),
            "diff_overlay": to_data_url(result["diff_overlay_jpg"]),
        }
    )


if __name__ == "__main__":
    app.run(debug=False)
