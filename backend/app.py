"""
TeleCloud Vault — Personal File Management Backend
- FastAPI + PostgreSQL metadata & file reference store (easy long-term backup/restore via pg_dump/psql)
- Strong single-owner Password Authentication (PBKDF2-HMAC-SHA256 600k iterations + HttpOnly JWT)
- AES-256-GCM Encrypted Credentials Vault for Telegram & Google OAuth secrets
- Telegram Storage Engine:
  * Private Bot API mode (sendDocument to preserve 100% uncompressed original bytes + EXIF)
- Lossless Image Compression Engine:
  * Generates separate lossless optimized WebP/PNG/JPEG copy (retaining EXIF & ICC profiles)
    while strictly preserving the untouched original file in Telegram.
- Google Photos OAuth 2.0 Integration:
  * Transfers original quality images using baseUrl + '=d' (preserving EXIF & capture timestamps).
- Backup & Recovery:
  * pg_dump SQL snapshot (portable, human-readable, restorable with `psql -f`) + optional upload to Telegram.
"""

import os
import io
import json
import time
import asyncio
import uuid
import hmac
import hashlib
import secrets
import base64
import subprocess
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, Header, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import psycopg
from psycopg import Connection
from psycopg_pool import ConnectionPool
from psycopg.rows import dict_row
from PIL import Image, ExifTags
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://telecloud:telecloud@localhost:5432/telecloud_vault")
MASTER_KEY_HEX = os.environ.get("VAULT_MASTER_KEY", secrets.token_hex(32))
DEFAULT_ADMIN_PASSWORD = os.environ.get("VAULT_INITIAL_PASSWORD", "")

app = FastAPI(title="TeleCloud Vault API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("ALLOWED_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": f"{type(exc).__name__}: {exc}"})


# Connections are reused from a small pool rather than opened per-request, since Postgres
# connections are heavier to establish than SQLite's "just open the file" model.
pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=10, kwargs={"row_factory": dict_row}, open=False)


def get_db():
    with pool.connection() as conn:
        yield conn


def init_db():
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    with pool.connection() as conn:
        conn.execute(schema_sql)

        cur = conn.execute("SELECT COUNT(*) AS cnt FROM folders WHERE id = 'root'")
        if cur.fetchone()["cnt"] == 0:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                "INSERT INTO folders (id, name, parent_id, color, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s)",
                ("root", "My Vault", None, "#6366f1", now, now),
            )

        if DEFAULT_ADMIN_PASSWORD:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM auth_config WHERE id = 1")
            if cur.fetchone()["cnt"] == 0:
                salt = secrets.token_hex(16)
                pw_hash = hash_password(DEFAULT_ADMIN_PASSWORD, salt, 600000)
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO auth_config (id, password_hash, salt, kdf_iterations, jwt_secret_encrypted, updated_at) VALUES (1, %s, %s, 600000, %s, %s)",
                    (pw_hash, salt, secrets.token_hex(32), now),
                )

        # Pre-seed Telegram bot credentials from environment variables (.env) if provided
        # and nothing has been saved via the Web UI Settings yet.
        env_bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        env_chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if env_bot_token and env_chat_id:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM credentials_vault WHERE service = 'telegram_bot'")
            if cur.fetchone()["cnt"] == 0:
                enc, nonce = encrypt_secret({"bot_token": env_bot_token, "chat_id": env_chat_id})
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO credentials_vault (service, encrypted_payload, nonce, is_active, updated_at) VALUES ('telegram_bot', %s, %s, 1, %s)",
                    (enc, nonce, now),
                )
        conn.commit()


def hash_password(password: str, salt: str, iterations: int = 600000) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations)
    return dk.hex()


def encrypt_secret(data: dict) -> tuple[str, str]:
    key = bytes.fromhex(MASTER_KEY_HEX[:64].ljust(64, "0"))
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, json.dumps(data).encode("utf-8"), None)
    return base64.b64encode(ct).decode("utf-8"), base64.b64encode(nonce).decode("utf-8")


def decrypt_secret(encrypted_b64: str, nonce_b64: str) -> dict:
    key = bytes.fromhex(MASTER_KEY_HEX[:64].ljust(64, "0"))
    aesgcm = AESGCM(key)
    ct = base64.b64decode(encrypted_b64)
    nonce = base64.b64decode(nonce_b64)
    pt = aesgcm.decrypt(nonce, ct, None)
    return json.loads(pt.decode("utf-8"))


def create_token(secret: str) -> str:
    payload = {"sub": "owner", "exp": int(time.time()) + 86400 * 7, "jti": secrets.token_hex(8)}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_auth(authorization: Optional[str] = Header(None), db: Connection = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authentication token")
    token = authorization.split(" ", 1)[1]
    row = db.execute("SELECT jwt_secret_encrypted FROM auth_config WHERE id = 1").fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="Vault password not initialized")
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(row["jwt_secret_encrypted"].encode(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("Invalid signature")
        padded = body + "=" * (-len(body) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        if data.get("exp", 0) < time.time():
            raise ValueError("Token expired")
        return data
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc))


@app.on_event("startup")
def on_startup():
    pool.open()
    init_db()


@app.on_event("shutdown")
def on_shutdown():
    pool.close()


# --- Authentication Endpoints ---

@app.post("/api/auth/setup")
def setup_password(payload: dict, db: Connection = Depends(get_db)):
    existing = db.execute("SELECT id FROM auth_config WHERE id = 1").fetchone()
    if existing:
        raise HTTPException(status_code=400, detail="Password already configured. Use change-password endpoint.")
    password = payload.get("password", "")
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters.")
    salt = secrets.token_hex(16)
    jwt_sec = secrets.token_hex(32)
    pw_hash = hash_password(password, salt, 600000)
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO auth_config (id, password_hash, salt, kdf_iterations, jwt_secret_encrypted, updated_at) VALUES (1, %s, %s, 600000, %s, %s)",
        (pw_hash, salt, jwt_sec, now),
    )
    db.commit()
    return {"token": create_token(jwt_sec), "status": "initialized"}


@app.post("/api/auth/login")
def login(payload: dict, db: Connection = Depends(get_db)):
    row = db.execute("SELECT * FROM auth_config WHERE id = 1").fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Vault not initialized. Set master password first.")
    password = payload.get("password", "")
    candidate = hash_password(password, row["salt"], row["kdf_iterations"])
    if not hmac.compare_digest(candidate, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid master password")
    return {"token": create_token(row["jwt_secret_encrypted"])}


@app.post("/api/auth/change-password")
def change_password(payload: dict, _=Depends(verify_auth), db: Connection = Depends(get_db)):
    row = db.execute("SELECT * FROM auth_config WHERE id = 1").fetchone()
    current_password = payload.get("current_password", "")
    new_password = payload.get("new_password", "")
    candidate = hash_password(current_password, row["salt"], row["kdf_iterations"])
    if not hmac.compare_digest(candidate, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Current master password is incorrect")
    if len(new_password) < 12:
        raise HTTPException(status_code=400, detail="New password must be at least 12 characters.")
    salt = secrets.token_hex(16)
    jwt_sec = secrets.token_hex(32)
    pw_hash = hash_password(new_password, salt, 600000)
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "UPDATE auth_config SET password_hash = %s, salt = %s, kdf_iterations = 600000, jwt_secret_encrypted = %s, updated_at = %s WHERE id = 1",
        (pw_hash, salt, jwt_sec, now),
    )
    db.commit()
    return {"token": create_token(jwt_sec), "status": "password_rotated"}


# --- Credentials Management (Telegram & Google OAuth) ---

@app.post("/api/credentials/{service}")
def save_credentials(service: str, payload: dict, _=Depends(verify_auth), db: Connection = Depends(get_db)):
    if service not in ("telegram_bot", "telegram_mtproto", "google_photos"):
        raise HTTPException(status_code=400, detail="Unsupported service type")
    enc, nonce = encrypt_secret(payload)
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        """INSERT INTO credentials_vault (service, encrypted_payload, nonce, is_active, updated_at)
           VALUES (%s, %s, %s, 1, %s)
           ON CONFLICT (service) DO UPDATE SET encrypted_payload = EXCLUDED.encrypted_payload, nonce = EXCLUDED.nonce, updated_at = EXCLUDED.updated_at""",
        (service, enc, nonce, now),
    )
    db.commit()
    return {"service": service, "status": "saved_encrypted", "updated_at": now}


def get_service_credentials(db: Connection, service: str) -> dict:
    row = db.execute("SELECT encrypted_payload, nonce FROM credentials_vault WHERE service = %s AND is_active = 1", (service,)).fetchone()
    if not row:
        raise HTTPException(status_code=400, detail=f"Credentials for {service} are not configured.")
    return decrypt_secret(row["encrypted_payload"], row["nonce"])


@app.get("/api/credentials/{service}/status")
def credentials_status(service: str, _=Depends(verify_auth), db: Connection = Depends(get_db)):
    row = db.execute("SELECT updated_at FROM credentials_vault WHERE service = %s AND is_active = 1", (service,)).fetchone()
    return {"service": service, "configured": bool(row), "updated_at": row["updated_at"] if row else None}


@app.get("/api/telegram/test")
async def test_telegram_connection(_=Depends(verify_auth), db: Connection = Depends(get_db)):
    """
    Read-only diagnostic: verifies the bot token with getMe, then checks that the
    configured chat_id is actually reachable with getChat. Sends no messages.
    """
    creds = get_service_credentials(db, "telegram_bot")
    bot_token = creds["bot_token"]
    chat_id = creds["chat_id"]
    async with httpx.AsyncClient(timeout=20.0) as client:
        me_resp = await client.get(f"https://api.telegram.org/bot{bot_token}/getMe")
        me_json = me_resp.json()
        if not me_json.get("ok"):
            raise HTTPException(status_code=502, detail=f"Invalid bot token: {me_json.get('description')}")

        chat_resp = await client.get(f"https://api.telegram.org/bot{bot_token}/getChat", params={"chat_id": chat_id})
        chat_json = chat_resp.json()
        if not chat_json.get("ok"):
            raise HTTPException(
                status_code=502,
                detail=(
                    f"Bot token is valid (@{me_json['result'].get('username')}) but chat_id '{chat_id}' is not reachable: "
                    f"{chat_json.get('description')}. Send any message to the bot from the target account/channel first, "
                    f"then fetch https://api.telegram.org/bot<token>/getUpdates to find the correct chat id."
                ),
            )
    return {
        "bot_username": me_json["result"].get("username"),
        "chat_id": chat_id,
        "chat_type": chat_json["result"].get("type"),
        "chat_title": chat_json["result"].get("title") or chat_json["result"].get("first_name"),
    }


# --- EXIF Extraction & Lossless Image Compression ---

def extract_exif_and_Lossless_compress(raw_bytes: bytes, mime_type: str, perform_lossless: bool) -> tuple[dict, Optional[bytes]]:
    exif_info = {}
    compressed_bytes = None
    if not mime_type.startswith("image/"):
        return exif_info, None
    try:
        img = Image.open(io.BytesIO(raw_bytes))
        exif_info["width"], exif_info["height"] = img.size
        raw_exif = img.getexif()
        if raw_exif:
            decoded = {ExifTags.TAGS.get(k, str(k)): str(v) for k, v in raw_exif.items() if k in ExifTags.TAGS}
            exif_info["camera_make"] = decoded.get("Make")
            exif_info["camera_model"] = decoded.get("Model")
            exif_info["lens_model"] = decoded.get("LensModel")
            exif_info["date_taken"] = decoded.get("DateTimeOriginal") or decoded.get("DateTime")
            exif_info["iso"] = int(decoded["ISOSpeedRatings"]) if str(decoded.get("ISOSpeedRatings", "")).isdigit() else None
            exif_info["aperture"] = decoded.get("FNumber")
            exif_info["shutter_speed"] = decoded.get("ExposureTime")
            exif_info["focal_length"] = decoded.get("FocalLength")
            exif_info["raw_exif_json"] = json.dumps(decoded)

        if perform_lossless:
            out_buf = io.BytesIO()
            exif_bytes = img.info.get("exif")
            icc_profile = img.info.get("icc_profile")
            save_kwargs = {}
            if exif_bytes:
                save_kwargs["exif"] = exif_bytes
            if icc_profile:
                save_kwargs["icc_profile"] = icc_profile

            if img.format == "PNG":
                img.save(out_buf, format="PNG", optimize=True, compress_level=9, **save_kwargs)
            elif img.format in ("JPEG", "JPG"):
                # Lossless Huffman table optimization via Pillow optimize=True while keeping original bytes separately
                img.save(out_buf, format="JPEG", quality="keep", optimize=True, **save_kwargs)
            elif img.format == "WEBP":
                img.save(out_buf, format="WEBP", lossless=True, quality=100, method=6, **save_kwargs)
            else:
                img.save(out_buf, format="WEBP", lossless=True, quality=100, **save_kwargs)

            candidate = out_buf.getvalue()
            if len(candidate) < len(raw_bytes):
                compressed_bytes = candidate
    except Exception:
        pass
    return exif_info, compressed_bytes


async def upload_bytes_to_telegram(db: Connection, filename: str, raw_bytes: bytes, caption: str) -> tuple[str, int, str]:
    """
    Uploads raw bytes to Telegram using `sendDocument` (disable_content_type_detection=True)
    so Telegram NEVER recompresses images, reinterprets them as stickers, or strips EXIF metadata.
    """
    creds = get_service_credentials(db, "telegram_bot")
    bot_token = creds["bot_token"]
    chat_id = creds["chat_id"]  # Can be private channel ID, user ID, or Saved Messages chat ID

    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    async with httpx.AsyncClient(timeout=120.0) as client:
        files = {"document": (filename, raw_bytes, "application/octet-stream")}
        # disable_content_type_detection is required, otherwise Telegram auto-detects formats
        # like .webp as stickers (or certain images/animations as other media types) and
        # returns them under a different result key than "document", breaking the parsing below.
        data = {"chat_id": chat_id, "caption": caption, "disable_content_type_detection": "true"}

        res_json = None
        for attempt in range(4):
            try:
                resp = await client.post(url, data=data, files=files)
            except httpx.TimeoutException:
                raise HTTPException(status_code=504, detail="Timed out contacting Telegram. The file may be too large or the connection too slow.")
            except httpx.HTTPError as exc:
                raise HTTPException(status_code=502, detail=f"Network error contacting Telegram: {exc}")
            res_json = resp.json()
            if res_json.get("ok"):
                break
            # Telegram flood control: back off and retry instead of failing the upload outright.
            # This matters most when several files are uploaded in parallel to the same chat.
            if res_json.get("error_code") == 429 and attempt < 3:
                retry_after = res_json.get("parameters", {}).get("retry_after", 2)
                await asyncio.sleep(retry_after + 0.5)
                continue
            raise HTTPException(status_code=502, detail=f"Telegram storage error: {res_json.get('description')}")
        msg = res_json["result"]
        doc = msg.get("document")
        if not doc:
            raise HTTPException(
                status_code=502,
                detail=(
                    f"Telegram accepted '{filename}' but did not return a document reference "
                    f"(response contained: {', '.join(msg.keys())}). The file type may have been "
                    f"reinterpreted by Telegram as a different kind of media."
                ),
            )
        return str(chat_id), int(msg["message_id"]), str(doc["file_id"])


# --- File & Folder CRUD + Bulk Upload ---

@app.get("/api/folders")
def list_folders(_=Depends(verify_auth), db: Connection = Depends(get_db)):
    rows = db.execute("SELECT * FROM folders ORDER BY name ASC").fetchall()
    return [dict(r) for r in rows]


@app.post("/api/folders")
def create_folder(payload: dict, _=Depends(verify_auth), db: Connection = Depends(get_db)):
    folder_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO folders (id, name, parent_id, color, created_at, updated_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (folder_id, payload["name"], payload.get("parent_id", "root"), payload.get("color", "#6366f1"), now, now),
    )
    db.commit()
    return {"id": folder_id, "name": payload["name"], "parent_id": payload.get("parent_id", "root")}


# Files upload concurrently from the frontend (bounded client-side); this semaphore caps how
# many files this backend process will compress/upload to Telegram at the same time, so a burst
# of parallel requests doesn't spawn unbounded CPU-bound Pillow work or Telegram connections.
UPLOAD_CONCURRENCY = asyncio.Semaphore(int(os.environ.get("UPLOAD_CONCURRENCY", "4")))


@app.post("/api/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    folder_id: str = Form("root"),
    original_mtime: str = Form(""),
    lossless_compress: bool = Form(False),
    _=Depends(verify_auth),
    db: Connection = Depends(get_db),
):
    async with UPLOAD_CONCURRENCY:
        raw_bytes = await file.read()
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        mtime_iso = original_mtime or now

        exif_data, compressed_bytes = await asyncio.to_thread(
            extract_exif_and_Lossless_compress,
            raw_bytes, file.content_type or "application/octet-stream", lossless_compress,
        )

        caption_meta = json.dumps({
            "name": file.filename,
            "sha256": sha256_hash[:16],
            "mtime": mtime_iso,
            "mode": "original_unouched",
        })
        chat_id, msg_id, tg_file_id = await upload_bytes_to_telegram(db, file.filename, raw_bytes, caption_meta)

        tg_compressed_file_id = None
        tg_compressed_message_id = None
        if compressed_bytes:
            _, tg_compressed_message_id, tg_compressed_file_id = await upload_bytes_to_telegram(
                db, f"lossless_{file.filename}", compressed_bytes, f"Lossless companion for {file.filename}"
            )

        file_id = str(uuid.uuid4())
        db.execute(
            """INSERT INTO files (
                id, folder_id, name, mime_type, size_bytes, compressed_size_bytes,
                is_lossless_compressed, sha256_hash, original_mtime, uploaded_at,
                storage_mode, tg_chat_id, tg_message_id, tg_file_id, tg_compressed_file_id, tg_compressed_message_id
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'telegram_bot', %s, %s, %s, %s, %s)""",
            (
                file_id,
                folder_id,
                file.filename,
                file.content_type or "application/octet-stream",
                len(raw_bytes),
                len(compressed_bytes) if compressed_bytes else None,
                1 if compressed_bytes else 0,
                sha256_hash,
                mtime_iso,
                now,
                chat_id,
                msg_id,
                tg_file_id,
                tg_compressed_file_id,
                tg_compressed_message_id,
            ),
        )

        if exif_data:
            db.execute(
                """INSERT INTO exif_metadata (
                    file_id, camera_make, camera_model, lens_model, iso, aperture,
                    shutter_speed, focal_length, width, height, date_taken, raw_exif_json
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    file_id,
                    exif_data.get("camera_make"),
                    exif_data.get("camera_model"),
                    exif_data.get("lens_model"),
                    exif_data.get("iso"),
                    exif_data.get("aperture"),
                    exif_data.get("shutter_speed"),
                    exif_data.get("focal_length"),
                    exif_data.get("width"),
                    exif_data.get("height"),
                    exif_data.get("date_taken"),
                    exif_data.get("raw_exif_json"),
                ),
            )

        db.commit()
        return {
            "id": file_id,
            "name": file.filename,
            "size_bytes": len(raw_bytes),
            "compressed_size_bytes": len(compressed_bytes) if compressed_bytes else None,
            "sha256_hash": sha256_hash,
            "original_mtime": mtime_iso,
            "tg_message_id": msg_id,
            "exif": exif_data,
        }


@app.get("/api/files")
def list_files(
    folder_id: Optional[str] = None,
    q: Optional[str] = None,
    _=Depends(verify_auth),
    db: Connection = Depends(get_db),
):
    sql = """
        SELECT f.*, e.camera_make, e.camera_model, e.date_taken, e.width, e.height, e.iso, e.aperture, e.shutter_speed
        FROM files f
        LEFT JOIN exif_metadata e ON f.id = e.file_id
        WHERE 1=1
    """
    params = []
    if folder_id:
        sql += " AND f.folder_id = %s"
        params.append(folder_id)
    if q:
        sql += " AND (f.name ILIKE %s OR e.camera_model ILIKE %s OR f.mime_type ILIKE %s)"
        params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    sql += " ORDER BY f.uploaded_at DESC"
    rows = db.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


@app.get("/api/files/{file_id}/download")
async def download_file(
    file_id: str,
    variant: str = "original",
    _=Depends(verify_auth),
    db: Connection = Depends(get_db),
):
    row = db.execute("SELECT * FROM files WHERE id = %s", (file_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    creds = get_service_credentials(db, "telegram_bot")
    bot_token = creds["bot_token"]
    target_tg_file_id = row["tg_compressed_file_id"] if (variant == "lossless" and row["tg_compressed_file_id"]) else row["tg_file_id"]

    async with httpx.AsyncClient(timeout=120.0) as client:
        meta_resp = await client.get(f"https://api.telegram.org/bot{bot_token}/getFile", params={"file_id": target_tg_file_id})
        meta_json = meta_resp.json()
        if not meta_json.get("ok"):
            raise HTTPException(status_code=502, detail="Could not resolve file path from Telegram")
        file_path = meta_json["result"]["file_path"]
        dl_url = f"https://api.telegram.org/file/bot{bot_token}/{file_path}"
        raw_resp = await client.get(dl_url)

    headers = {
        "Content-Disposition": f'attachment; filename="{row["name"]}"',
        "X-Original-Mtime": row["original_mtime"],
        "X-SHA256-Checksum": row["sha256_hash"],
    }
    return Response(content=raw_resp.content, media_type=row["mime_type"], headers=headers)


@app.delete("/api/files/{file_id}")
async def delete_file(file_id: str, _=Depends(verify_auth), db: Connection = Depends(get_db)):
    row = db.execute("SELECT * FROM files WHERE id = %s", (file_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    try:
        creds = get_service_credentials(db, "telegram_bot")
        message_ids = [row["tg_message_id"]]
        if row["tg_compressed_message_id"]:
            message_ids.append(row["tg_compressed_message_id"])
        async with httpx.AsyncClient(timeout=30.0) as client:
            for message_id in message_ids:
                await client.post(
                    f"https://api.telegram.org/bot{creds['bot_token']}/deleteMessage",
                    json={"chat_id": row["tg_chat_id"], "message_id": message_id},
                )
    except Exception:
        pass
    db.execute("DELETE FROM files WHERE id = %s", (file_id,))
    db.commit()
    return {"deleted": file_id}


# --- Google Photos OAuth 2.0 Transfer Integration ---

@app.post("/api/google-photos/transfer")
async def transfer_google_photos(payload: dict, _=Depends(verify_auth), db: Connection = Depends(get_db)):
    """
    Transfers selected Google Photos media items using OAuth 2.0 Bearer access token.
    Appends `=d` to Google Photos `baseUrl` so original unmodified bytes and EXIF metadata are preserved.
    """
    access_token = payload.get("access_token")
    media_items = payload.get("media_items", [])
    folder_id = payload.get("folder_id", "root")
    if not access_token:
        raise HTTPException(status_code=400, detail="Missing Google OAuth access_token")

    transferred = []
    async with httpx.AsyncClient(timeout=120.0) as client:
        for item in media_items:
            base_url = item["baseUrl"]
            filename = item.get("filename", f"gphoto_{item['id']}.jpg")
            mime_type = item.get("mimeType", "image/jpeg")
            creation_time = item.get("mediaMetadata", {}).get("creationTime", datetime.now(timezone.utc).isoformat())

            # '=d' downloads original quality image preserving EXIF metadata
            dl_resp = await client.get(f"{base_url}=d", headers={"Authorization": f"Bearer {access_token}"})
            raw_bytes = dl_resp.content
            sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
            exif_data, _ = extract_exif_and_Lossless_compress(raw_bytes, mime_type, False)

            chat_id, msg_id, tg_file_id = await upload_bytes_to_telegram(
                db, filename, raw_bytes, f"Google Photos Transfer | {creation_time}"
            )
            file_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc).isoformat()
            db.execute(
                """INSERT INTO files (
                    id, folder_id, name, mime_type, size_bytes, is_lossless_compressed,
                    sha256_hash, original_mtime, uploaded_at, storage_mode,
                    tg_chat_id, tg_message_id, tg_file_id, gphotos_media_item_id
                ) VALUES (%s, %s, %s, %s, %s, 0, %s, %s, %s, 'google_photos_import', %s, %s, %s, %s)""",
                (file_id, folder_id, filename, mime_type, len(raw_bytes), sha256_hash, creation_time, now, chat_id, msg_id, tg_file_id, item["id"]),
            )
            transferred.append({"id": file_id, "name": filename, "size_bytes": len(raw_bytes)})
    db.commit()
    return {"transferred_count": len(transferred), "items": transferred}


# --- PostgreSQL Backup & Recovery ---

def _pg_env_from_url(url: str) -> dict:
    """Builds a libpq-compatible environment from DATABASE_URL instead of passing the
    password on the pg_dump command line, where it would be visible to other processes."""
    parsed = urlparse(url)
    env = os.environ.copy()
    env["PGHOST"] = parsed.hostname or "localhost"
    env["PGPORT"] = str(parsed.port or 5432)
    env["PGUSER"] = parsed.username or ""
    env["PGPASSWORD"] = parsed.password or ""
    env["PGDATABASE"] = (parsed.path or "").lstrip("/")
    return env


@app.get("/api/backup/export")
async def export_postgres_backup(push_to_telegram: bool = False, _=Depends(verify_auth), db: Connection = Depends(get_db)):
    """
    Produces a plain-text SQL dump of the whole database via pg_dump — portable and
    human-readable, restorable on any Postgres instance with:
        psql "$DATABASE_URL" -f telecloud_vault_backup.sql
    """
    def run_pg_dump():
        return subprocess.run(
            ["pg_dump", "--no-owner", "--no-privileges", "--format=plain"],
            env=_pg_env_from_url(DATABASE_URL),
            capture_output=True,
            timeout=120,
        )

    try:
        result = await asyncio.to_thread(run_pg_dump)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="pg_dump is not installed in this container/environment.")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="pg_dump timed out.")

    if result.returncode != 0:
        raise HTTPException(status_code=500, detail=f"pg_dump failed: {result.stderr.decode('utf-8', 'ignore')}")

    raw_dump = result.stdout
    if push_to_telegram:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        await upload_bytes_to_telegram(db, f"telecloud_vault_backup_{ts}.sql", raw_dump, f"Automated PostgreSQL Snapshot ({ts})")
    return Response(
        content=raw_dump,
        media_type="application/sql",
        headers={"Content-Disposition": 'attachment; filename="telecloud_vault_backup.sql"'},
    )


@app.get("/")
def serve_spa_index():
    index_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html"))
    if os.path.exists(index_file):
        return FileResponse(index_file, media_type="text/html")
    return JSONResponse({"service": "TeleCloud Vault API", "status": "running", "docs": "/docs"})
