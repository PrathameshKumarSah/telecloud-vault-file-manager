# TeleCloud Vault — Personal File Management Web App (Telegram + PostgreSQL + Google Photos)

A responsive, mobile-friendly personal cloud file manager that uses your **Private Telegram Bot** as an unlimited zero-cost storage backend, your own **external PostgreSQL** instance for metadata, folder indexing, and EXIF querying, and **Google Photos OAuth 2.0** for lossless photo transfers.

## Key Capabilities
1. **Unaltered Original Quality & EXIF Preservation**:
   - Uploads every image and file via Telegram's `sendDocument` API (`application/octet-stream`, `disable_content_type_detection=True`) rather than `sendPhoto`, ensuring zero server-side recompression, no accidental reinterpretation as stickers/other media, intact EXIF metadata (Camera model, Lens, ISO, Aperture, Shutter Speed, Date Taken), and SHA-256 integrity verification.
   - Preserves original `lastModified` file timestamps across upload and download (`X-Original-Mtime` + the `original_mtime` column).
   - Uploads run concurrently (bounded, with automatic retry on Telegram flood-control) so a batch of files finishes much faster than one-at-a-time.
2. **Non-Destructive Lossless Image Compression**:
   - Optional lossless optimization pipeline (WebP Lossless / PNG ZLIB level 9 / JPEG Huffman table optimization retaining EXIF & ICC color profiles) stored as a companion message in the same chat, while keeping your original file 100% untouched. Deleting a file removes both the original and the companion message from Telegram.
3. **Strong Personal Password Authentication & AES-256-GCM Credentials Vault**:
   - Single-owner authentication using **PBKDF2-HMAC-SHA256 (600,000 iterations)** + signed JWT tokens.
   - Telegram bot token and Google OAuth tokens are encrypted at rest in PostgreSQL using **AES-256-GCM**.
4. **Google Photos OAuth 2.0 Integration**:
   - Backend endpoint (`/api/google-photos/transfer`) accepts a Google OAuth access token and media item list, fetching original bytes via the `=d` baseUrl parameter so EXIF headers and timestamps remain intact. The frontend's Google Photos tab is a UI preview — wiring up a real OAuth consent flow and Photos Library API listing is left as a follow-up.
5. **PostgreSQL Backup & Recovery**:
   - One-click `pg_dump` snapshot (plain SQL — portable and restorable on any Postgres instance with `psql -f`), with an option to also push the snapshot straight to your Telegram chat.

## Quick Start (Docker Compose)

This app connects to a PostgreSQL database you already have (a managed instance like Supabase/Neon/RDS, or your own server) — docker-compose does not bundle a database, so your data's lifecycle is entirely independent of the app containers.

```bash
cp .env.example .env
# Generate a random 32-byte hex key for VAULT_MASTER_KEY:
openssl rand -hex 32
# Set a real DATABASE_URL in .env pointing at your external Postgres instance, then:
docker compose up -d --build
```

The app creates its schema automatically on first boot (`CREATE TABLE IF NOT EXISTS`) — the database just needs to already exist with a user that can create tables. Open `http://localhost` (or `http://localhost:8000`) to initialize your Master Password and configure your Telegram Bot credentials.

### Getting your Telegram bot token and chat ID
1. Message [@BotFather](https://t.me/BotFather) to create a bot and get its token.
2. Send any message to your new bot from the Telegram account/chat you want files stored in.
3. Fetch `https://api.telegram.org/bot<TOKEN>/getUpdates` — your chat ID is in the response.
4. Put both values in `.env` (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`) before `docker compose up`, or configure them later in the app's Credentials & Security tab. Use **Verify Telegram Handshake** there to confirm the chat ID is actually reachable before uploading.

## Native Windows (no Docker)
Requires a PostgreSQL server already running locally (e.g. from the [official installer](https://www.postgresql.org/download/windows/)) with a database created for the app. Run `run_windows_python.bat`, or set `DATABASE_URL` yourself (e.g. `postgresql://telecloud:telecloud@localhost:5432/telecloud_vault`) before starting `uvicorn backend.app:app`.
