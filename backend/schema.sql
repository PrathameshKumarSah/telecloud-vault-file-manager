-- TeleCloud Vault PostgreSQL Schema

CREATE TABLE IF NOT EXISTS auth_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    kdf_iterations INTEGER NOT NULL DEFAULT 600000,
    jwt_secret_encrypted TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials_vault (
    service TEXT PRIMARY KEY, -- 'telegram_bot', 'telegram_mtproto', 'google_photos'
    encrypted_payload TEXT NOT NULL, -- AES-256-GCM encrypted JSON
    nonce TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    parent_id TEXT REFERENCES folders(id) ON DELETE CASCADE,
    color TEXT DEFAULT '#6366f1',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_folders_parent ON folders(parent_id);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    folder_id TEXT REFERENCES folders(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    compressed_size_bytes INTEGER,
    is_lossless_compressed INTEGER NOT NULL DEFAULT 0,
    sha256_hash TEXT NOT NULL,
    original_mtime TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    storage_mode TEXT NOT NULL, -- 'telegram_bot', 'saved_messages', 'google_photos_import'
    tg_chat_id TEXT NOT NULL,
    tg_message_id INTEGER NOT NULL,
    tg_file_id TEXT NOT NULL,
    tg_compressed_file_id TEXT,
    tg_compressed_message_id INTEGER,
    gphotos_media_item_id TEXT,
    starred INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_files_folder ON files(folder_id);
CREATE INDEX IF NOT EXISTS idx_files_name ON files(name);
CREATE INDEX IF NOT EXISTS idx_files_mime ON files(mime_type);

CREATE TABLE IF NOT EXISTS exif_metadata (
    file_id TEXT PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
    camera_make TEXT,
    camera_model TEXT,
    lens_model TEXT,
    iso INTEGER,
    aperture TEXT,
    shutter_speed TEXT,
    focal_length TEXT,
    width INTEGER,
    height INTEGER,
    date_taken TEXT,
    gps_latitude REAL,
    gps_longitude REAL,
    raw_exif_json TEXT
);

CREATE TABLE IF NOT EXISTS sync_jobs (
    id TEXT PRIMARY KEY,
    job_type TEXT NOT NULL, -- 'google_photos_import', 'telegram_backup'
    status TEXT NOT NULL, -- 'queued', 'running', 'completed', 'failed'
    total_items INTEGER NOT NULL DEFAULT 0,
    processed_items INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    started_at TEXT NOT NULL,
    completed_at TEXT
);
