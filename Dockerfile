FROM python:3.12-slim-bookworm

WORKDIR /app

# postgresql-client-18 is installed from the official PGDG apt repo for the /api/backup/export
# endpoint's pg_dump call, matching the external Neon PostgreSQL 18 instance this app connects
# to. If you switch to a different external PostgreSQL instance later, change
# "postgresql-client-18" below to match its major version (e.g. postgresql-client-16, -17),
# since pg_dump refuses to run against a server newer than itself.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg-turbo-progs optipng ca-certificates curl gnupg && \
    install -d /usr/share/postgresql-common/pgdg && \
    curl -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc --fail https://www.postgresql.org/media/keys/ACCC4CF8.asc && \
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list && \
    apt-get update && apt-get install -y --no-install-recommends postgresql-client-18 && \
    apt-get purge -y gnupg curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

EXPOSE 8000

# Shell form so ${PORT} expands: Render (and some other PaaS hosts) inject their own PORT env
# var and expect the app to bind to it; falls back to 8000 for local `docker compose up`.
CMD uvicorn backend.app:app --host 0.0.0.0 --port ${PORT:-8000}
