FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core iputils-ping && rm -rf /var/lib/apt/lists/*

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app/uptime-monitor-service

COPY requirements.txt ./
RUN pip install --upgrade pip setuptools wheel \
    && pip install -r requirements.txt \
    && playwright install --with-deps chromium

COPY backend ./backend
COPY frontend ./frontend
COPY docs ./docs
COPY run.py README.md INSTALL.md ./
COPY migrate_sqlite_to_postgres.py ./

RUN mkdir -p /app/uptime-monitor-service/screenshots

EXPOSE 8080

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1", "--proxy-headers"]
