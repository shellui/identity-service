FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SQLITE_PATH=/app/data/db.sqlite3 \
    DEBUG=false

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

COPY . /app

RUN python manage.py collectstatic --noinput

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

VOLUME ["/app/data"]

EXPOSE 8000

ENTRYPOINT ["/app/tools/docker-entrypoint.sh"]
