FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=300 \
    PIP_RETRIES=5 \
    ANALYZER_MODE=rule \
    AUDIT_BACKEND=jsonl \
    AUDIT_LOG_PATH=/data/audit.jsonl \
    CASE_LOG_PATH=/data/cases.jsonl

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app

RUN --mount=type=cache,target=/root/.cache/pip \
    groupadd --gid 10001 secops \
    && useradd --uid 10001 --gid secops --home-dir /app --no-create-home --shell /usr/sbin/nologin secops \
    && pip install . \
    && mkdir -p /data \
    && chown secops:secops /data

USER secops

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
