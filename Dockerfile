FROM python@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b AS runtime-build
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY infra/runtime /runtime-build
RUN python /runtime-build/build_runtime.py patch-http
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
RUN python /runtime-build/build_runtime.py build-sqlite --assets /runtime-assets

FROM python@sha256:1148dbb014615300fa7e713b2f94f550c0d1c69780c0805f84f093ceee34dd0b AS patched-runtime
ENV PYTHONDONTWRITEBYTECODE=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY --from=runtime-build /usr/local/lib/python3.12/http/client.py /usr/local/lib/python3.12/http/client.py
COPY --from=runtime-build /runtime-assets /runtime-assets
COPY infra/runtime /opt/secops-runtime/install
RUN python /opt/secops-runtime/install/build_runtime.py install-library --assets /runtime-assets \
    && python /opt/secops-runtime/install/build_runtime.py bootstrap-pip --assets /runtime-assets \
    && cp /runtime-assets/runtime.json /opt/secops-runtime/runtime.json \
    && cp /runtime-assets/sqlite3.h /usr/local/include/sqlite3.h \
    && mkdir -p /usr/local/lib/pkgconfig \
    && cp /runtime-assets/sqlite3.pc /usr/local/lib/pkgconfig/sqlite3.pc \
    && rm -r /runtime-assets \
    && python /opt/secops-runtime/install/build_runtime.py verify --assets /opt/secops-runtime
FROM patched-runtime AS project-wheel
WORKDIR /build/project
COPY pyproject.toml README.md ./
COPY app ./app
RUN python -m pip install --only-binary=:all: --require-hashes -r /opt/secops-runtime/install/requirements/build.lock \
    && python /opt/secops-runtime/install/build_runtime.py build-project --assets /project-wheel

FROM patched-runtime AS application

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=300 \
    PIP_RETRIES=5 \
    ANALYZER_MODE=rule \
    AUDIT_BACKEND=jsonl \
    AUDIT_LOG_PATH=/data/audit.jsonl \
    CASE_LOG_PATH=/data/cases.jsonl \
    OUTBOX_LOG_PATH=/data/integration-outbox.jsonl \
    ZERO_TRUST_DB_PATH=/data/zero-trust.sqlite3

WORKDIR /app

COPY pyproject.toml README.md ./
COPY app ./app
COPY scripts ./scripts
COPY --from=project-wheel /project-wheel /project-wheel

RUN --mount=type=cache,target=/root/.cache/pip \
    groupadd --gid 10001 secops \
    && useradd --uid 10001 --gid secops --home-dir /app --no-create-home --shell /usr/sbin/nologin secops \
    && python -m pip install --only-binary=:all: --require-hashes -r /opt/secops-runtime/install/requirements/runtime.lock \
    && python -m pip install --no-index --no-deps --require-hashes -r /project-wheel/project.lock \
    && python -m pip check \
    && rm -r /project-wheel \
    && mkdir -p /data \
    && chown secops:secops /data

USER secops

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=2)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
