# syntax=docker/dockerfile:1
# Anisakys backend image.
#
#   docker build -t anisakys .
#
# The default command (entrypoint-backend.sh) applies the database migrations
# and starts the API. Other roles reuse the image with a different command and
# serve no HTTP: the scheduler role writes a heartbeat file, so override the
# healthcheck with `python -m src.runtime.health`; for the scanner role disable
# it (compose: `healthcheck: {disable: true}`).
#
# Runtime configuration comes from the environment (compose `env_file`):
# .env files are excluded from the build context and never baked in.
# Writable paths for the unprivileged user: /app/logs, /app/screenshots,
# /app/attachments and /app/data (point OFFSET_FILE/QUERIES_FILE there).

ARG PYTHON_IMAGE=python:3.12.15-slim-trixie

# --- dependencies ------------------------------------------------------------
# The tag is pinned in PYTHON_IMAGE above; hadolint cannot resolve build args.
# hadolint ignore=DL3006
FROM ${PYTHON_IMAGE} AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

# --- runtime -----------------------------------------------------------------
# hadolint ignore=DL3006
FROM ${PYTHON_IMAGE} AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    DEBIAN_FRONTEND=noninteractive

# whois and dig are executed by the abuse-contact lookup (subprocess).
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 anisakys \
    && useradd --system --uid 10001 --gid anisakys --home-dir /app --no-create-home \
        --shell /usr/sbin/nologin anisakys

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# Code stays root-owned (read-only for the service user); only data dirs are writable.
COPY . .
RUN mkdir -p logs screenshots attachments data \
    && chown anisakys:anisakys logs screenshots attachments data

# Numeric uid/gid so orchestrators can verify runAsNonRoot.
USER 10001:10001

EXPOSE 8091

# Exits non-zero (unhealthy) on connection errors and non-2xx responses.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/v1/health' % os.environ.get('ANISAKYS_API_PORT', '8091'), timeout=4)"]

CMD ["sh", "/app/entrypoint-backend.sh"]
