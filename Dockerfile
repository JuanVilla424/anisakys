# Backend Anisakys — imagen para el stack docker-compose local.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 curl libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# hadolint ignore=DL3013
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

EXPOSE 8091
