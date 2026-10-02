#!/bin/sh
# Entrypoint del backend Anisakys (montado por docker-compose).
# 1. retry alembic upgrade head (espera a que postgres acepte conexiones)
# 2. arranca la API Flask en :8091 con la master key del entorno
set -e
cd /app

echo "[entrypoint] running alembic migrations (retry up to 30x)..."
for i in $(seq 1 30); do
  if alembic upgrade head 2>&1; then
    echo "[entrypoint] migrations OK"
    break
  fi
  echo "[entrypoint] alembic attempt $i/30 failed, retrying in 3s..."
  sleep 3
  if [ "$i" = "30" ]; then
    echo "[entrypoint] FATAL: alembic never succeeded." >&2
    exit 1
  fi
done

echo "[entrypoint] starting Anisakys API on :8091"
exec python anisakys.py --start-api --api-port 8091 --api-key "$ANISAKYS_API_KEY"
