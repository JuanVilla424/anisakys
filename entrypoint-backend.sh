#!/bin/sh
# Entrypoint del backend Anisakys (montado por docker-compose).
# 1. espera a que postgres acepte conexiones y aplica alembic upgrade head una vez
# 2. sirve la API con gunicorn (src.api.wsgi) en :8091
#
# gunicorn escucha en 0.0.0.0 *dentro del contenedor* a propósito: el loopback
# del contenedor no es alcanzable desde fuera, y el puerto solo queda expuesto a
# través del mapeo de puertos / la red de docker-compose. Fuera de contenedores,
# el servidor de desarrollo (anisakys.py --start-api) escucha en API_BIND_HOST
# (127.0.0.1 por defecto) y nunca activa el debugger de Werkzeug.
#
# Este proceso es solo el rol API: no arranca los trabajos en segundo plano
# (envío de reportes de abuso, monitor de takedown, re-escaneo GSB, schedulers);
# esos corren en el rol scheduler, como proceso/servicio aparte.
#
# Ajustes: GUNICORN_WORKERS (2), GUNICORN_THREADS (4), GUNICORN_TIMEOUT (120 s).
# Con más de un worker, configurar RATELIMIT_STORAGE_URL=redis://... para que los
# límites de peticiones se compartan entre workers.
set -e
cd /app

# Wait for the database (alembic resolves DATABASE_URL like the app does),
# then migrate exactly once: a failing migration must stop the container
# immediately instead of being retried as if it were a connectivity issue.
echo "[entrypoint] waiting for the database (up to 30 attempts)..."
attempt=0
until alembic current >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "[entrypoint] FATAL: database unreachable; last error:" >&2
    alembic current >&2 || true
    exit 1
  fi
  sleep 3
done

echo "[entrypoint] applying migrations (alembic upgrade head)..."
alembic upgrade head
echo "[entrypoint] migrations OK"

echo "[entrypoint] starting Anisakys API (gunicorn) on :8091"
exec gunicorn \
  --bind 0.0.0.0:8091 \
  --workers "${GUNICORN_WORKERS:-2}" \
  --worker-class gthread \
  --threads "${GUNICORN_THREADS:-4}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" \
  --access-logfile - \
  "src.api.wsgi:create_app()"
