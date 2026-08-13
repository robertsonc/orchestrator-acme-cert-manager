#!/bin/sh
set -e
mkdir -p /data/logs /data/certs

echo "[entrypoint] orchestrator-acme-cert-manager starting"
echo "[entrypoint] lego: $(lego --version 2>&1 | head -1)"
python -m app.cli list || true

# Optional one-shot forced renewal on boot (testing)
if [ "${FORCE_RENEW}" = "true" ]; then
  echo "[entrypoint] FORCE_RENEW=true — running renew-all once"
  python -m app.cli renew-all --force || true
fi

# Web UI in the background
python -m app.webui.server &

# Foreground: supercronic scheduler
echo "[entrypoint] starting supercronic"
exec supercronic /app/crontab
