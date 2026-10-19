#!/bin/sh
set -e
mkdir -p /data/logs /data/certs

echo "[entrypoint] orchestrator-acme-cert-manager starting"
echo "[entrypoint] lego: $(lego --version 2>&1 | head -1)"
echo "[entrypoint] SERVERS_FILE=${SERVERS_FILE:-<unset>}  CONFIG_DIR=${CONFIG_DIR:-<unset>}  DATA_DIR=${DATA_DIR:-<unset>}"

# Preflight: refuses to start on a configuration that would silently lose
# changes (unmounted config path, legacy /data/servers.json only). Set
# STRICT_STARTUP=false to downgrade fatal findings to warnings.
if ! python -m app.cli check; then
  echo "[entrypoint] preflight FAILED — fix the items above (or set STRICT_STARTUP=false to override)" >&2
  exit 1
fi
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
