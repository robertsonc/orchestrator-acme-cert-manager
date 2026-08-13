#!/usr/bin/env bash
# Host prep: create the data layout and copy example config/env into place.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
data="${here}/data"

echo ">> Creating data directories under ${data}"
mkdir -p "${data}/certs" "${data}/logs" "${data}/ssh"

if [[ ! -f "${here}/config/servers.json" ]]; then
  cp "${here}/config/servers.example.json" "${here}/config/servers.json"
  echo ">> Created config/servers.json from example — edit it before starting."
fi

if [[ ! -f "${here}/.env" ]]; then
  cp "${here}/.env.example" "${here}/.env"
  echo ">> Created .env from example — fill in your secrets before starting."
fi

echo ">> Place the tool's SSH private key at ${data}/ssh/orch_restart (chmod 600)."
echo ">> Done. Next: edit config/servers.json and .env, then: docker compose up -d --build"
