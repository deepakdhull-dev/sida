#!/usr/bin/env bash
# Run once, after `docker compose up -d elasticsearch` reports healthy and
# BEFORE starting the kibana container. Reads ELASTIC_PASSWORD and
# KIBANA_SYSTEM_PASSWORD from .env in the same directory.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck disable=SC1091
source .env

curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  -X POST "http://localhost:9200/_security/user/kibana_system/_password" \
  -H "Content-Type: application/json" \
  -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}"

echo
echo "[*] kibana_system password set. Now run: docker compose up -d kibana"
