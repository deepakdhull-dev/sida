#!/usr/bin/env bash
# Creates the four Kibana Alerting rules (INC-001..INC-004) via the
# Alerting REST API. Run from a host that can reach Kibana on
# 192.168.56.10:5601 (SIEM-01 itself, or the VirtualBox host).
#
# Requires python3 (stdlib only, no pip packages needed).
set -euo pipefail

export KIBANA_URL="${KIBANA_URL:-http://192.168.56.10:5601}"
export ES_USER="${ES_USER:-elastic}"
export ES_PASSWORD="${ES_PASSWORD:?Set ES_PASSWORD to the elastic superuser password before running}"

cd "$(dirname "$0")"
echo "[*] Creating detection rules against ${KIBANA_URL} ..."
python3 _post_rules.py
