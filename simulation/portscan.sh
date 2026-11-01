#!/usr/bin/env bash
# INC-001 — Port scan simulation
# Run from KALI-ATK01 (192.168.56.50) against UBU-APP01 and WIN-FS01.
# Requires nmap. Should be run while
#   sudo tcpdump -i enp0s8 -w portscan.pcap host 192.168.56.50
# is capturing on IDS-01 (host-only interface) for the packet-level
# evidence screenshot.
set -euo pipefail

TARGETS=("192.168.56.20" "192.168.56.30")   # UBU-APP01, WIN-FS01
OUTDIR="$(dirname "$0")/portscan-results"
mkdir -p "$OUTDIR"

for t in "${TARGETS[@]}"; do
  echo "[*] SYN scanning $t (ports 1-1024)..."
  sudo nmap -sS -p 1-1024 -T4 -oN "${OUTDIR}/scan_${t}.txt" "$t"
  echo "[*] Done: ${OUTDIR}/scan_${t}.txt"
  echo
done

echo "[*] All scans complete. Check Kibana Alerting for the"
echo "    'LAB CUSTOM Possible TCP Port Scan Detected' rule firing."
