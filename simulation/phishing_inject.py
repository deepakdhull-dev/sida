#!/usr/bin/env python3
"""
INC-004 — Phishing simulation (injected logs).

Per the project decisions, a full mail server and phishing platform are
out of scope. This script generates synthetic but realistic email, proxy
and DNS log entries for the logical asset WKS-014 (no VM exists for it)
referencing indicators from threat_feed.csv, and bulk-indexes them into
Elasticsearch on SIEM-01. The injection itself is disclosed in the
Incident Analysis Report, as the project spec permits manual sample-log
injection where live simulation is not possible.

Stdlib only — no external dependencies.

Usage:
    python3 phishing_inject.py
"""
import csv
import json
import os
import random
import urllib.error
import urllib.request
import base64
from datetime import datetime, timedelta, timezone

ES_HOST = "http://192.168.56.10:9200"
ES_USER = "elastic"
ES_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "ChangeMe-Orion-2026!")
INDEX = "phishing-logs"

FEED_PATH = os.path.join(os.path.dirname(__file__), "threat_feed.csv")

WORKSTATION_IP = "192.168.56.14"   # logical IP assigned to WKS-014
VICTIM_USER = "jordan.patel"
VICTIM_EMAIL = "jordan.patel@orionfreight.lab"


def load_feed():
    domains, urls, sender_domains = [], [], []
    with open(FEED_PATH, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["indicator_type"] == "domain":
                domains.append(row["value"])
            elif row["indicator_type"] == "url":
                urls.append(row["value"])
            elif row["indicator_type"] == "sender_domain":
                sender_domains.append(row["value"])
    return domains, urls, sender_domains


def build_events():
    domains, urls, sender_domains = load_feed()
    phishing_domain = domains[0]
    phishing_url = urls[0]
    sender_domain = sender_domains[0]

    # Timeline ends at "now" so the click (DNS + proxy) falls inside the
    # INC-004 rule's 1-minute look-back window on its next run.
    base_time = datetime.now(timezone.utc) - timedelta(seconds=92)
    events = []

    # 1. Email received
    events.append({
        "@timestamp": base_time.isoformat(),
        "event.dataset": "email",
        "event.action": "email-received",
        "host.name": "wks-014",
        "lab.asset_criticality": "medium",
        "user.name": VICTIM_USER,
        "destination.user.email": VICTIM_EMAIL,
        "sender.address": f"payroll-update@{sender_domain}",
        "sender.domain": sender_domain,
        "email.subject": "Action required: verify your payment details",
        "url.full": phishing_url,
        "url.domain": phishing_domain,
    })

    # 2. User clicks the link ~90s later -> DNS lookup
    dns_time = base_time + timedelta(seconds=90)
    events.append({
        "@timestamp": dns_time.isoformat(),
        "event.dataset": "dns",
        "event.action": "dns-query",
        "host.name": "wks-014",
        "lab.asset_criticality": "medium",
        "source.ip": WORKSTATION_IP,
        "user.name": VICTIM_USER,
        "dns.question.name": phishing_domain,
        "dns.answers": ["203.0.113.44"],
    })

    # 3. Proxy log for the outbound request to the phishing URL
    proxy_time = dns_time + timedelta(seconds=2)
    events.append({
        "@timestamp": proxy_time.isoformat(),
        "event.dataset": "proxy",
        "event.action": "web-request",
        "host.name": "wks-014",
        "lab.asset_criticality": "medium",
        "source.ip": WORKSTATION_IP,
        "user.name": VICTIM_USER,
        "destination.domain": phishing_domain,
        "url.domain": phishing_domain,
        "url.full": phishing_url,
        "http.response.status_code": 200,
        "http.request.method": "GET",
    })

    # 4. A couple of benign proxy events shortly before the email, for context
    for i in range(2):
        t = base_time - timedelta(minutes=random.randint(1, 4))
        events.append({
            "@timestamp": t.isoformat(),
            "event.dataset": "proxy",
            "event.action": "web-request",
            "host.name": "wks-014",
            "lab.asset_criticality": "medium",
            "source.ip": WORKSTATION_IP,
            "user.name": VICTIM_USER,
            "destination.domain": "intranet.orionfreight.lab",
            "url.full": "http://intranet.orionfreight.lab/dashboard",
            "http.response.status_code": 200,
            "http.request.method": "GET",
        })

    return events


# Explicit types for the fields the dashboard aggregates on, so they match
# the Beats indices (keyword / ip). Without this, dynamic mapping makes them
# "text" and the combined data view reports a field conflict.
INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"dataset": {"type": "keyword"},
                                     "action": {"type": "keyword"}}},
            "host": {"properties": {"name": {"type": "keyword"}}},
            "user": {"properties": {"name": {"type": "keyword"}}},
            "source": {"properties": {"ip": {"type": "ip"}}},
            "url": {"properties": {"domain": {"type": "keyword"},
                                   "full": {"type": "keyword"}}},
            "destination": {"properties": {"domain": {"type": "keyword"}}},
        }
    }
}


def _request(method, path, body, content_type):
    auth = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    return urllib.request.Request(
        url=f"{ES_HOST}{path}",
        data=body,
        method=method,
        headers={"Content-Type": content_type, "Authorization": f"Basic {auth}"},
    )


def ensure_index():
    req = _request("PUT", f"/{INDEX}", json.dumps(INDEX_MAPPING).encode("utf-8"),
                   "application/json")
    try:
        urllib.request.urlopen(req, timeout=10).close()
        print(f"[*] Created index '{INDEX}' with explicit mapping.")
    except urllib.error.HTTPError as e:
        if e.code == 400 and b"resource_already_exists" in e.read():
            return
        raise


def bulk_index(events):
    lines = []
    for ev in events:
        lines.append(json.dumps({"index": {"_index": INDEX}}))
        lines.append(json.dumps(ev))
    body = ("\n".join(lines) + "\n").encode("utf-8")

    req = _request("POST", "/_bulk?refresh=true", body, "application/x-ndjson")
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read().decode())
        if result.get("errors"):
            print("[!] Some documents failed to index:")
            print(json.dumps(result, indent=2))
        else:
            print(f"[*] Indexed {len(events)} documents into '{INDEX}'.")


if __name__ == "__main__":
    evs = build_events()
    ensure_index()
    bulk_index(evs)
    print("[*] Check Kibana Alerting for the INC-004 feed-match rule firing,")
    print("    and Discover (index pattern 'phishing-logs*') for the raw events.")
