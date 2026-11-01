#!/usr/bin/env python3
"""
Worker invoked by create_rules.sh. Creates the four Kibana Alerting rules
for this project via the Alerting API (rule_type_id ".es-query").

Reads connection details from environment variables set by create_rules.sh:
    KIBANA_URL, ES_USER, ES_PASSWORD

Queries are Elasticsearch query_string (Lucene) syntax, so boolean
operators MUST be uppercase AND / OR. Lowercase "and"/"or" would be read
as search terms and the rules would match the wrong documents.

Field names assume the Filebeat suricata/system modules' and Winlogbeat's
default ECS mappings. The Filebeat suricata module's dataset is
"suricata.eve" (fileset name), not "suricata.alert"; the signature id is
kept as suricata.eve.alert.signature_id and copied to rule.id, so INC-001
checks both. Verify in Discover before running if your stack version differs.
"""
import json
import os
import base64
import urllib.request
import urllib.error

from feed_rule_generator import build_query as phishing_query

KIBANA_URL = os.environ.get("KIBANA_URL", "http://192.168.56.10:5601")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ.get("ES_PASSWORD", "ChangeMe-Orion-2026!")


def es_query_rule(name, index_pattern, query_string, threshold, window_minutes,
                   group_by_field=None, tags=None):
    params = {
        "searchType": "esQuery",
        "esQuery": json.dumps({"query": {"query_string": {"query": query_string}}}),
        "index": [index_pattern],
        "timeField": "@timestamp",
        "size": 100,
        "thresholdComparator": ">=",
        "threshold": [threshold],
        "timeWindowSize": window_minutes,
        "timeWindowUnit": "m",
    }
    if group_by_field:
        params["aggType"] = "count"
        params["groupBy"] = "top"
        params["termField"] = group_by_field
        params["termSize"] = 10

    return {
        "name": name,
        "rule_type_id": ".es-query",
        "consumer": "alerts",
        "schedule": {"interval": "1m"},
        "params": params,
        "actions": [],
        "tags": tags or ["lab", "orion-freight"],
        "notify_when": "onActiveAlert",
    }


RULES = [
    es_query_rule(
        name="INC-001 Port Scan Detected (Low)",
        index_pattern="filebeat-*",
        query_string=('event.dataset:"suricata.eve" AND '
                      '(suricata.eve.alert.signature_id:1000001 OR rule.id:"1000001")'),
        threshold=1,
        window_minutes=1,
        tags=["lab", "severity-low", "reconnaissance"],
    ),
    es_query_rule(
        name="INC-002 SSH Brute Force Detected (High)",
        index_pattern="filebeat-*",
        query_string='event.dataset:"system.auth" AND event.outcome:"failure" AND host.name:"ubu-app01"',
        threshold=10,
        window_minutes=2,
        group_by_field="source.ip",
        tags=["lab", "severity-high", "brute-force"],
    ),
    es_query_rule(
        name="INC-003 Malware Execution Detected (Critical)",
        index_pattern="winlogbeat-*",
        query_string=(
            'host.name:"win-fs01" AND '
            '((winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND '
            'winlog.event_id:(1 OR 3 OR 11)) OR '
            '(winlog.channel:"Microsoft-Windows-Windows Defender/Operational" AND '
            'winlog.event_id:(1116 OR 1117)))'
        ),
        threshold=1,
        window_minutes=1,
        tags=["lab", "severity-critical", "malware"],
    ),
    es_query_rule(
        name="INC-004 Phishing Indicator Match (Medium)",
        index_pattern="phishing-logs*",
        query_string=phishing_query(),
        threshold=1,
        window_minutes=1,
        tags=["lab", "severity-medium", "phishing"],
    ),
]


def create_rule(rule_body):
    auth = base64.b64encode(f"{ES_USER}:{ES_PASSWORD}".encode()).decode()
    req = urllib.request.Request(
        url=f"{KIBANA_URL}/api/alerting/rule",
        data=json.dumps(rule_body).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Authorization": f"Basic {auth}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read().decode())
            print(f"[+] Created: {rule_body['name']}  (id={result.get('id')})")
    except urllib.error.HTTPError as e:
        print(f"[!] Failed: {rule_body['name']}  HTTP {e.code}")
        print("    " + e.read().decode()[:500])


if __name__ == "__main__":
    for rule in RULES:
        create_rule(rule)
    print("\n[*] Verify in Kibana: Stack Management -> Rules.")
