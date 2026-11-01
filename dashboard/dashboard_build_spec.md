# Dashboard build spec — "Orion Freight SOC Overview"

Built manually in Kibana (Analytics → Dashboard → Create dashboard) with
Lens panels, after the data views below exist and all four simulations
have run at least once. One dashboard, four sections, matching
Deliverable 3.

## Data views to create first
(Stack Management → Data Views → Create data view)

| Name | Index pattern | Time field | Notes |
|---|---|---|---|
| `filebeat` | `filebeat-*` | `@timestamp` | |
| `winlogbeat` | `winlogbeat-*` | `@timestamp` | |
| `phishing-logs` | `phishing-logs*` | `@timestamp` | |
| `lab-events` | `filebeat-*,winlogbeat-*,phishing-logs*` | `@timestamp` | All raw source events in one view |
| `lab-alerts` | `.alerts-stack.alerts-default*` | `@timestamp` | Enable **"Allow hidden and system indices"**. Holds the alerts written by the four rules |

Why two kinds of source: alert documents (`lab-alerts`) carry the rule
name and tags but **not** `host.name` or `source.ip`. Panels that need
host or IP are therefore built on `lab-events`, filtered to the events the
detection rules match.

## Detection filter (used by several panels)
Paste this as the panel-level query (KQL) on `lab-events` panels marked
"detection filter". It is the union of the four rule queries in
`detection/_post_rules.py`:

```
(event.dataset:"suricata.eve" AND (suricata.eve.alert.signature_id:1000001 OR rule.id:"1000001"))
OR (event.dataset:"system.auth" AND event.outcome:"failure" AND host.name:"ubu-app01")
OR (host.name:"win-fs01" AND ((winlog.channel:"Microsoft-Windows-Sysmon/Operational" AND winlog.event_id:(1 OR 3 OR 11)) OR (winlog.channel:"Microsoft-Windows-Windows Defender/Operational" AND winlog.event_id:(1116 OR 1117))))
OR (url.domain:("secure-paymentportal-update.com" OR "orion-hr-benefits-verify.net" OR "document-share-verify.com") OR destination.domain:("secure-paymentportal-update.com" OR "orion-hr-benefits-verify.net" OR "document-share-verify.com"))
```

The last line is the output of `python3 detection/feed_rule_generator.py`;
regenerate it if `threat_feed.csv` changes.

## Section 1 — Incident Trends
**Panel:** "Alerts Over Time by Rule"
- Data view: `lab-alerts`
- Type: Bar vertical stacked
- Horizontal axis: `@timestamp` (date histogram, auto interval)
- Vertical axis: Count
- Breakdown: Top values of `kibana.alert.rule.name`

## Section 2 — Alert Activity
**Panel A:** "Alert Count by Severity"
- Data view: `lab-alerts`
- Type: Donut
- Slice by: **Filters**, four entries:
  - `kibana.alert.rule.tags:"severity-low"` → label `Low`
  - `kibana.alert.rule.tags:"severity-medium"` → label `Medium`
  - `kibana.alert.rule.tags:"severity-high"` → label `High`
  - `kibana.alert.rule.tags:"severity-critical"` → label `Critical`
- Metric: Count

**Panel B:** "Alert Detail Table"
- Data view: `lab-events`, detection filter applied
- Type: Table
- Rows, in order:
  1. **Filters** (label each with rule name + severity):
     - `event.dataset:"suricata.eve"` → `INC-001 Port Scan (Low)`
     - `event.dataset:"system.auth"` → `INC-002 SSH Brute Force (High)`
     - `host.name:"win-fs01"` → `INC-003 Malware Execution (Critical)`
     - `host.name:"wks-014"` → `INC-004 Phishing Indicator Match (Medium)`
  2. Top values of `host.name`
  3. Top values of `source.ip` (enable "Include documents without this field")
- Metrics: Last value / Maximum of `@timestamp` (label "Last seen"), Count
- Sort: "Last seen" descending

(The Filters rows only need to separate the incidents. The detection
filter has already narrowed the events to what each rule matches.)

## Section 3 — Affected Assets
**Panel:** "Alerts by Affected Asset"
- Data view: `lab-events`, detection filter applied
- Type: Bar horizontal
- Vertical axis: **Filters**, three entries:
  - `host.name:"ubu-app01" OR destination.ip:"192.168.56.20"` → `UBU-APP01 (High)`
  - `host.name:"win-fs01" OR destination.ip:"192.168.56.30"` → `WIN-FS01 (Critical)`
  - `host.name:"wks-014"` → `WKS-014 (Medium)`
- Horizontal axis: Count

`destination.ip` is used for INC-001 because Suricata events are shipped
by the sensor (`host.name: ids-01`), while the scanned assets are the
destinations.

## Section 4 — Security Observations
**Panel A:** "Top Source IPs" — `lab-events`, detection filter, Table, Top
values of `source.ip` (size 10), Count.

**Panel B:** "Failed Logins by User" — `filebeat`, query
`event.dataset:"system.auth" AND event.outcome:"failure"`, Table, Top
values of `user.name` (size 10), Count.

**Panel C:** "Suricata Signatures Fired" — `filebeat`, query
`event.dataset:"suricata.eve" AND event.kind:"alert"`, Table, Top values
of `rule.name` (fall back to `suricata.eve.alert.signature` if `rule.name`
is empty in Discover), Count.

**Panel D:** "Threat Feed Matches" — `phishing-logs`, query = output of
`python3 detection/feed_rule_generator.py`, Table, rows Top values of
`url.domain`, `user.name`, `host.name`. Metrics: Maximum of `@timestamp`
and Count.

## Layout
Arrange top to bottom: Section 1 (full width) → Section 2 (A left, B
right) → Section 3 (full width) → Section 4 (2x2 grid of A–D). Add a
Markdown panel above each section with its title ("1. Incident Trends",
etc.) so each screenshot is self-labelled.

## Save
Set the time range to cover all four simulations, save as **"Orion
Freight SOC Overview"** with "Store time with dashboard" on, tag `lab`.
Screenshot each section separately for the Deliverable 3 evidence.
