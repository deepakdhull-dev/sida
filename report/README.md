# Report generation — not yet started

The Incident Analysis Report (Deliverable 2, single PDF, academic
submission format per the locked project decisions) is written after the
lab has been run, because it requires real evidence, not placeholder text.

## What is needed from you, per incident (INC-001 to INC-004)

a. **Incident Summary** — incident type, date/time, affected asset(s),
   severity (already fixed: Low / High / Critical / Medium respectively).
b. **Detection and Analysis** — which rule fired, the triggering alert
   screenshot, the matching raw log lines from Discover, tools used
   (Suricata / Filebeat / Sysmon / Winlogbeat / the injection script),
   and a short timeline (first event → detection → last related event).
c. **Mitigation and Recovery** — per decision D26-b, these are
   *documented, not executed*: write the action that would be taken
   (isolate host, block source IP, disable account, remove dropped file,
   remove phishing indicator) and state plainly that it was not performed
   in this lab run.
d. **Future Recommendations** — drawn from the spec's own lists: patch
   management, policy updates, firewall/IDS rule tuning, user awareness
   training, network segmentation, Zero Trust.

Also needed once, for the whole report:
- Deliverable 1 evidence (VM/network settings, service status, Discover
  ingestion views, chrony/w32time status, rule list) — see RUNBOOK.md
  steps 3–10.
- Deliverable 3 evidence (four dashboard section screenshots) — RUNBOOK.md
  step 13.
- The Orion Freight Ltd. asset table and severity model (already defined
  in the project decisions; will be reproduced in the report's
  Environment section without changes).

## Next step
Once the above is collected, the report will be drafted section by
section and exported as a PDF.
