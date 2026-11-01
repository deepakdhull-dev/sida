#!/usr/bin/env python3
"""
Builds the INC-004 detection query directly from simulation/threat_feed.csv,
so the rule and the feed never drift apart.

Used two ways:
  1. Imported by _post_rules.py when the INC-004 Kibana rule is created.
  2. Run standalone to print the same query for the dashboard's
     "Threat Feed Matches" panel filter:
         python3 feed_rule_generator.py

Operators are uppercase (AND/OR) so the same string is valid both as a
Lucene query_string (used by the .es-query rule) and as KQL (used in the
dashboard), since KQL operators are case-insensitive.
"""
import csv
import os

FEED_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "simulation", "threat_feed.csv")


def build_query(feed_path=FEED_PATH):
    domains = []
    with open(feed_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["indicator_type"] == "domain":
                domains.append(row["value"])

    if not domains:
        raise SystemExit("No domain-type indicators found in threat_feed.csv")

    quoted = " OR ".join(f'"{d}"' for d in domains)
    return f'(url.domain:({quoted}) OR destination.domain:({quoted}))'


if __name__ == "__main__":
    print(build_query())
