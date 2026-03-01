#!/usr/bin/env python3
"""
check_metrics.py — Query Prometheus and print a health dashboard in the terminal.

Usage:
    python3 check_metrics.py --prometheus http://localhost:9090
"""

import argparse
import json
from urllib.request import urlopen, Request
from urllib.parse import urlencode
from urllib.error import URLError


def query(base_url: str, promql: str) -> str | None:
    url = base_url.rstrip("/") + "/api/v1/query?" + urlencode({"query": promql})
    try:
        with urlopen(Request(url), timeout=5) as resp:
            data = json.loads(resp.read())
            if data["status"] == "success" and data["data"]["result"]:
                return data["data"]["result"][0]["value"][1]
    except (URLError, KeyError, IndexError):
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Terminal metrics dashboard")
    parser.add_argument("--prometheus", default="http://localhost:9090")
    args = parser.parse_args()

    base = args.prometheus
    print(f"\n=== devops-lab Metrics Dashboard ===")
    print(f"Prometheus: {base}\n")

    checks = [
        ("Total requests (all time)",
         'sum(http_requests_total{job="devops-lab"})'),
        ("Request rate (last 1m)",
         'sum(rate(http_requests_total{job="devops-lab"}[1m]))'),
        ("Error rate 4xx/5xx (last 1m)",
         'sum(rate(http_requests_total{job="devops-lab",status=~"4..|5.."}[1m]))'),
        ("Rate limit hits 429 (last 1m)",
         'sum(rate(http_requests_total{job="devops-lab",status="429"}[1m]))'),
        ("Avg request latency p50 (last 5m)",
         'histogram_quantile(0.50, rate(http_request_duration_seconds_bucket{job="devops-lab"}[5m]))'),
        ("Avg request latency p99 (last 5m)",
         'histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{job="devops-lab"}[5m]))'),
        ("Login failures (last 1m)",
         'sum(rate(login_attempts_total{result="failure"}[1m]))'),
        ("Login successes (last 1m)",
         'sum(rate(login_attempts_total{result="success"}[1m]))'),
        ("Active connections",
         'sum(active_connections{job="devops-lab"})'),
        ("Running pods",
         'count(up{job="devops-lab"} == 1)'),
    ]

    for label, query_str in checks:
        value = query(base, query_str)
        if value is None:
            display = "N/A"
        else:
            try:
                fv = float(value)
                display = f"{fv:.4f}" if fv < 1 else f"{fv:.2f}"
            except ValueError:
                display = value
        print(f"  {label:<45} {display}")

    print()


if __name__ == "__main__":
    main()
