#!/usr/bin/env python3
"""
attack_pathtraversal.py — Path traversal & suspicious endpoint probe.

Probes common attack paths to see how the app responds.
Demonstrates: 404/401 patterns in Grafana, what an attacker reconnaissance
looks like in logs, and how to detect/alert on it.

Usage:
    python3 attack_pathtraversal.py --url http://localhost:30080
"""

import argparse
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

PROBE_PATHS = [
    # Admin/config discovery
    "/admin",
    "/admin/",
    "/admin/users",
    "/api/admin",
    "/.env",
    "/config",
    "/config.json",
    "/config.yaml",
    # Path traversal attempts
    "/../etc/passwd",
    "/%2e%2e/etc/passwd",
    "/static/../etc/passwd",
    "/images/../../../../etc/shadow",
    # Common sensitive files
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php",
    "/phpinfo.php",
    "/.ssh/id_rsa",
    "/backup.sql",
    "/dump.sql",
    # API versioning probes
    "/api/v1/users",
    "/api/v2/users",
    "/v1/admin",
    # Debug endpoints
    "/debug/vars",
    "/debug/pprof/",
    "/actuator/health",
    "/actuator/env",
    "/swagger.json",
    "/openapi.json",
]

def probe(base_url: str, path: str) -> tuple[int, str]:
    url = base_url.rstrip("/") + path
    try:
        req = Request(url)
        with urlopen(req, timeout=3) as resp:
            return resp.status, "OK"
    except HTTPError as e:
        return e.code, e.reason
    except URLError as e:
        return 0, str(e.reason)


def main():
    parser = argparse.ArgumentParser(description="Path traversal & recon probe")
    parser.add_argument("--url", default="http://localhost:30080")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests in seconds")
    args = parser.parse_args()

    print(f"[*] Path traversal & recon probe")
    print(f"[*] Target: {args.url}")
    print(f"[*] Probing {len(PROBE_PATHS)} paths...\n")

    results: dict[str, list[str]] = {"2xx": [], "3xx": [], "4xx": [], "5xx": [], "err": []}

    for path in PROBE_PATHS:
        status, reason = probe(args.url, path)
        bucket = f"{status // 100}xx" if status > 0 else "err"
        if bucket not in results:
            bucket = "err"
        results[bucket].append(path)

        marker = "(!)" if status == 200 else "   "
        print(f"  {marker} {status:3d}  {path}")
        time.sleep(args.delay)

    print(f"\n--- Recon Probe Report ---")
    print(f"200 OK (potential exposure) : {results.get('2xx', [])}")
    print(f"3xx redirects               : {results.get('3xx', [])}")
    print(f"4xx (expected denials)      : {len(results.get('4xx', []))} paths")
    print(f"5xx errors                  : {results.get('5xx', [])}")
    print(f"Connection errors           : {results.get('err', [])}")

    if results.get("2xx"):
        print("\n[!] WARNING: Some paths returned 200 — investigate these endpoints!")
    else:
        print("\n[+] No unexpected 200s — app surface looks clean")


if __name__ == "__main__":
    main()
