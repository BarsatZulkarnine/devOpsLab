#!/usr/bin/env python3
"""
traffic_sim.py — Normal traffic simulator.

Sends realistic mixed traffic to the app to generate metrics in Grafana.
Runs multiple concurrent workers to simulate real users.

Usage:
    python3 traffic_sim.py --url http://localhost:30080 --rps 20 --duration 120
"""

import argparse
import random
import time
import threading
import sys
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import json

ENDPOINTS = [
    ("/",         "GET",  None,  0.50),   # 50% weight
    ("/health",   "GET",  None,  0.10),
    ("/ready",    "GET",  None,  0.05),
    ("/slow",     "GET",  None,  0.10),
    ("/slow?ms=200", "GET", None, 0.05),
    ("/admin",    "GET",  None,  0.05),   # will 401 without token
    ("/login",    "POST", {"username": "alice", "password": "pass1"}, 0.05),
    ("/login",    "POST", {"username": "admin", "password": "secret123"}, 0.10),
]

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.total = 0
        self.success = 0
        self.errors = 0
        self.status_counts: dict[int, int] = {}

    def record(self, status: int):
        with self.lock:
            self.total += 1
            self.status_counts[status] = self.status_counts.get(status, 0) + 1
            if 200 <= status < 400:
                self.success += 1
            else:
                self.errors += 1

    def report(self):
        with self.lock:
            print(f"\n--- Traffic Simulation Report ---")
            print(f"Total requests : {self.total}")
            print(f"Success (2xx/3xx): {self.success}")
            print(f"Errors         : {self.errors}")
            print(f"Status breakdown: {dict(sorted(self.status_counts.items()))}")


def pick_endpoint():
    weights = [e[3] for e in ENDPOINTS]
    total = sum(weights)
    r = random.uniform(0, total)
    cumulative = 0
    for endpoint in ENDPOINTS:
        cumulative += endpoint[3]
        if r <= cumulative:
            return endpoint
    return ENDPOINTS[0]


def make_request(base_url: str, stats: Stats):
    path, method, body, _ = pick_endpoint()
    url = base_url.rstrip("/") + path

    try:
        if body:
            data = json.dumps(body).encode()
            req = Request(url, data=data, method=method,
                          headers={"Content-Type": "application/json"})
        else:
            req = Request(url, method=method)

        with urlopen(req, timeout=5) as resp:
            stats.record(resp.status)
    except HTTPError as e:
        stats.record(e.code)
    except URLError:
        stats.record(0)  # connection error


def worker(base_url: str, stats: Stats, stop_event: threading.Event,
           rps_per_worker: float):
    interval = 1.0 / rps_per_worker if rps_per_worker > 0 else 0.1
    while not stop_event.is_set():
        t0 = time.monotonic()
        make_request(base_url, stats)
        elapsed = time.monotonic() - t0
        sleep_time = max(0, interval - elapsed)
        stop_event.wait(timeout=sleep_time)


def main():
    parser = argparse.ArgumentParser(description="Normal traffic simulator")
    parser.add_argument("--url", default="http://localhost:30080")
    parser.add_argument("--rps", type=float, default=20, help="Total requests per second")
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    args = parser.parse_args()

    stats = Stats()
    stop_event = threading.Event()
    rps_per_worker = args.rps / args.workers

    print(f"Starting traffic simulation: {args.rps} rps, {args.workers} workers, {args.duration}s")
    print(f"Target: {args.url}")

    threads = []
    for _ in range(args.workers):
        t = threading.Thread(target=worker,
                             args=(args.url, stats, stop_event, rps_per_worker),
                             daemon=True)
        t.start()
        threads.append(t)

    try:
        for elapsed in range(args.duration):
            time.sleep(1)
            with stats.lock:
                print(f"\r[{elapsed+1:3d}s] total={stats.total} ok={stats.success} err={stats.errors}",
                      end="", flush=True)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=2)

    stats.report()


if __name__ == "__main__":
    main()
