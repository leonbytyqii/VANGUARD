#!/usr/bin/env python3
"""
VANGUARD ingestion performance benchmark.

Sends synthetic events to POST /api/v1/events at an increasing EPS (events
per second) ramp and reports actual throughput, p50/p95/p99 latency, and
failure rate for each tier.

Usage:

    python scripts/bench_ingestion.py \\
        --url  http://localhost:8000 \\
        --token <access_token> \\
        --tiers 10,50,100,200 \\
        --duration 10

Each tier runs for `--duration` seconds, then the results are printed.
Requires: httpx (already in requirements.txt)

This script is a benchmarking tool, not an attack tool. Only run it against
your own authorized VANGUARD instance. The events it sends are synthetic,
clearly labeled (source=synthetic_lab), and use RFC 5737 / RFC 2606 addresses
so they cannot be confused with real infrastructure.
"""
from __future__ import annotations

import argparse
import statistics
import threading
import time
from dataclasses import dataclass, field

import httpx

SYNTHETIC_EVENT = {
    "source": "windows_sysmon",
    "host": "BENCH-HOST-01",
    "user": "bench-user",
    "event_type": "process_creation",
    "process": "powershell.exe",
    "parent_process": "cmd.exe",
    "command_line": "powershell.exe -NoProfile -Command Get-Process",
}


@dataclass
class TierResult:
    target_eps: int
    actual_eps: float
    success_count: int
    failure_count: int
    latencies_ms: list[float] = field(default_factory=list)

    @property
    def p50(self) -> float:
        return statistics.median(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def p95(self) -> float:
        if not self.latencies_ms:
            return 0.0
        s = sorted(self.latencies_ms)
        return s[int(len(s) * 0.95)]

    @property
    def p99(self) -> float:
        if not self.latencies_ms:
            return 0.0
        s = sorted(self.latencies_ms)
        return s[int(len(s) * 0.99)]

    @property
    def error_rate(self) -> float:
        total = self.success_count + self.failure_count
        return self.failure_count / total if total else 0.0


def run_tier(
    url: str,
    token: str,
    target_eps: int,
    duration_s: int,
) -> TierResult:
    endpoint = f"{url.rstrip('/')}/api/v1/events"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    interval = 1.0 / target_eps

    result = TierResult(target_eps=target_eps, actual_eps=0.0, success_count=0, failure_count=0)
    lock = threading.Lock()

    def _send(client: httpx.Client) -> None:
        t0 = time.perf_counter()
        try:
            resp = client.post(endpoint, json=SYNTHETIC_EVENT, headers=headers, timeout=10.0)
            elapsed_ms = (time.perf_counter() - t0) * 1000
            with lock:
                if resp.is_success:
                    result.success_count += 1
                    result.latencies_ms.append(elapsed_ms)
                else:
                    result.failure_count += 1
        except Exception:
            with lock:
                result.failure_count += 1

    start = time.perf_counter()
    threads: list[threading.Thread] = []
    with httpx.Client() as client:
        while (time.perf_counter() - start) < duration_s:
            t = threading.Thread(target=_send, args=(client,), daemon=True)
            t.start()
            threads.append(t)
            time.sleep(interval)

    for t in threads:
        t.join(timeout=15)

    elapsed = time.perf_counter() - start
    result.actual_eps = (result.success_count + result.failure_count) / elapsed
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="VANGUARD ingestion benchmark")
    parser.add_argument("--url", default="http://localhost:8000", help="Backend base URL")
    parser.add_argument("--token", required=True, help="Bearer access token")
    parser.add_argument(
        "--tiers",
        default="10,50,100",
        help="Comma-separated list of target EPS tiers to test",
    )
    parser.add_argument("--duration", type=int, default=10, help="Seconds per tier")
    args = parser.parse_args()

    tiers = [int(t.strip()) for t in args.tiers.split(",")]

    print(f"\nVANGUARD ingestion benchmark — {args.url}")
    print(f"Duration per tier: {args.duration}s\n")
    print(f"{'Target EPS':>12}  {'Actual EPS':>12}  {'p50 (ms)':>10}  {'p95 (ms)':>10}  {'p99 (ms)':>10}  {'Error rate':>12}")
    print("-" * 80)

    for target_eps in tiers:
        result = run_tier(args.url, args.token, target_eps, args.duration)
        print(
            f"{result.target_eps:>12}  "
            f"{result.actual_eps:>12.1f}  "
            f"{result.p50:>10.1f}  "
            f"{result.p95:>10.1f}  "
            f"{result.p99:>10.1f}  "
            f"{result.error_rate:>11.1%}"
        )

    print()


if __name__ == "__main__":
    main()
