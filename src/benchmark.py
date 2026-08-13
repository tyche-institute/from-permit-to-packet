#!/usr/bin/env python3
"""Measure verifier latency and artifact size for the frozen v0.1 corpus."""

from __future__ import annotations

import json
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

import cryptography

from permit_to_packet import EVALUATORS


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_CAPTURE = Path("/srv/tyche/labs/from-permit-to-packet-2026-08-13/capture")
ITERATIONS = 2000


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(len(ordered) * fraction))]


def main() -> int:
    bundles = [json.loads(path.read_bytes()) for path in sorted((ROOT / "corpus").glob("*.json"))]
    measurements = {}
    for name, verifier in EVALUATORS.items():
        for bundle in bundles:
            verifier(bundle)
        timings = []
        for _ in range(ITERATIONS):
            start = time.perf_counter_ns()
            for bundle in bundles:
                verifier(bundle)
            timings.append((time.perf_counter_ns() - start) / len(bundles) / 1000)
        measurements[name] = {
            "median_microseconds_per_bundle": round(statistics.median(timings), 3),
            "p95_microseconds_per_bundle": round(percentile(timings, 0.95), 3),
        }

    closure = ROOT / "prospective" / "closure.json"
    capture_files = list(PRIVATE_CAPTURE.rglob("*.json"))
    output = {
        "schema": "tyche-from-permit-to-packet-performance-v0.1",
        "measured_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "environment": {
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
            "platform": platform.platform(),
        },
        "corpus_case_count": len(bundles),
        "iterations": ITERATIONS,
        "timing_method": "perf_counter_ns; each sample is one full corpus pass divided by case count",
        "verifiers": measurements,
        "sizes": {
            "clean_replay_bundle_bytes": (ROOT / "corpus" / "P00_clean_replay.json").stat().st_size,
            "signed_prospective_closure_bytes": closure.stat().st_size,
            "prospective_capture_json_bytes": sum(path.stat().st_size for path in capture_files),
            "prospective_capture_json_file_count": len(capture_files),
        },
        "boundary": "Single-host descriptive microbenchmark; no cross-machine performance claim.",
    }
    path = ROOT / "results" / "performance.json"
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
