#!/usr/bin/env python3
"""Run deterministic generated mutations over seven transition families."""

from __future__ import annotations

import copy
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from permit_to_packet import EVALUATORS, rehash
from run_experiment import base_bundle


ROOT = Path(__file__).resolve().parents[1]
SEED = 20260813
PER_FAMILY = 64
Mutation = Callable[[dict, random.Random, int], None]


def mutate_target(bundle: dict, rng: random.Random, index: int) -> None:
    replacement = f"forbidden-{rng.randrange(10**8):08d}.example"
    for item in bundle["action"]["definitions"]:
        item["query_argument" if item["type"] == "dns" else "target"] = replacement


def mutate_probe_budget(bundle: dict, rng: random.Random, index: int) -> None:
    bundle["action"]["probes"][0]["requested"] = rng.randint(5, 500)


def mutate_duration(bundle: dict, rng: random.Random, index: int) -> None:
    maximum = bundle["permit"]["payload"]["maximum_duration_seconds"]
    bundle["action"]["stop_time"] = bundle["action"]["start_time"] + maximum + rng.randint(1, 86400)


def mutate_host(bundle: dict, rng: random.Random, index: int) -> None:
    bundle["action"]["execution_host"] = f"unauthorised-host-{rng.randrange(10**8):08d}"


def mutate_effect(bundle: dict, rng: random.Random, index: int) -> None:
    bundle["effect"]["measurements"][0]["target"] = f"substitute-{rng.randrange(10**8):08d}.example"


def mutate_summary(bundle: dict, rng: random.Random, index: int) -> None:
    bundle["evidence"]["summary"]["result_count"] = rng.randint(0, 278)


def mutate_claim(bundle: dict, rng: random.Random, index: int) -> None:
    bundle["claim"]["assertions"].append("global_availability")


FAMILIES: list[tuple[str, str, Mutation]] = [
    ("target_substitution", "mandate_to_action", mutate_target),
    ("probe_budget_escalation", "mandate_to_action", mutate_probe_budget),
    ("duration_escalation", "mandate_to_action", mutate_duration),
    ("execution_host_escape", "mandate_to_action", mutate_host),
    ("platform_effect_substitution", "action_to_effect", mutate_effect),
    ("evidence_summary_cherry_pick", "effect_to_evidence", mutate_summary),
    ("claim_overreach", "evidence_to_claim", mutate_claim),
]


def main() -> int:
    rng = random.Random(SEED)
    summaries = []
    failures = []
    for family, expected_stage, mutate in FAMILIES:
        detected = 0
        localised = 0
        for index in range(PER_FAMILY):
            bundle = copy.deepcopy(base_bundle())
            bundle["case_id"] = f"generated-{family}-{index:03d}"
            mutate(bundle, rng, index)
            rehash(bundle)
            verdict = EVALUATORS["composed_witnessed"](bundle)
            detected += verdict["verdict"] == "DENY"
            localised += verdict["first_bad_edge"] == expected_stage
            if verdict["verdict"] != "DENY" or verdict["first_bad_edge"] != expected_stage:
                failures.append({"case_id": bundle["case_id"], "expected_stage": expected_stage, "verdict": verdict})
        summaries.append(
            {
                "family": family,
                "expected_first_bad_edge": expected_stage,
                "generated_count": PER_FAMILY,
                "detected_count": detected,
                "correctly_localised_count": localised,
            }
        )

    total = len(FAMILIES) * PER_FAMILY
    output = {
        "schema": "tyche-from-permit-to-packet-generated-mutations-v0.1",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "seed": SEED,
        "per_family": PER_FAMILY,
        "family_count": len(FAMILIES),
        "generated_fault_count": total,
        "detected_count": sum(item["detected_count"] for item in summaries),
        "correctly_localised_count": sum(item["correctly_localised_count"] for item in summaries),
        "families": summaries,
        "failures": failures,
        "boundary": "Deterministic generated variations of seven authored operators; this expands input coverage but is not a population sample or independent adversarial evaluation.",
    }
    path = ROOT / "results" / "generated-mutations.json"
    path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
