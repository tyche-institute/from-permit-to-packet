#!/usr/bin/env python3
"""Composed verifier for the From Permit to Packet experiment.

This is a research prototype.  Its signed JSON envelopes are deliberately
profile-local and are not represented as SCITT receipts or RATS Evidence.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Callable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


COMPONENTS = ("permit", "action", "effect", "evidence", "claim")
EXPECTED_DEFINITIONS = {
    ("ping", 4, 900),
    ("ping", 6, 900),
    ("traceroute", 4, 21600),
    ("traceroute", 6, 21600),
    ("dns", 4, 21600),
    ("dns", 6, 21600),
    ("sslcert", 4, 21600),
    ("sslcert", 6, 21600),
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def verify_signed(envelope: dict[str, Any]) -> bool:
    try:
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(envelope["public_key_b64"], validate=True)
        )
        key.verify(
            base64.b64decode(envelope["signature_b64"], validate=True),
            canonical_bytes(envelope["payload"]),
        )
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
    return True


def rehash(bundle: dict[str, Any]) -> None:
    bundle["manifest"] = {
        "algorithm": "sha-256",
        "components": {name: digest(bundle[name]) for name in COMPONENTS},
    }


def result(verdict: str, gate: str, stage: str | None) -> dict[str, Any]:
    return {"verdict": verdict, "gate": gate, "first_bad_edge": stage}


def integrity_gate(bundle: dict[str, Any]) -> tuple[bool, str]:
    expected = bundle.get("manifest", {}).get("components", {})
    for name in COMPONENTS:
        if expected.get(name) != digest(bundle.get(name)):
            return False, f"integrity.{name}"
    return True, "verified"


def action_gate(bundle: dict[str, Any]) -> tuple[bool, str]:
    permit = bundle["permit"]
    action = bundle["action"]
    if not verify_signed(permit):
        return False, "mandate.signature"
    policy = permit["payload"]
    appraisal = parse_time(bundle["appraisal_time"])
    if not (parse_time(policy["not_before"]) <= appraisal <= parse_time(policy["expires_at"])):
        return False, "mandate.freshness"
    if action.get("execution_host") not in policy["allowed_execution_hosts"]:
        return False, "mandate.execution_host"
    definitions = action.get("definitions", [])
    observed = {(item.get("type"), item.get("af"), item.get("interval")) for item in definitions}
    if observed != EXPECTED_DEFINITIONS or len(definitions) != len(EXPECTED_DEFINITIONS):
        return False, "mandate.definition_set"
    for item in definitions:
        target = item.get("query_argument") if item["type"] == "dns" else item.get("target")
        if target not in policy["allowed_targets"]:
            return False, "mandate.target"
        if item.get("auto_topup") is not False:
            return False, "mandate.auto_topup"
    regions = action.get("probes", [])
    if {item.get("value") for item in regions} != set(policy["allowed_regions"]):
        return False, "mandate.regions"
    requested = sum(item.get("requested", 0) for item in regions)
    if requested > policy["maximum_requested_probes"]:
        return False, "mandate.probe_budget"
    duration = action.get("stop_time", 0) - action.get("start_time", 0)
    if duration <= 0 or duration > policy["maximum_duration_seconds"]:
        return False, "mandate.duration"
    if action.get("estimated_daily_credits", 0) > policy["maximum_daily_credits"]:
        return False, "mandate.daily_credit_budget"
    if action.get("estimated_total_credits", 0) > policy["maximum_total_credits"]:
        return False, "mandate.total_credit_budget"
    if digest(action) != policy["authorized_semantic_action_digest"]:
        return False, "mandate.action_binding"
    return True, "verified"


def native_gate(bundle: dict[str, Any]) -> tuple[bool, str]:
    effect = bundle.get("effect", {})
    measurements = effect.get("measurements", [])
    if effect.get("platform") != "RIPE Atlas" or effect.get("status") != "running":
        return False, "native.platform_state"
    if len(measurements) != 8 or len({item.get("id") for item in measurements}) != 8:
        return False, "native.measurement_shape"
    if any(item.get("status") != "Ongoing" or item.get("participant_count", 0) <= 0 for item in measurements):
        return False, "native.measurement_state"
    return True, "verified"


def effect_gate(bundle: dict[str, Any]) -> tuple[bool, str]:
    action = bundle["action"]
    effect = bundle["effect"]
    if effect.get("semantic_action_digest") != digest(action):
        return False, "effect.request_binding"
    action_defs = [
        (item["type"], item["af"], item["interval"], item.get("target"), item.get("query_argument"))
        for item in action["definitions"]
    ]
    effect_defs = [
        (item["type"], item["af"], item["interval"], item.get("target"), item.get("query_argument"))
        for item in effect["measurements"]
    ]
    if action_defs != effect_defs:
        return False, "effect.definition_binding"
    if effect.get("start_time") != action.get("start_time") or effect.get("stop_time") != action.get("stop_time"):
        return False, "effect.time_binding"
    requested = sum(item["requested"] for item in action["probes"])
    if effect.get("scheduled_probe_count", 0) > requested:
        return False, "effect.source_budget"
    return True, "verified"


def evidence_gate(bundle: dict[str, Any], witnessed: bool) -> tuple[bool, str]:
    evidence = bundle["evidence"]
    capture = evidence["collector_capture"]
    if not verify_signed(capture):
        return False, "evidence.collector_signature"
    payload = capture["payload"]
    if witnessed:
        witness = evidence["witness_capture"]
        if not verify_signed(witness):
            return False, "evidence.witness_signature"
        if witness["payload"]["source_index_digest"] != digest(payload["source_index"]):
            return False, "evidence.witness_disagreement"
    effect_ids = {item["id"] for item in bundle["effect"]["measurements"]}
    index_ids = {item["measurement_id"] for item in payload["source_index"]}
    if effect_ids != index_ids:
        return False, "evidence.measurement_set"
    window_start = int(parse_time(payload["start_time"]).timestamp())
    window_stop = int(parse_time(payload["stop_time"]).timestamp())
    if not (
        bundle["effect"]["start_time"]
        <= window_start
        < window_stop
        <= bundle["effect"]["stop_time"]
    ):
        return False, "evidence.window_binding"
    derived_results = sum(item["result_count"] for item in payload["source_index"])
    derived_successes = sum(item["narrow_success_count"] for item in payload["source_index"])
    summary = evidence["summary"]
    if summary.get("result_count") != derived_results or summary.get("narrow_success_count") != derived_successes:
        return False, "evidence.summary_binding"
    scheduled = bundle["effect"]["scheduled_probe_count"]
    all_sources = all(item["seen_probe_count"] == scheduled for item in payload["source_index"])
    if summary.get("all_definitions_saw_all_sources") != all_sources:
        return False, "evidence.coverage_binding"
    appraisal = parse_time(bundle["appraisal_time"])
    age = (appraisal - parse_time(payload["stop_time"])).total_seconds()
    if age < 0 or age > bundle["permit"]["payload"]["maximum_evidence_age_seconds"]:
        return False, "evidence.freshness"
    return True, "verified"


def claim_gate(bundle: dict[str, Any]) -> tuple[bool, str]:
    claim = bundle["claim"]
    summary = bundle["evidence"]["summary"]
    if claim.get("kind") != "bounded_observation":
        return False, "claim.class"
    if set(claim.get("assertions", [])) & {"global_availability", "ripe_ncc_membership", "lir_status", "general_security"}:
        return False, "claim.overreach"
    expected = {
        "result_count": summary["result_count"],
        "narrow_success_count": summary["narrow_success_count"],
        "scheduled_source_count": bundle["effect"]["scheduled_probe_count"],
        "current_connected_sources": bundle["effect"]["current_connected_sources"],
        "all_definitions_saw_all_sources": summary["all_definitions_saw_all_sources"],
    }
    if claim.get("facts") != expected:
        return False, "claim.fact_binding"
    required = set(bundle["permit"]["payload"]["required_claim_boundaries"])
    if not required.issubset(claim.get("boundary_ids", [])):
        return False, "claim.boundary_omission"
    return True, "verified"


def evaluate_hash_only(bundle: dict[str, Any]) -> dict[str, Any]:
    ok, gate = integrity_gate(bundle)
    return result("ALLOW" if ok else "DENY", gate, None if ok else "integrity")


def evaluate_native_only(bundle: dict[str, Any]) -> dict[str, Any]:
    ok, gate = native_gate(bundle)
    return result("ALLOW" if ok else "DENY", gate, None if ok else "platform_effect")


def evaluate_permit_only(bundle: dict[str, Any]) -> dict[str, Any]:
    ok, gate = action_gate(bundle)
    return result("ALLOW" if ok else "DENY", gate, None if ok else "mandate_to_action")


def evaluate_composed(bundle: dict[str, Any], witnessed: bool = False) -> dict[str, Any]:
    stages: list[tuple[str, Callable[..., tuple[bool, str]], tuple[Any, ...]]] = [
        ("integrity", integrity_gate, (bundle,)),
        ("mandate_to_action", action_gate, (bundle,)),
        ("platform_effect", native_gate, (bundle,)),
        ("action_to_effect", effect_gate, (bundle,)),
        ("effect_to_evidence", evidence_gate, (bundle, witnessed)),
        ("evidence_to_claim", claim_gate, (bundle,)),
    ]
    for stage, checker, arguments in stages:
        ok, gate = checker(*arguments)
        if not ok:
            return result("DENY", gate, stage)
    return result("ALLOW", "verified", None)


EVALUATORS = {
    "hash_only": evaluate_hash_only,
    "native_only": evaluate_native_only,
    "permit_only": evaluate_permit_only,
    "composed_offline": evaluate_composed,
    "composed_witnessed": lambda bundle: evaluate_composed(bundle, witnessed=True),
}
