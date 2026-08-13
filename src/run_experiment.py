#!/usr/bin/env python3
"""Build and execute the deterministic From Permit to Packet corpus."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from permit_to_packet import EVALUATORS, canonical_bytes, digest, rehash


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
RESULTS = ROOT / "results"
APPRAISAL_TIME = "2026-08-13T18:00:00Z"


def fixture_key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"tyche-from-permit-to-packet-v0.1:{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def signed(payload: dict[str, Any], label: str) -> dict[str, Any]:
    key = fixture_key(label)
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "alg": "Ed25519",
        "key_role": label,
        "public_key_b64": base64.b64encode(public).decode(),
        "signature_b64": base64.b64encode(key.sign(canonical_bytes(payload))).decode(),
        "payload": payload,
        "test_fixture_key": True,
    }


def resign(envelope: dict[str, Any], label: str) -> None:
    replacement = signed(envelope["payload"], label)
    envelope.update(replacement)


def base_bundle() -> dict[str, Any]:
    definitions = [
        {"type": "ping", "af": 4, "interval": 900, "target": "tyche.institute", "auto_topup": False},
        {"type": "ping", "af": 6, "interval": 900, "target": "tyche.institute", "auto_topup": False},
        {"type": "traceroute", "af": 4, "interval": 21600, "target": "tyche.institute", "auto_topup": False},
        {"type": "traceroute", "af": 6, "interval": 21600, "target": "tyche.institute", "auto_topup": False},
        {"type": "dns", "af": 4, "interval": 21600, "query_argument": "tyche.institute", "auto_topup": False},
        {"type": "dns", "af": 6, "interval": 21600, "query_argument": "tyche.institute", "auto_topup": False},
        {"type": "sslcert", "af": 4, "interval": 21600, "target": "tyche.institute", "auto_topup": False},
        {"type": "sslcert", "af": 6, "interval": 21600, "target": "tyche.institute", "auto_topup": False},
    ]
    probes = [
        {"type": "region", "value": region, "requested": 4}
        for region in ("afrinic", "apnic", "arin", "lacnic", "ripencc")
    ]
    action = {
        "schema": "tyche-atlas-semantic-action-v0.1",
        "execution_host": "zeus1",
        "platform": "RIPE Atlas",
        "definitions": definitions,
        "probes": probes,
        "start_time": 1786616700,
        "stop_time": 1789208700,
        "estimated_daily_credits": 19520,
        "estimated_total_credits": 585600,
        "privacy_profile": "public-aggregate-no-address-or-geometry-v1",
        "note": "Privacy-minimised semantic replay derived from the live campaign; not the exact private API wire body.",
    }
    permit_payload = {
        "schema": "tyche-measurement-permit-v0.1",
        "permit_id": "tmp-replay-2026-08-13-001",
        "issuer": "Tyche Measurement Permit Lab",
        "subject": "athena-research-agent",
        "purpose": "bounded dual-stack evidence research",
        "not_before": "2026-08-13T09:00:00Z",
        "expires_at": "2026-09-13T23:59:59Z",
        "allowed_execution_hosts": ["zeus1"],
        "allowed_targets": ["tyche.institute"],
        "allowed_regions": ["afrinic", "apnic", "arin", "lacnic", "ripencc"],
        "maximum_requested_probes": 20,
        "maximum_duration_seconds": 2592000,
        "maximum_daily_credits": 19520,
        "maximum_total_credits": 585600,
        "maximum_evidence_age_seconds": 7200,
        "required_claim_boundaries": [
            "observation-not-global-availability",
            "integrity-not-truth",
            "atlas-participation-not-membership",
        ],
        "authorized_semantic_action_digest": digest(action),
        "retrospective_replay": True,
    }
    ids = [200375573, 200375574, 200375575, 200375577, 200375578, 200375579, 200375581, 200375582]
    counts = [(80, 79), (79, 79), (20, 20), (20, 20), (20, 20), (20, 20), (20, 20), (20, 20)]
    measurements = []
    source_index = []
    for definition, measurement_id, (result_count, success_count) in zip(definitions, ids, counts):
        measurements.append(
            {
                **definition,
                "id": measurement_id,
                "status": "Ongoing",
                "participant_count": 20,
                "public": True,
            }
        )
        source_index.append(
            {
                "measurement_id": measurement_id,
                "type": definition["type"],
                "af": definition["af"],
                "result_count": result_count,
                "narrow_success_count": success_count,
                "seen_probe_count": 20,
                "raw_window_sha256": hashlib.sha256(f"pinned-private-window:{measurement_id}".encode()).hexdigest(),
            }
        )
    effect = {
        "schema": "tyche-atlas-platform-effect-v0.1",
        "platform": "RIPE Atlas",
        "status": "running",
        "semantic_action_digest": digest(action),
        "start_time": action["start_time"],
        "stop_time": action["stop_time"],
        "scheduled_probe_count": 20,
        "current_connected_sources": 19,
        "measurements": measurements,
        "upstream_authentication_boundary": "Public API over TLS; RIPE does not sign these fixture rows.",
    }
    capture_payload = {
        "schema": "tyche-atlas-capture-statement-v0.1",
        "captured_at": "2026-08-13T17:26:00Z",
        "start_time": "2026-08-13T16:25:00Z",
        "stop_time": "2026-08-13T17:24:40Z",
        "source_index": source_index,
    }
    collector = signed(capture_payload, "collector")
    witness_payload = {
        "schema": "tyche-atlas-witness-statement-v0.1",
        "observed_at": "2026-08-13T17:27:00Z",
        "source_index_digest": digest(source_index),
        "independence_boundary": "Logically separate replay witness; same host and same RIPE upstream, not Byzantine independence.",
    }
    summary = {
        "result_count": 279,
        "narrow_success_count": 278,
        "all_definitions_saw_all_sources": True,
    }
    claim = {
        "schema": "tyche-bounded-network-claim-v0.1",
        "kind": "bounded_observation",
        "assertions": ["result-flow", "source-presence-in-window"],
        "facts": {
            "result_count": 279,
            "narrow_success_count": 278,
            "scheduled_source_count": 20,
            "current_connected_sources": 19,
            "all_definitions_saw_all_sources": True,
        },
        # Keep the claim's presentation list distinct from the signed Permit
        # policy list so a claim-only mutation cannot mutate signed authority
        # through Python object aliasing.
        "boundary_ids": list(permit_payload["required_claim_boundaries"]),
    }
    bundle = {
        "schema": "tyche-from-permit-to-packet-bundle-v0.1",
        "case_id": "P00_clean_replay",
        "appraisal_time": APPRAISAL_TIME,
        "permit": signed(permit_payload, "permit-issuer"),
        "action": action,
        "effect": effect,
        "evidence": {
            "collector_capture": collector,
            "witness_capture": signed(witness_payload, "witness"),
            "summary": summary,
        },
        "claim": claim,
    }
    rehash(bundle)
    return bundle


def path_set(value: dict[str, Any], path: str, replacement: Any) -> None:
    parts = path.split(".")
    cursor: Any = value
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    last = parts[-1]
    if isinstance(cursor, list):
        cursor[int(last)] = replacement
    else:
        cursor[last] = replacement


def mutate_target(bundle: dict[str, Any]) -> None:
    for item in bundle["action"]["definitions"]:
        item["query_argument" if item["type"] == "dns" else "target"] = "example.net"


def remove_ipv6(bundle: dict[str, Any]) -> None:
    bundle["action"]["definitions"] = [item for item in bundle["action"]["definitions"] if item["af"] == 4]


def corrupt_signature(bundle: dict[str, Any]) -> None:
    raw = bytearray(base64.b64decode(bundle["permit"]["signature_b64"]))
    raw[0] ^= 1
    bundle["permit"]["signature_b64"] = base64.b64encode(raw).decode()


def remove_evidence_measurement(bundle: dict[str, Any]) -> None:
    bundle["evidence"]["collector_capture"]["payload"]["source_index"].pop()
    resign(bundle["evidence"]["collector_capture"], "collector")


def cherry_pick_summary(bundle: dict[str, Any]) -> None:
    bundle["evidence"]["summary"]["result_count"] = 278


def stale_capture(bundle: dict[str, Any]) -> None:
    payload = bundle["evidence"]["collector_capture"]["payload"]
    payload["start_time"] = "2026-08-12T14:00:00Z"
    payload["stop_time"] = "2026-08-12T15:00:00Z"
    resign(bundle["evidence"]["collector_capture"], "collector")


def collector_reissued_cherry_pick(bundle: dict[str, Any]) -> None:
    payload = bundle["evidence"]["collector_capture"]["payload"]
    payload["source_index"][0]["result_count"] = 79
    payload["source_index"][0]["narrow_success_count"] = 79
    bundle["evidence"]["summary"]["result_count"] = 278
    bundle["evidence"]["summary"]["narrow_success_count"] = 278
    bundle["claim"]["facts"]["result_count"] = 278
    bundle["claim"]["facts"]["narrow_success_count"] = 278
    resign(bundle["evidence"]["collector_capture"], "collector")


def integrity_only_tamper(bundle: dict[str, Any]) -> None:
    bundle["claim"]["facts"]["current_connected_sources"] = 20


def reauthorize_action(bundle: dict[str, Any]) -> None:
    action_digest = digest(bundle["action"])
    bundle["permit"]["payload"]["authorized_semantic_action_digest"] = action_digest
    resign(bundle["permit"], "permit-issuer")
    bundle["effect"]["semantic_action_digest"] = action_digest


def refresh_evidence_signatures(bundle: dict[str, Any]) -> None:
    source_index = bundle["evidence"]["collector_capture"]["payload"]["source_index"]
    resign(bundle["evidence"]["collector_capture"], "collector")
    bundle["evidence"]["witness_capture"]["payload"]["source_index_digest"] = digest(source_index)
    resign(bundle["evidence"]["witness_capture"], "witness")


def positive_authorized_target(bundle: dict[str, Any]) -> None:
    target = "example.net"
    bundle["permit"]["payload"]["allowed_targets"].append(target)
    for item in bundle["action"]["definitions"]:
        item["query_argument" if item["type"] == "dns" else "target"] = target
    for item in bundle["effect"]["measurements"]:
        item["query_argument" if item["type"] == "dns" else "target"] = target
    reauthorize_action(bundle)


def positive_probe_reallocation(bundle: dict[str, Any]) -> None:
    bundle["action"]["probes"][0]["requested"] = 5
    bundle["action"]["probes"][1]["requested"] = 3
    reauthorize_action(bundle)


def positive_duration(bundle: dict[str, Any], reduction: int) -> None:
    bundle["action"]["stop_time"] -= reduction
    bundle["effect"]["stop_time"] = bundle["action"]["stop_time"]
    reauthorize_action(bundle)


def positive_reordered_definitions(bundle: dict[str, Any]) -> None:
    bundle["action"]["definitions"].reverse()
    bundle["effect"]["measurements"].reverse()
    reauthorize_action(bundle)


def positive_note_change(bundle: dict[str, Any], suffix: str) -> None:
    bundle["action"]["note"] += suffix
    reauthorize_action(bundle)


def positive_extended_permit(bundle: dict[str, Any]) -> None:
    bundle["permit"]["payload"]["expires_at"] = "2026-10-13T23:59:59Z"
    resign(bundle["permit"], "permit-issuer")


def positive_lower_credit_estimate(bundle: dict[str, Any]) -> None:
    bundle["action"]["estimated_daily_credits"] = 19000
    reauthorize_action(bundle)


def positive_single_definition_target(bundle: dict[str, Any]) -> None:
    target = "www.example.com"
    bundle["permit"]["payload"]["allowed_targets"].append(target)
    bundle["action"]["definitions"][0]["target"] = target
    bundle["effect"]["measurements"][0]["target"] = target
    reauthorize_action(bundle)


def positive_reordered_evidence(bundle: dict[str, Any]) -> None:
    bundle["evidence"]["collector_capture"]["payload"]["source_index"].reverse()
    refresh_evidence_signatures(bundle)


def positive_redistributed_counts(bundle: dict[str, Any]) -> None:
    index = bundle["evidence"]["collector_capture"]["payload"]["source_index"]
    index[0]["result_count"] = 79
    index[0]["narrow_success_count"] = 78
    index[1]["result_count"] = 80
    index[1]["narrow_success_count"] = 80
    refresh_evidence_signatures(bundle)


def positive_fresh_window(bundle: dict[str, Any]) -> None:
    payload = bundle["evidence"]["collector_capture"]["payload"]
    payload["start_time"] = "2026-08-13T16:30:00Z"
    payload["stop_time"] = "2026-08-13T17:20:00Z"
    resign(bundle["evidence"]["collector_capture"], "collector")


def positive_connected_fact(bundle: dict[str, Any]) -> None:
    bundle["effect"]["current_connected_sources"] = 18
    bundle["claim"]["facts"]["current_connected_sources"] = 18


def positive_extra_boundaries(bundle: dict[str, Any]) -> None:
    bundle["claim"]["boundary_ids"].reverse()
    bundle["claim"]["boundary_ids"].append("window-time-bounded")


def positive_participant_variation(bundle: dict[str, Any]) -> None:
    bundle["effect"]["measurements"][0]["participant_count"] = 19


def positive_collector_reissue(bundle: dict[str, Any]) -> None:
    bundle["evidence"]["collector_capture"]["payload"]["captured_at"] = "2026-08-13T17:28:00Z"
    resign(bundle["evidence"]["collector_capture"], "collector")


Mutation = Callable[[dict[str, Any]], None]


CASES: list[tuple[str, Mutation | None, str | None, bool]] = [
    ("P00_clean_replay", None, None, True),
    ("D01_target_substitution", mutate_target, "mandate_to_action", True),
    ("D02_probe_budget_escalation", lambda b: path_set(b, "action.probes.0.requested", 184), "mandate_to_action", True),
    ("D03_duration_escalation", lambda b: path_set(b, "action.stop_time", 1791800700), "mandate_to_action", True),
    ("D04_auto_topup_enabled", lambda b: path_set(b, "action.definitions.0.auto_topup", True), "mandate_to_action", True),
    ("D05_ipv6_removed", remove_ipv6, "mandate_to_action", True),
    ("D06_wrong_execution_host", lambda b: path_set(b, "action.execution_host", "unauthorised-host"), "mandate_to_action", True),
    ("D07_invalid_permit_signature", corrupt_signature, "mandate_to_action", True),
    ("D08_effect_request_digest_mismatch", lambda b: path_set(b, "effect.semantic_action_digest", "0" * 64), "action_to_effect", True),
    ("D09_effect_definition_substitution", lambda b: path_set(b, "effect.measurements.0.target", "example.net"), "action_to_effect", True),
    ("D10_effect_time_drift", lambda b: path_set(b, "effect.stop_time", 1789295100), "action_to_effect", True),
    ("D11_evidence_measurement_omission", remove_evidence_measurement, "effect_to_evidence", True),
    ("D12_summary_cherry_pick", cherry_pick_summary, "effect_to_evidence", True),
    ("D13_stale_capture", stale_capture, "effect_to_evidence", True),
    ("D14_global_availability_overclaim", lambda b: path_set(b, "claim.kind", "global_availability"), "evidence_to_claim", True),
    ("D15_ripe_membership_overclaim", lambda b: b["claim"]["assertions"].append("ripe_ncc_membership"), "evidence_to_claim", True),
    ("D16_connected_source_overclaim", lambda b: path_set(b, "claim.facts.current_connected_sources", 20), "evidence_to_claim", True),
    ("D17_boundary_omission", lambda b: path_set(b, "claim.boundary_ids", []), "evidence_to_claim", True),
    ("D18_native_platform_stopped", lambda b: path_set(b, "effect.status", "stopped"), "platform_effect", True),
    ("D19_integrity_tamper_no_rehash", integrity_only_tamper, "integrity", False),
    ("D20_collector_reissued_cherry_pick", collector_reissued_cherry_pick, "effect_to_evidence", True),
    ("D21_multi_fault_first_edge", lambda b: (path_set(b, "action.execution_host", "unauthorised-host"), b["claim"]["assertions"].append("global_availability")), "mandate_to_action", True),
]


POSITIVE_CONTROLS: list[tuple[str, Mutation | None, str | None, bool]] = [
    ("P01_authorized_target_change", positive_authorized_target, None, True),
    ("P02_in_budget_probe_reallocation", positive_probe_reallocation, None, True),
    ("P03_in_budget_duration", lambda b: positive_duration(b, 60), None, True),
    ("P04_auto_topup_remains_disabled", lambda b: positive_note_change(b, " Auto-topup control."), None, True),
    ("P05_complete_reordered_dual_stack_set", positive_reordered_definitions, None, True),
    ("P06_authorized_execution_host", lambda b: positive_note_change(b, " Execution-host control."), None, True),
    ("P07_valid_extended_permit", positive_extended_permit, None, True),
    ("P08_matching_recomputed_action_digest", positive_lower_credit_estimate, None, True),
    ("P09_matching_effect_definition", positive_single_definition_target, None, True),
    ("P10_matching_effect_time", lambda b: positive_duration(b, 1800), None, True),
    ("P11_complete_reordered_evidence", positive_reordered_evidence, None, True),
    ("P12_consistent_redistributed_summary", positive_redistributed_counts, None, True),
    ("P13_fresh_shifted_capture", positive_fresh_window, None, True),
    ("P14_bounded_additional_assertion", lambda b: b["claim"]["assertions"].append("window-bounded"), None, True),
    ("P15_atlas_participation_assertion", lambda b: b["claim"]["assertions"].append("atlas-participation-observed"), None, True),
    ("P16_factual_connected_source_change", positive_connected_fact, None, True),
    ("P17_required_plus_extra_boundaries", positive_extra_boundaries, None, True),
    ("P18_running_participant_variation", positive_participant_variation, None, True),
    ("P19_integrity_preserving_claim_order", lambda b: b["claim"]["assertions"].reverse(), None, True),
    ("P20_collector_reissue_without_equivocation", positive_collector_reissue, None, True),
    ("P21_multi_safe_variation", lambda b: (positive_note_change(b, " Multi-safe control."), b["claim"]["assertions"].append("window-bounded")), None, True),
]


def paired_id(case_id: str) -> str | None:
    if len(case_id) >= 3 and case_id[0] in {"D", "P"} and case_id[1:3].isdigit() and case_id != "P00_clean_replay":
        return f"pair-{case_id[1:3]}"
    return None


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    CORPUS.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    cases = []
    verdicts = []
    for case_id, mutation, expected_stage, should_rehash in CASES + POSITIVE_CONTROLS:
        bundle = copy.deepcopy(base_bundle())
        bundle["case_id"] = case_id
        if mutation is not None:
            mutation(bundle)
        if should_rehash:
            rehash(bundle)
        expected = {"ground_truth": "ALLOW" if expected_stage is None else "DENY", "first_bad_edge": expected_stage}
        write_json(CORPUS / f"{case_id}.json", bundle)
        evaluated = {name: evaluator(bundle) for name, evaluator in EVALUATORS.items()}
        pair_id = paired_id(case_id)
        verdicts.append({"case_id": case_id, "pair_id": pair_id, "expected": expected, "verifiers": evaluated})
        cases.append({"case_id": case_id, "pair_id": pair_id, "expected": expected})

    verifier_names = list(EVALUATORS)
    metrics = {}
    negatives = [item for item in verdicts if item["expected"]["ground_truth"] == "DENY"]
    positives = [item for item in verdicts if item["expected"]["ground_truth"] == "ALLOW"]
    for name in verifier_names:
        false_accepts = [item["case_id"] for item in negatives if item["verifiers"][name]["verdict"] == "ALLOW"]
        false_rejects = [item["case_id"] for item in positives if item["verifiers"][name]["verdict"] == "DENY"]
        detected = len(negatives) - len(false_accepts)
        true_accepts = len(positives) - len(false_rejects)
        safe_accept_rate = true_accepts / len(positives)
        negative_detection_rate = detected / len(negatives)
        localized = sum(
            item["verifiers"][name]["first_bad_edge"] == item["expected"]["first_bad_edge"]
            for item in negatives
            if item["verifiers"][name]["verdict"] == "DENY"
        )
        metrics[name] = {
            "false_accept_count": len(false_accepts),
            "false_accept_case_ids": false_accepts,
            "false_reject_count": len(false_rejects),
            "false_reject_case_ids": false_rejects,
            "detected_negative_count": detected,
            "negative_case_count": len(negatives),
            "true_accept_count": true_accepts,
            "positive_case_count": len(positives),
            "safe_accept_rate": round(safe_accept_rate, 6),
            "negative_detection_rate": round(negative_detection_rate, 6),
            "balanced_accuracy": round((safe_accept_rate + negative_detection_rate) / 2, 6),
            "correct_first_bad_edge_count_among_all_negatives": localized,
        }
    summary = {
        "schema": "tyche-from-permit-to-packet-results-v0.1",
        "case_count": len(verdicts),
        "positive_case_count": len(verdicts) - len(negatives),
        "negative_case_count": len(negatives),
        "matched_pair_count": len(POSITIVE_CONTROLS),
        "unpaired_clean_control_count": 1,
        "metrics": metrics,
        "designed_corpus_boundary": "These are author-designed fault vectors. Counts demonstrate corpus coverage, not population error rates.",
        "upstream_boundary": "RIPE Atlas public API rows are fetched over TLS but are not RIPE-signed statements. Fixture signatures prove statements by test roles, not upstream truth.",
    }
    write_json(ROOT / "corpus-index.json", {"schema": "tyche-from-permit-to-packet-corpus-v0.1", "cases": cases})
    (RESULTS / "verdicts.jsonl").write_text("".join(json.dumps(item, sort_keys=True) + "\n" for item in verdicts), encoding="utf-8")
    write_json(RESULTS / "summary.json", summary)

    files = sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and path.name != "SHA256SUMS"
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    )
    (ROOT / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(ROOT)}\n" for path in files),
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
