#!/usr/bin/env python3
"""Capture and verify the frozen prospective RIPE Atlas pilot."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)

from permit_to_packet import canonical_bytes, digest, verify_signed


ROOT = Path(__file__).resolve().parents[1]
PRECOMMIT = ROOT / "prospective" / "precommit"
EXECUTION = ROOT / "prospective" / "execution"
LAB_ROOT = Path("/srv/tyche/labs/from-permit-to-packet-2026-08-13")
CAPTURE = LAB_ROOT / "capture"
PRIVATE = LAB_ROOT / "private"
COLLECTOR_KEY = PRIVATE / "pilot-collector-ed25519.pem"
API = "https://atlas.ripe.net/api/v2"
EXPECTED_PAIRS = {
    ("ping", 4),
    ("ping", 6),
    ("traceroute", 4),
    ("traceroute", 6),
    ("dns", 4),
    ("dns", 6),
    ("sslcert", 4),
    ("sslcert", 6),
}


def read(path: Path) -> Any:
    return json.loads(path.read_bytes())


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def atomic_write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def write_json(path: Path, value: Any) -> None:
    atomic_write(
        path,
        (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
    )


def fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Tyche-Permit-to-Packet-Prospective-Capture/0.1",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def load_or_create_collector() -> Ed25519PrivateKey:
    if COLLECTOR_KEY.exists():
        key = load_pem_private_key(COLLECTOR_KEY.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("collector key is not Ed25519")
        return key
    PRIVATE.mkdir(parents=True, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    key = Ed25519PrivateKey.generate()
    atomic_write(
        COLLECTOR_KEY,
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    os.chmod(COLLECTOR_KEY, 0o600)
    return key


def signed(payload: dict[str, Any]) -> dict[str, Any]:
    key = load_or_create_collector()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "alg": "Ed25519",
        "key_role": "tyche-prospective-pilot-collector",
        "public_key_b64": base64.b64encode(public).decode(),
        "public_key_sha256": sha256_bytes(public),
        "signature_b64": base64.b64encode(key.sign(canonical_bytes(payload))).decode(),
        "payload": payload,
        "trust_boundary": "Tyche collector statement over TLS-fetched RIPE public API rows; not a RIPE signature.",
    }


def narrow_success(kind: str, row: dict[str, Any]) -> bool:
    if kind == "ping":
        return row.get("sent", 0) > 0 and row.get("rcvd") == row.get("sent")
    if kind == "traceroute":
        return bool(row.get("destination_ip_responded"))
    if kind == "dns":
        entries = row.get("resultset") or []
        if not entries:
            return False
        result = entries[0].get("result", {})
        return not result.get("error") and result.get("ANCOUNT", 0) > 0
    if kind == "sslcert":
        return bool(row.get("cert"))
    return False


def validate_precommit() -> tuple[dict[str, Any], dict[str, Any], bytes, list[str]]:
    request_raw = (PRECOMMIT / "api-request.canonical.json").read_bytes()
    request = json.loads(request_raw)
    permit = read(PRECOMMIT / "permit.json")
    creation = read(EXECUTION / "creation-response.json")
    gates: list[str] = []
    if not verify_signed(permit):
        raise ValueError("mandate_to_action: permit signature invalid")
    gates.append("permit_signature")
    request_digest = sha256_bytes(request_raw)
    if request_digest != permit["payload"]["exact_api_request_sha256"]:
        raise ValueError("mandate_to_action: exact request digest mismatch")
    if creation["request_sha256"] != request_digest:
        raise ValueError("action_to_effect: creation receipt digest mismatch")
    gates.append("exact_request_digest")
    if creation.get("authenticated_transport", "").split()[-1] != "zeus1":
        raise ValueError("mandate_to_action: execution host mismatch")
    gates.append("execution_host")
    if creation["balance_before"] < permit["payload"]["maximum_credits"]:
        raise ValueError("mandate_to_action: credit gate failed")
    gates.append("credit_ceiling")
    measurements = creation.get("measurements", [])
    if len(measurements) != 8 or len(set(measurements)) != 8:
        raise ValueError("action_to_effect: expected eight distinct platform IDs")
    gates.append("platform_id_shape")
    return request, permit, request_raw, gates


def capture(measurement_ids: list[int], deadline_seconds: int = 300) -> None:
    CAPTURE.mkdir(parents=True, exist_ok=True)
    for measurement_id in measurement_ids:
        raw = fetch(f"{API}/measurements/{measurement_id}/?optional_fields=probes")
        atomic_write(CAPTURE / "measurements" / f"{measurement_id}.json", raw)

    pending = set(measurement_ids)
    deadline = time.monotonic() + deadline_seconds
    while pending and time.monotonic() < deadline:
        for measurement_id in tuple(sorted(pending)):
            try:
                raw = fetch(f"{API}/measurements/{measurement_id}/results/")
            except urllib.error.HTTPError as error:
                if error.code in {404, 429, 503}:
                    continue
                raise
            rows = json.loads(raw)
            metadata = read(CAPTURE / "measurements" / f"{measurement_id}.json")
            if isinstance(rows, list) and len(rows) >= metadata.get("probes_scheduled", 1):
                atomic_write(CAPTURE / "results" / f"{measurement_id}.json", raw)
                pending.remove(measurement_id)
                print(f"measurement {measurement_id}: {len(rows)} row(s)", flush=True)
        if pending:
            print(f"waiting for complete rows: {','.join(map(str, sorted(pending)))}", flush=True)
            time.sleep(10)
    if pending:
        # Retain the latest partial response rather than pretending it is absent.
        for measurement_id in sorted(pending):
            raw = fetch(f"{API}/measurements/{measurement_id}/results/")
            atomic_write(CAPTURE / "results" / f"{measurement_id}.json", raw)


def close() -> dict[str, Any]:
    request, permit, request_raw, gates = validate_precommit()
    creation = read(EXECUTION / "creation-response.json")
    ids = creation["measurements"]
    request_by_pair = {(item["type"], item["af"]): item for item in request["definitions"]}
    source_index = []
    all_complete = True
    total_rows = 0
    total_successes = 0
    observed_credits = 0
    scheduled_union: set[int] = set()

    for measurement_id in ids:
        metadata_path = CAPTURE / "measurements" / f"{measurement_id}.json"
        results_path = CAPTURE / "results" / f"{measurement_id}.json"
        metadata = read(metadata_path)
        rows = read(results_path)
        pair = (metadata.get("type"), metadata.get("af"))
        if pair not in request_by_pair:
            raise ValueError(f"action_to_effect: unexpected type/family for {measurement_id}")
        expected = request_by_pair.pop(pair)
        target = metadata.get("query_argument") if metadata["type"] == "dns" else metadata.get("target")
        expected_target = expected.get("query_argument") if expected["type"] == "dns" else expected.get("target")
        # RIPE serialises DNS names as absolute FQDNs with a trailing dot.
        normalised_target = target.rstrip(".") if isinstance(target, str) else target
        normalised_expected = (
            expected_target.rstrip(".") if isinstance(expected_target, str) else expected_target
        )
        if normalised_target != normalised_expected or normalised_target != "tyche.institute":
            raise ValueError(f"action_to_effect: target mismatch for {measurement_id}")
        if metadata.get("is_public") is not True or metadata.get("is_oneoff") is not True:
            raise ValueError(f"platform_effect: public/one-off state mismatch for {measurement_id}")
        scheduled = {item["id"] for item in metadata.get("probes", [])}
        requested = set(permit["payload"]["allowed_probe_ids"])
        if not scheduled or not scheduled.issubset(requested):
            raise ValueError(f"action_to_effect: scheduled source escape for {measurement_id}")
        returned = {row["prb_id"] for row in rows}
        if not returned.issubset(scheduled):
            raise ValueError(f"effect_to_evidence: result source escape for {measurement_id}")
        successes = sum(narrow_success(metadata["type"], row) for row in rows)
        complete = len(rows) == metadata.get("probes_scheduled") and returned == scheduled
        all_complete &= complete
        total_rows += len(rows)
        total_successes += successes
        credits = metadata.get("credits_per_result", 0) * len(rows)
        observed_credits += credits
        scheduled_union.update(scheduled)
        source_index.append(
            {
                "measurement_id": measurement_id,
                "type": metadata["type"],
                "af": metadata["af"],
                "status": metadata["status"]["name"],
                "scheduled_probe_ids": sorted(scheduled),
                "returned_probe_ids": sorted(returned),
                "result_count": len(rows),
                "narrow_success_count": successes,
                "complete_scheduled_source_coverage": complete,
                "credits_observed": credits,
                "metadata_sha256": sha256(metadata_path),
                "results_sha256": sha256(results_path),
                "measurement_url": f"https://atlas.ripe.net/measurements/{measurement_id}/",
                "results_api": f"{API}/measurements/{measurement_id}/results/",
            }
        )

    if request_by_pair or {(item["type"], item["af"]) for item in source_index} != EXPECTED_PAIRS:
        raise ValueError("action_to_effect: definition set incomplete")
    gates.extend(["definition_binding", "target_binding", "source_subset", "result_source_binding"])
    if observed_credits > permit["payload"]["maximum_credits"]:
        raise ValueError("effect_to_evidence: observed credit ceiling exceeded")
    gates.append("observed_credit_ceiling")
    if not all_complete:
        raise ValueError("effect_to_evidence: incomplete scheduled-source coverage")
    gates.append("complete_source_coverage")

    raw_capture_files = sorted(
        path
        for path in CAPTURE.rglob("*.json")
        if path.name != "manifest.json"
    )
    captured_at = (
        datetime.fromtimestamp(
            max(path.stat().st_mtime for path in raw_capture_files), timezone.utc
        )
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    claim = {
        "kind": "bounded_observation",
        "target": "tyche.institute",
        "definition_count": 8,
        "requested_probe_count": len(permit["payload"]["allowed_probe_ids"]),
        "scheduled_probe_ids": sorted(scheduled_union),
        "result_count": total_rows,
        "narrow_success_count": total_successes,
        "credits_observed_from_result_count": observed_credits,
        "all_definitions_complete_for_scheduled_sources": all_complete,
        "boundaries": [
            "one one-off observation, not global or long-term availability",
            "narrow protocol success, not general security",
            "Atlas participation, not RIPE NCC membership or LIR status",
            "Tyche collector signature, not a RIPE signature",
        ],
    }
    gates.append("bounded_claim_class")
    payload = {
        "schema": "tyche-from-permit-to-packet-prospective-closure-v0.1",
        "state": "CAPTURED_VERIFIED",
        "captured_at": captured_at,
        "execution_host": "zeus1",
        "permit_id": permit["payload"]["permit_id"],
        "permit_sha256": digest(permit),
        "exact_api_request_sha256": sha256_bytes(request_raw),
        "creation_response_sha256": digest(creation),
        "measurement_ids": ids,
        "source_index": source_index,
        "claim": claim,
        "verifier": {
            "verdict": "ALLOW",
            "first_bad_edge": None,
            "verified_gates": gates,
        },
        "witness": {
            "state": "PENDING_SEPARATE_REPLAY",
            "boundary": "Any later witness shares the same RIPE upstream unless explicitly stated otherwise.",
        },
    }
    envelope = signed(payload)
    if not verify_signed(envelope):
        raise ValueError("closure self-verification failed")
    write_json(ROOT / "prospective" / "closure.json", envelope)

    manifest = {
        "schema": "tyche-from-permit-to-packet-capture-manifest-v0.1",
        "captured_at": captured_at,
        "measurement_ids": ids,
        "files": {
            str(path.relative_to(CAPTURE)): {
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in raw_capture_files
        },
    }
    write_json(CAPTURE / "manifest.json", manifest)
    # This allow-listed copy contains filenames, sizes, and hashes only.  Raw
    # result rows remain in the Zeus1 lab directory and are not duplicated in
    # the research repository.
    write_json(ROOT / "prospective" / "capture-manifest.json", manifest)
    checksum_files = sorted(path for path in CAPTURE.rglob("*.json"))
    atomic_write(
        CAPTURE / "SHA256SUMS",
        "".join(f"{sha256(path)}  {path.relative_to(CAPTURE)}\n" for path in checksum_files).encode(),
    )
    print(json.dumps(envelope, indent=2, sort_keys=True))
    return envelope


def main() -> int:
    creation = read(EXECUTION / "creation-response.json")
    capture(creation["measurements"])
    close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
