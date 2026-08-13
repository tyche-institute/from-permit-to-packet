#!/usr/bin/env python3
"""Compare the browser replay with the collector and attach a signed witness."""

from __future__ import annotations

import base64
import json
import os
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

from capture_prospective import PRIVATE, ROOT, signed as sign_closure, write_json
from permit_to_packet import canonical_bytes, digest, verify_signed


WITNESS_DIR = ROOT / "prospective" / "witness"
OBSERVATION = WITNESS_DIR / "browser-observation.json"
WITNESS_KEY = PRIVATE / "pilot-witness-ed25519.pem"


def read(path: Path) -> Any:
    return json.loads(path.read_bytes())


def witness_key() -> Ed25519PrivateKey:
    if WITNESS_KEY.exists():
        key = load_pem_private_key(WITNESS_KEY.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("witness key is not Ed25519")
        return key
    PRIVATE.mkdir(parents=True, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    key = Ed25519PrivateKey.generate()
    WITNESS_KEY.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    os.chmod(WITNESS_KEY, 0o600)
    return key


def sign_witness(payload: dict[str, Any]) -> dict[str, Any]:
    key = witness_key()
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    import hashlib

    return {
        "alg": "Ed25519",
        "key_role": "tyche-browser-replay-witness",
        "public_key_b64": base64.b64encode(public).decode(),
        "public_key_sha256": hashlib.sha256(public).hexdigest(),
        "signature_b64": base64.b64encode(key.sign(canonical_bytes(payload))).decode(),
        "payload": payload,
        "independence_boundary": (
            "Separate Chrome-CDP collection code path and signing key, but the "
            "same zeus1 host, Tyche administration, network, and RIPE upstream; "
            "not Byzantine or organisational independence."
        ),
    }


def main() -> int:
    closure = read(ROOT / "prospective" / "closure.json")
    observation = read(OBSERVATION)
    if not verify_signed(closure):
        raise ValueError("collector closure signature invalid before witness attachment")
    if observation.get("execution_host") != "zeus1":
        raise ValueError("witness execution host is outside the pilot scope")

    collector_entries = [
        {
            "af": item["af"],
            "measurement_id": item["measurement_id"],
            "narrow_success_count": item["narrow_success_count"],
            "result_count": item["result_count"],
            "returned_probe_ids": item["returned_probe_ids"],
            "type": item["type"],
        }
        for item in closure["payload"]["source_index"]
    ]
    if observation.get("entries") != collector_entries:
        raise ValueError("effect_to_evidence: browser witness disagrees with collector")

    payload = {
        "schema": "tyche-browser-replay-witness-v0.1",
        "observed_at": observation["observed_at"],
        "execution_host": "zeus1",
        "observation_sha256": digest(observation),
        "source_semantics_sha256": digest(collector_entries),
        "measurement_ids": [item["measurement_id"] for item in collector_entries],
        "agrees_with_collector": True,
        "result_count": sum(item["result_count"] for item in collector_entries),
        "narrow_success_count": sum(item["narrow_success_count"] for item in collector_entries),
    }
    witness = sign_witness(payload)
    if not verify_signed(witness):
        raise ValueError("witness self-verification failed")
    write_json(WITNESS_DIR / "witness.json", witness)

    closure["payload"]["witness"] = witness
    closure["payload"]["verifier"]["verified_gates"].append("browser_witness_agreement")
    updated = sign_closure(closure["payload"])
    if not verify_signed(updated):
        raise ValueError("collector closure signature invalid after witness attachment")
    write_json(ROOT / "prospective" / "closure.json", updated)
    print(json.dumps({"verdict": "ALLOW", "witness": payload}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
