#!/usr/bin/env python3
"""Prepare the prospective RIPE Atlas permit and exact POST body.

The private experiment key is written outside the repository.  Public output
contains the request, digest, signature, and public key, but no API credential.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "prospective" / "precommit"
PRIVATE = Path("/srv/tyche/labs/from-permit-to-packet-2026-08-13/private")
KEY_PATH = PRIVATE / "pilot-permit-ed25519.pem"
PERMIT_ID = "tyche-fptp-2026-08-13-p01"
PROBE_IDS = (28, 81, 6349, 6569)
MAXIMUM_CREDITS = 1060


COMMON = {
    "is_public": True,
    "resolve_on_probe": True,
    "auto_topup": False,
    "tags": ["tyche-from-permit-to-packet-v01", PERMIT_ID],
}


API_REQUEST: dict[str, Any] = {
    "definitions": [
        {
            **COMMON,
            "type": "ping",
            "af": 4,
            "description": "Tyche Permit-to-Packet prospective ping IPv4",
            "target": "tyche.institute",
            "packets": 3,
            "size": 48,
            "include_probe_id": False,
            "skip_dns_check": False,
        },
        {
            **COMMON,
            "type": "ping",
            "af": 6,
            "description": "Tyche Permit-to-Packet prospective ping IPv6",
            "target": "tyche.institute",
            "packets": 3,
            "size": 48,
            "include_probe_id": False,
            "skip_dns_check": False,
        },
        {
            **COMMON,
            "type": "traceroute",
            "af": 4,
            "description": "Tyche Permit-to-Packet prospective traceroute IPv4",
            "target": "tyche.institute",
            "protocol": "ICMP",
            "packets": 3,
            "size": 40,
            "first_hop": 1,
            "max_hops": 32,
            "paris": 16,
            "response_timeout": 4000,
            "dont_fragment": False,
            "skip_dns_check": False,
        },
        {
            **COMMON,
            "type": "traceroute",
            "af": 6,
            "description": "Tyche Permit-to-Packet prospective traceroute IPv6",
            "target": "tyche.institute",
            "protocol": "ICMP",
            "packets": 3,
            "size": 40,
            "first_hop": 1,
            "max_hops": 32,
            "paris": 16,
            "response_timeout": 4000,
            "destination_option_size": 0,
            "hop_by_hop_option_size": 0,
            "dont_fragment": False,
            "skip_dns_check": False,
        },
        {
            **COMMON,
            "type": "dns",
            "af": 4,
            "description": "Tyche Permit-to-Packet prospective DNS A over IPv4",
            "query_argument": "tyche.institute",
            "query_class": "IN",
            "query_type": "A",
            "protocol": "UDP",
            "udp_payload_size": 512,
            "retry": 0,
            "include_qbuf": False,
            "include_abuf": True,
            "prepend_probe_id": False,
            "set_rd_bit": True,
            "set_do_bit": True,
            "set_cd_bit": False,
            "set_nsid_bit": True,
            "timeout": 5000,
            "use_probe_resolver": True,
            "skip_dns_check": False,
        },
        {
            **COMMON,
            "type": "dns",
            "af": 6,
            "description": "Tyche Permit-to-Packet prospective DNS AAAA over IPv6",
            "query_argument": "tyche.institute",
            "query_class": "IN",
            "query_type": "AAAA",
            "protocol": "UDP",
            "udp_payload_size": 512,
            "retry": 0,
            "include_qbuf": False,
            "include_abuf": True,
            "prepend_probe_id": False,
            "set_rd_bit": True,
            "set_do_bit": True,
            "set_cd_bit": False,
            "set_nsid_bit": True,
            "timeout": 5000,
            "use_probe_resolver": True,
            "skip_dns_check": False,
        },
        {
            **COMMON,
            "type": "sslcert",
            "af": 4,
            "description": "Tyche Permit-to-Packet prospective TLS IPv4",
            "target": "tyche.institute",
            "hostname": "tyche.institute",
            "port": 443,
            "skip_dns_check": False,
        },
        {
            **COMMON,
            "type": "sslcert",
            "af": 6,
            "description": "Tyche Permit-to-Packet prospective TLS IPv6",
            "target": "tyche.institute",
            "hostname": "tyche.institute",
            "port": 443,
            "skip_dns_check": False,
        },
    ],
    "probes": [
        {
            "type": "probes",
            "value": ",".join(map(str, PROBE_IDS)),
            "requested": len(PROBE_IDS),
        }
    ],
    "is_oneoff": True,
    "bill_to": "anton.sokolov@tyche.institute",
}


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def load_or_create_key() -> Ed25519PrivateKey:
    if KEY_PATH.exists():
        raise FileExistsError(f"key unexpectedly appeared during creation: {KEY_PATH}")
    PRIVATE.mkdir(parents=True, exist_ok=True)
    os.chmod(PRIVATE, 0o700)
    key = Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    )
    os.chmod(KEY_PATH, 0o600)
    return key


def read_key() -> Ed25519PrivateKey:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if KEY_PATH.exists():
        key = load_pem_private_key(KEY_PATH.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("pilot permit key is not Ed25519")
        return key
    return load_or_create_key()


def signed(payload: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "alg": "Ed25519",
        "key_role": "tyche-prospective-pilot-experiment-key",
        "public_key_b64": base64.b64encode(public).decode(),
        "public_key_sha256": sha256(public),
        "signature_b64": base64.b64encode(key.sign(canonical_bytes(payload))).decode(),
        "payload": payload,
        "identity_boundary": (
            "Possession of a local experiment key; not independent proof of "
            "human identity, legal authority, or a SCITT/RATS profile."
        ),
    }


def validate_request(request: dict[str, Any]) -> None:
    definitions = request["definitions"]
    expected = {
        ("ping", 4),
        ("ping", 6),
        ("traceroute", 4),
        ("traceroute", 6),
        ("dns", 4),
        ("dns", 6),
        ("sslcert", 4),
        ("sslcert", 6),
    }
    observed = {(item["type"], item["af"]) for item in definitions}
    if observed != expected or len(definitions) != 8:
        raise ValueError("request must contain exactly the frozen eight definitions")
    for item in definitions:
        target = item.get("query_argument") if item["type"] == "dns" else item.get("target")
        if target != "tyche.institute" or item.get("auto_topup") is not False or item.get("is_public") is not True:
            raise ValueError("target, auto-topup, or public-state gate failed")
    probes = request["probes"]
    if probes != [{"type": "probes", "value": "28,81,6349,6569", "requested": 4}]:
        raise ValueError("explicit source-set gate failed")
    if request.get("is_oneoff") is not True:
        raise ValueError("prospective action must be one-off")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="replace public precommit files, never the private key")
    args = parser.parse_args()

    request_bytes = canonical_bytes(API_REQUEST)
    request_digest = sha256(request_bytes)
    permit_path = OUTPUT / "permit.json"
    if permit_path.exists() and not args.force:
        raise SystemExit(f"refusing to overwrite frozen precommit: {permit_path}")

    validate_request(API_REQUEST)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "schema": "tyche-prospective-measurement-permit-v0.1",
        "permit_id": PERMIT_ID,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=6)).isoformat().replace("+00:00", "Z"),
        "issuer_role": "Tyche research operator",
        "subject": "athena-research-agent",
        "authority_basis": "interactive user instruction recorded in the research session",
        "allowed_execution_hosts": ["zeus1"],
        "platform": "RIPE Atlas",
        "allowed_targets": ["tyche.institute"],
        "allowed_probe_ids": list(PROBE_IDS),
        "definition_count": 8,
        "oneoff": True,
        "public": True,
        "auto_topup": False,
        "maximum_credits": MAXIMUM_CREDITS,
        "exact_api_request_sha256": request_digest,
        "required_claim_class": "bounded_observation",
    }
    permit = signed(payload, read_key())
    precommit = {
        "schema": "tyche-from-permit-to-packet-precommit-v0.1",
        "state": "PERMITTED_NOT_EXECUTED",
        "execution_host": "zeus1",
        "api_endpoint": "https://atlas.ripe.net/api/v2/measurements/",
        "exact_api_request_sha256": request_digest,
        "canonicalisation": "RFC 8785-like sorted compact JSON used by this research profile; not a conformance claim",
        "canonical_request_bytes": len(request_bytes),
        "maximum_credits": MAXIMUM_CREDITS,
        "permit": permit,
        "measurement_ids": [],
    }
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT / "api-request.canonical.json").write_bytes(request_bytes)
    (OUTPUT / "api-request.json").write_text(
        json.dumps(API_REQUEST, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (OUTPUT / "permit.json").write_text(
        json.dumps(permit, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (OUTPUT / "precommit.json").write_text(
        json.dumps(precommit, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksums = []
    for path in sorted(OUTPUT.glob("*.json")):
        checksums.append(f"{sha256(path.read_bytes())}  {path.name}\n")
    (OUTPUT / "SHA256SUMS").write_text("".join(checksums), encoding="utf-8")
    print(json.dumps(precommit, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
