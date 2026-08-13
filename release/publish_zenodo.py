#!/usr/bin/env python3
"""Create, fill, verify, and explicitly publish the Zenodo v0.1.0 record.

The irreversible publish action is available only with ``--publish``. Draft
creation and upload are separate so the reserved DOI can be inserted into the
manuscript and release before final bytes are uploaded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "release" / ".zenodo-draft-state.json"
METADATA = ROOT / "release" / "zenodo-metadata-draft.json"
ARCHIVE = Path("/srv/tyche/releases/from-permit-to-packet-v0.1.0/from-permit-to-packet-v0.1.0.zip")
API = "https://zenodo.org/api"


class ZenodoError(RuntimeError):
    pass


def request(method: str, url: str, token: str = "", *, json_body=None, raw_body=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif raw_body is not None:
        data = raw_body
        headers["Content-Type"] = "application/octet-stream"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise ZenodoError(f"{method} {url} -> HTTP {error.code}\n{detail}") from error


def load_token() -> str:
    if os.environ.get("ZENODO_TOKEN"):
        return os.environ["ZENODO_TOKEN"]
    candidates = list(Path(__file__).resolve().parents) + list(Path.cwd().resolve().parents)
    for directory in candidates:
        env_file = directory / ".env"
        if not env_file.exists():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            if key.strip() == "ZENODO_TOKEN":
                return value.strip().strip('"').strip("'")
    return ""


def md5(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


def files() -> list[tuple[Path, str]]:
    return [
        (ARCHIVE, "from-permit-to-packet-v0.1.0.zip"),
        (ROOT / "manuscript-v0.1.pdf", "from-permit-to-packet-manuscript-v0.1.0.pdf"),
        (ROOT / "SHA256SUMS", "SHA256SUMS"),
        (ROOT / "RELEASE-NOTES.md", "RELEASE-NOTES.md"),
    ]


def create_draft(token: str) -> dict:
    payload = json.loads(METADATA.read_text(encoding="utf-8"))
    draft = request("POST", f"{API}/deposit/depositions", token, json_body=payload)
    state = {
        "deposit_id": draft["id"],
        "bucket": draft["links"]["bucket"],
        "html": draft["links"]["html"],
        "reserved_doi": draft["metadata"]["prereserve_doi"]["doi"],
    }
    STATE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return state


def load_state() -> dict:
    if not STATE.exists():
        raise ZenodoError("No local Zenodo draft state; run --create-draft first")
    return json.loads(STATE.read_text(encoding="utf-8"))


def upload_and_verify(token: str, state: dict) -> dict:
    selected = files()
    for path, _ in selected:
        if not path.exists():
            raise ZenodoError(f"Missing release file: {path}")
    draft = request("GET", f"{API}/deposit/depositions/{state['deposit_id']}", token)
    for item in draft.get("files", []):
        request("DELETE", f"{API}/deposit/depositions/{state['deposit_id']}/files/{item['id']}", token)
    for path, name in selected:
        request("PUT", f"{state['bucket']}/{name}", token, raw_body=path.read_bytes())
    metadata = json.loads(METADATA.read_text(encoding="utf-8"))
    request("PUT", f"{API}/deposit/depositions/{state['deposit_id']}", token, json_body=metadata)
    checked = request("GET", f"{API}/deposit/depositions/{state['deposit_id']}", token)
    expected = {name: md5(path) for path, name in selected}
    observed = {
        item.get("filename") or item.get("key"): (item.get("checksum") or "").replace("md5:", "")
        for item in checked.get("files", [])
    }
    if expected != observed:
        raise ZenodoError(f"Uploaded files do not match local bytes: expected={expected}, observed={observed}")
    if checked["metadata"].get("prereserve_doi", {}).get("doi") != state["reserved_doi"]:
        raise ZenodoError("Reserved DOI changed during metadata update")
    return checked


def publish(token: str, state: dict) -> dict:
    result = request("POST", f"{API}/deposit/depositions/{state['deposit_id']}/actions/publish", token)
    public = request("GET", f"{API}/records/{result['id']}")
    output = {
        "record_id": public["id"],
        "doi": public["doi"],
        "conceptdoi": public["conceptdoi"],
        "title": public["metadata"]["title"],
        "version": public["metadata"].get("version"),
        "html": public["links"]["html"],
        "files": [item["key"] for item in public.get("files", [])],
    }
    (ROOT / "release" / "zenodo-record.json").write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-draft", action="store_true")
    parser.add_argument("--upload", action="store_true")
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args(argv)
    if not any((args.create_draft, args.upload, args.publish)):
        parser.error("choose --create-draft, --upload, or --publish")
    token = load_token()
    if not token:
        sys.exit("ZENODO_TOKEN not found")
    state = create_draft(token) if args.create_draft else load_state()
    print(json.dumps(state, indent=2, sort_keys=True))
    if args.upload:
        checked = upload_and_verify(token, state)
        print(json.dumps({"verified_draft": checked["id"], "files": len(checked["files"])}, indent=2))
    if args.publish:
        print(json.dumps(publish(token, state), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
