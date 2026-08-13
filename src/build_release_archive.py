#!/usr/bin/env python3
"""Build a deterministic private staging archive; never performs a deposit."""

from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = Path("/srv/tyche/releases/from-permit-to-packet-v0.1.0")
ARCHIVE = OUTPUT / "from-permit-to-packet-v0.1.0.zip"
FIXED_TIME = (2026, 8, 13, 0, 0, 0)


def included(path: Path) -> bool:
    return (
        path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
        and path.name not in {"release-stage.json", ".zenodo-draft-state.json"}
    )


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in ROOT.rglob("*") if included(path))
    with zipfile.ZipFile(ARCHIVE, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = Path("from-permit-to-packet-v0.1.0") / path.relative_to(ROOT)
            info = zipfile.ZipInfo(str(relative), date_time=FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    raw = ARCHIVE.read_bytes()
    stage = {
        "schema": "tyche-from-permit-to-packet-release-stage-v0.1.0",
        "state": "READY_FOR_VERIFIED_DEPOSIT",
        "reason": "Dual licensing and isolated public source are resolved; publish only after checksum verification.",
        "archive": str(ARCHIVE),
        "archive_bytes": len(raw),
        "archive_sha256": hashlib.sha256(raw).hexdigest(),
        "included_file_count": len(files),
        "private_keys_included": False,
        "raw_capture_included": False,
    }
    (OUTPUT / "release-stage.json").write_text(
        json.dumps(stage, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(stage, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
