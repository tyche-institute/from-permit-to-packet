#!/usr/bin/env python3

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from permit_to_packet import EVALUATORS  # noqa: E402


class PermitToPacketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.index = json.loads((ROOT / "corpus-index.json").read_text())

    def bundle(self, case_id: str) -> dict:
        return json.loads((ROOT / "corpus" / f"{case_id}.json").read_text())

    def test_clean_case_is_accepted_by_all_verifiers(self) -> None:
        positives = [
            item for item in self.index["cases"]
            if item["expected"]["ground_truth"] == "ALLOW"
        ]
        self.assertEqual(22, len(positives))
        for item in positives:
            bundle = self.bundle(item["case_id"])
            for name, verifier in EVALUATORS.items():
                with self.subTest(case=item["case_id"], verifier=name):
                    self.assertEqual("ALLOW", verifier(bundle)["verdict"])

    def test_every_designed_fault_has_a_matched_positive_control(self) -> None:
        pairs: dict[str, set[str]] = {}
        for item in self.index["cases"]:
            if item["pair_id"] is None:
                continue
            pairs.setdefault(item["pair_id"], set()).add(item["expected"]["ground_truth"])
        self.assertEqual(21, len(pairs))
        self.assertTrue(all(outcomes == {"ALLOW", "DENY"} for outcomes in pairs.values()))

    def test_witnessed_composed_rejects_every_negative_at_expected_edge(self) -> None:
        for item in self.index["cases"]:
            if item["expected"]["ground_truth"] != "DENY":
                continue
            verdict = EVALUATORS["composed_witnessed"](self.bundle(item["case_id"]))
            with self.subTest(case=item["case_id"]):
                self.assertEqual("DENY", verdict["verdict"])
                self.assertEqual(item["expected"]["first_bad_edge"], verdict["first_bad_edge"])

    def test_offline_composed_exposes_collector_reissue_blind_spot(self) -> None:
        bundle = self.bundle("D20_collector_reissued_cherry_pick")
        self.assertEqual("ALLOW", EVALUATORS["composed_offline"](bundle)["verdict"])
        self.assertEqual("DENY", EVALUATORS["composed_witnessed"](bundle)["verdict"])

    def test_hash_only_accepts_semantically_rehashed_faults(self) -> None:
        bundle = self.bundle("D01_target_substitution")
        self.assertEqual("ALLOW", EVALUATORS["hash_only"](bundle)["verdict"])
        self.assertEqual("DENY", EVALUATORS["composed_witnessed"](bundle)["verdict"])


if __name__ == "__main__":
    unittest.main()
