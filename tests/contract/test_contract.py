"""Fixture coverage, output shape and determinism."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

import policy
from tests.helpers import CASES, OUTPUT_KEYS, ROOT, load_jsonl

CASE_IDS = [f"AIR-0{n}" for n in range(1, 9)]


class Contract(unittest.TestCase):
    def test_fixture_files_hold_exactly_the_eight_cases(self):
        """Contract: events.jsonl and expected.jsonl each hold exactly AIR-01 to AIR-08, in order."""
        self.assertEqual([case["case_id"] for case in load_jsonl("events.jsonl")], CASE_IDS)
        self.assertEqual([row["case_id"] for row in load_jsonl("expected.jsonl")], CASE_IDS)

    def test_decisions_have_contract_keys_in_order(self):
        """Contract: every decision has exactly the contract's keys, in the contract's order, and is not a crash record."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                decision = policy.decide(case)
                self.assertEqual(tuple(decision), OUTPUT_KEYS)
                self.assertNotIn("POLICY_ERROR", decision["reason_codes"])

    def test_cli_is_byte_identical_across_hash_seeds(self):
        """Determinism: two CLI runs with different PYTHONHASHSEED values print identical bytes, with no POLICY_ERROR."""
        runs = [subprocess.run([sys.executable, "policy.py", "fixtures/events.jsonl"], cwd=ROOT, check=True,
                               capture_output=True, env={**os.environ, "PYTHONHASHSEED": seed}).stdout
                for seed in ("0", "4242")]
        self.assertEqual(runs[0], runs[1])
        self.assertEqual(len(runs[0].splitlines()), len(CASE_IDS))
        self.assertNotIn(b"POLICY_ERROR", runs[0])

    def test_cli_survives_unreadable_lines(self):
        """Fail closed: an absurdly nested line and a non-UTF-8 line each get a QUARANTINE decision; the other cases still run."""
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "events.jsonl")
            with open(os.path.join(ROOT, "fixtures", "events.jsonl"), "rb") as source, open(path, "wb") as target:
                target.write(source.read() + b"[" * 200000 + b"\n" + b'{"case_id": "AIR-99\xff"}\n')
            run = subprocess.run([sys.executable, "policy.py", path], cwd=ROOT, check=True, capture_output=True)
        decisions = [json.loads(line) for line in run.stdout.splitlines()]
        self.assertEqual([item["case_id"] for item in decisions], CASE_IDS + ["UNKNOWN", "UNKNOWN"])
        for item in decisions[-2:]:
            self.assertEqual((item["disposition"], item["reason_codes"]), ("QUARANTINE", ["MALFORMED_ENVELOPE"]))


if __name__ == "__main__":
    unittest.main()
