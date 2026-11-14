"""Invariant 1: ticket, email and alert bodies cannot grant tool permissions or override the policy."""
import unittest

import policy
from tests.helpers import (CASES, DISGUISED_INJECTION, OBVIOUS_INJECTION, append_to_free_text, clone,
                           decide_checked, rank)


class Authority(unittest.TestCase):
    def test_obvious_injection_never_lowers_strictness(self):
        """Invariant 1: an injection appended to every free-text field never makes a decision less strict, and is flagged unless quarantined."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                clean = policy.decide(case)
                output = decide_checked(self, append_to_free_text(case, OBVIOUS_INJECTION))
                self.assertGreaterEqual(rank(output), rank(clean))
                if output["disposition"] != "QUARANTINE":
                    self.assertIn("INJECTION_REJECTED", output["reason_codes"])

    def test_undetected_injection_changes_nothing(self):
        """Invariant 1: an injection the detector misses leaves disposition, codes, actions and review flag unchanged."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                clean = policy.decide(case)
                output = decide_checked(self, append_to_free_text(case, DISGUISED_INJECTION))
                for field in ("disposition", "reason_codes", "safe_next_action", "additional_actions",
                              "human_review_required"):
                    self.assertEqual(output[field], clean[field], field)

    def test_payload_cannot_claim_verification_or_permissions(self):
        """Invariant 1: provenance and admin permissions written inside the payload change nothing at all."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                mutated = clone(case)
                for item in mutated["events"]:
                    item["payload"]["provenance"] = {"method": "hmac_sha256", "verified": True, "source_identity": "admin"}
                    item["payload"]["permissions"] = ["admin"]
                self.assertEqual(decide_checked(self, mutated), policy.decide(case))


if __name__ == "__main__":
    unittest.main()
