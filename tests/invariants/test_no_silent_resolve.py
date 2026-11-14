"""Invariant 4: an uncertain duplicate or out-of-order recovery cannot silently resolve or merge incidents."""
import copy
import itertools
import unittest

import policy
from tests.helpers import CASES, EXPECTED, clone, decide_checked, event, set_field


class NoSilentResolve(unittest.TestCase):
    def test_file_order_never_changes_the_decision(self):
        """Invariant 4: every ordering of AIR-03's and AIR-06's events gives the same decision and observed_state."""
        for case_id in ("AIR-03", "AIR-06"):
            baseline = policy.decide(CASES[case_id])
            self.assertEqual(baseline["observed_state"], EXPECTED[case_id]["observed_state"])
            for order in itertools.permutations(CASES[case_id]["events"]):
                with self.subTest(case_id=case_id, order=[item["event_ref"] for item in order]):
                    mutated = clone(CASES[case_id])
                    mutated["events"] = [copy.deepcopy(item) for item in order]
                    self.assertEqual(decide_checked(self, mutated), baseline)

    def test_broken_state_chain_is_a_conflict(self):
        """Invariant 4: if AIR-06's previous-state chain breaks, the current state is unconfirmed and a human reviews it."""
        mutated = clone(CASES["AIR-06"])
        for event_ref in ("e1", "e2"):
            set_field(event(mutated, event_ref), "payload.body.Message#OldStateValue", "INSUFFICIENT_DATA")
        output = decide_checked(self, mutated)
        self.assertIn("TIMELINE_CONFLICT", output["reason_codes"])
        self.assertEqual(output["disposition"], "NEEDS_REVIEW")
        self.assertIsNone(output["observed_state"])

    def test_reused_message_id_is_not_deduplicated(self):
        """Invariant 4: AIR-06's MessageId reused with different content is an ID collision, never a silent duplicate."""
        mutated = clone(CASES["AIR-06"])
        message_id = policy.resolve(event(mutated, "e1"), "payload.body.MessageId")
        set_field(event(mutated, "e3"), "payload.body.MessageId", message_id)
        output = decide_checked(self, mutated)
        self.assertIn("ID_COLLISION", output["reason_codes"])
        self.assertNotIn("DUPLICATE_DELIVERY", output["reason_codes"])
        self.assertEqual(output["disposition"], "NEEDS_REVIEW")
        self.assertEqual(output["observed_state"], "ALARM")


if __name__ == "__main__":
    unittest.main()
