"""Invariant 4: an uncertain duplicate or out-of-order recovery cannot silently resolve or merge incidents."""
import copy
import itertools
import unittest

import policy
from tests.helpers import CASES, EXPECTED, clone, decide_checked, delete_field, event, set_field


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

    def test_newer_non_status_update_exposes_a_missing_reopen(self):
        """Invariant 4: if the reopen arrives only as a later non-status edit, the stale "Resolved" is never shown as current."""
        mutated = clone(CASES["AIR-03"])
        set_field(event(mutated, "e1"), "payload.body.changelog.items",
                  [{"field": "priority", "fieldtype": "jira", "fieldId": "priority", "fromString": "High", "toString": "Highest"}])
        output = decide_checked(self, mutated)
        self.assertIn("TIMELINE_CONFLICT", output["reason_codes"])
        self.assertIsNone(output["observed_state"])
        self.assertNotEqual(output["disposition"], "ACCEPT")

    def test_future_dated_recovery_cannot_set_the_state(self):
        """Invariant 4: an OK whose time is after its own receipt cannot be placed, so it cannot close AIR-06's alarm."""
        mutated = clone(CASES["AIR-06"])
        e3 = event(mutated, "e3")
        set_field(e3, "payload.body.Message#StateChangeTime", "2026-11-13T15:30:00.000+0000")
        e3["occurred_at"] = "2026-11-13T15:30:00Z"
        output = decide_checked(self, mutated)
        self.assertIn("TIMELINE_CONFLICT", output["reason_codes"])
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

    def test_same_id_from_another_sender_is_not_deduplicated(self):
        """Invariant 4: AIR-06's redelivery arriving under a different source identity is not merged as a duplicate."""
        mutated = clone(CASES["AIR-06"])
        event(mutated, "e2")["provenance"]["source_identity"] = "arn:aws:sns:ap-south-1:111122223333:other-topic"
        self.assertNotIn("DUPLICATE_DELIVERY", decide_checked(self, mutated)["reason_codes"])

    def test_updated_record_with_same_id_is_not_a_duplicate(self):
        """Invariant 4: a later update of AIR-05's case (same Id and description, new subject and time) is not deduplicated."""
        mutated = clone(CASES["AIR-05"])
        update = copy.deepcopy(mutated["events"][0])
        update["event_ref"] = "e2"
        update["payload"]["Subject"] = "Escalated: Fleet API sync still failing"
        update["payload"]["LastModifiedDate"] = update["occurred_at"] = "2026-11-12T09:15:22.000+0000"
        update["received_at"] = "2026-11-12T09:16:05Z"
        mutated["events"].append(update)
        output = decide_checked(self, mutated)
        self.assertNotIn("DUPLICATE_DELIVERY", output["reason_codes"])
        self.assertIn("ID_COLLISION", output["reason_codes"])

    def test_forward_without_unique_body_still_reports_new_information(self):
        """Invariant 4: when a forward's uniqueBody is missing, "nothing new" cannot be shown, so NEW_INFORMATION is still reported."""
        mutated = clone(CASES["AIR-02"])
        delete_field(event(mutated, "e2"), "payload.uniqueBody")
        output = decide_checked(self, mutated)
        self.assertIn("NEW_INFORMATION", output["reason_codes"])
        self.assertIn("THREAD_RELATION_ASSERTED", output["reason_codes"])


if __name__ == "__main__":
    unittest.main()
