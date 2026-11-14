"""Invariant 2: no missing identifier or conflicting timestamp may be fabricated into verified evidence."""
import unittest

from tests.helpers import CASES, clone, decide_checked, declared, delete_field, event


class NoFabrication(unittest.TestCase):
    def assert_not_invented(self, column, code):
        """Delete each event's declared field in turn: never ACCEPT, `code` present, no ref to the deleted field."""
        for case_id, case in CASES.items():
            for event_ref, path in declared(case, column):
                with self.subTest(case_id=case_id, event=event_ref):
                    mutated = clone(case)
                    delete_field(event(mutated, event_ref), path)
                    output = decide_checked(self, mutated)
                    self.assertNotEqual(output["disposition"], "ACCEPT")
                    self.assertIn(code, output["reason_codes"])
                    self.assertNotIn(f"{event_ref}:{path}", [item["ref"] for item in output["evidence_refs"]])

    def test_missing_event_time_is_never_invented(self):
        """Invariant 2: with its declared time deleted, an event gets MISSING_OCCURRED_AT; receipt time is never substituted."""
        self.assert_not_invented("time", "MISSING_OCCURRED_AT")

    def test_missing_source_id_is_never_invented(self):
        """Invariant 2: with its declared source ID deleted, an event gets MISSING_SOURCE_EVENT_ID and is never accepted."""
        self.assert_not_invented("id", "MISSING_SOURCE_EVENT_ID")


if __name__ == "__main__":
    unittest.main()
