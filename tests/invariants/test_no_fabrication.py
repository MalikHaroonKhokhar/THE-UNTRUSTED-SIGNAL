"""Invariant 2: no missing identifier or conflicting timestamp may be fabricated into verified evidence."""
import unittest
from datetime import datetime, timedelta

from tests.helpers import ID_PATH, TIME_PATH, CASES, clone, decide_checked, delete_field, event, fields, set_field


def shifted(timestamp, hours):
    """An ISO timestamp moved by `hours`."""
    return (datetime.fromisoformat(timestamp) + timedelta(hours=hours)).isoformat()


class NoFabrication(unittest.TestCase):
    def assert_flagged(self, mutate, code):
        """Mutate each event of each case in turn: never ACCEPT and `code` present. Returns nothing."""
        for case_id, case in CASES.items():
            for item in case["events"]:
                mutated = clone(case)
                if mutate(event(mutated, item["event_ref"])) is False:
                    continue  # the mutation does not apply to this event
                with self.subTest(case_id=case_id, event=item["event_ref"]):
                    self.assertNotEqual(mutated, case)  # the mutation really happened
                    output = decide_checked(self, mutated)
                    self.assertNotEqual(output["disposition"], "ACCEPT")
                    self.assertIn(code, output["reason_codes"])

    def assert_deletion_not_invented(self, paths, code):
        """Delete each event's declared field in turn: never ACCEPT, `code` present, no ref to the deleted field."""
        for case_id, case in CASES.items():
            for event_ref, path in fields(case, paths):
                with self.subTest(case_id=case_id, event=event_ref):
                    mutated = clone(case)
                    delete_field(event(mutated, event_ref), path)
                    self.assertNotEqual(mutated, case)
                    output = decide_checked(self, mutated)
                    self.assertNotEqual(output["disposition"], "ACCEPT")
                    self.assertIn(code, output["reason_codes"])
                    self.assertNotIn(f"{event_ref}:{path}", [ref["ref"] for ref in output["evidence_refs"]])

    def test_missing_event_time_is_never_invented(self):
        """Invariant 2: with its declared time deleted, an event gets MISSING_OCCURRED_AT, is never accepted, and nothing cites the deleted field."""
        self.assert_deletion_not_invented(TIME_PATH, "MISSING_OCCURRED_AT")

    def test_missing_source_id_is_never_invented(self):
        """Invariant 2: with its declared source ID deleted, an event gets MISSING_SOURCE_EVENT_ID and is never accepted."""
        self.assert_deletion_not_invented(ID_PATH, "MISSING_SOURCE_EVENT_ID")

    def test_malformed_source_id_is_dropped(self):
        """Invariant 2: a source ID that does not match its connector's format is dropped (ID_UNTRUSTED_FORMAT), never trusted."""
        self.assert_flagged(lambda item: set_field(item, ID_PATH[item["connector"]], "not an id"), "ID_UNTRUSTED_FORMAT")

    def test_conflicting_event_times_are_flagged(self):
        """Invariant 2: when the adapter's occurred_at disagrees with the payload's event time, the conflict is reported, not resolved."""
        def mutate(item):
            """Move the adapter's occurred_at one hour away from the payload's event time."""
            if item["occurred_at"] is None:
                return False
            item["occurred_at"] = shifted(item["occurred_at"], 1)
        self.assert_flagged(mutate, "TIMELINE_CONFLICT")

    def test_event_time_after_receipt_is_flagged(self):
        """Invariant 2: an event time more than five minutes after its receipt time is reported as CLOCK_SKEW."""
        def mutate(item):
            """Record receipt one hour before the event time."""
            if item["occurred_at"] is None:
                return False
            item["received_at"] = shifted(item["occurred_at"], -1)
        self.assert_flagged(mutate, "CLOCK_SKEW")

    def test_unverified_event_is_never_cited_as_observed(self):
        """Invariant 2: once an event's verification is false, none of its payload fields is cited as observed evidence."""
        def mutate(item):
            """Mark a verified event as unverified."""
            if item["provenance"]["verified"] is not True:
                return False  # already unverified (AIR-08)
            item["provenance"]["verified"] = False
        self.assert_flagged(mutate, "UNVERIFIED_SOURCE")  # check() inside rejects any observed payload ref


if __name__ == "__main__":
    unittest.main()
