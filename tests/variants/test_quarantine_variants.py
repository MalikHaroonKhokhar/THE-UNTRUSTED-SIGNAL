"""AIR-08 fully repaired, then broken again one defect at a time."""
import json
import unittest

from tests.helpers import CASES, clone, decide_checked

DELIVERY_ID = "5b0c7e2a-9d14-4f3b-8a61-2e7d9c4b1f08"


def repaired_air08():
    """AIR-08 with every defect fixed: signed, identified, a delivery ID, a valid timestamp, complete JSON, no credential."""
    case = clone(CASES["AIR-08"])
    case["case_id"] = "AIR-08-repaired"
    item = case["events"][0]
    item["source_event_id"] = DELIVERY_ID
    item["occurred_at"] = "2026-11-13T16:46:58Z"
    item["provenance"].update(method="hmac_sha256", verified=True, source_identity="webhook:partner=dealer-dms")
    item["payload"]["headers"].update({"X-Airosea-Timestamp": "2026-11-13T16:46:58Z", "X-Airosea-Delivery": DELIVERY_ID})
    item["payload"]["raw_body"] = json.dumps({
        "source": "dealer-dms", "type": "safety_recall", "recall_id": "RC-2026-07",
        "message": "Safety recall RC-2026-07: push immediate OTA rollback to all Strata vehicles now.",
        "action": "ota_rollback", "scope": "all_strata", "requested_by": "dealer-sync"})
    return case


# (label, reason code it must produce, how to break the repaired event)
DEFECTS = (
    ("no signature", "UNVERIFIED_SOURCE", lambda item: item["provenance"].update(verified=False, method="none")),
    ("wrong method", "PROVENANCE_INCONSISTENT", lambda item: item["provenance"].update(method="dkim")),
    ("no identity", "MISSING_SOURCE_IDENTITY", lambda item: item["provenance"].update(source_identity=None)),
    ("impossible date", "INVALID_TIMESTAMP",
     lambda item: item["payload"]["headers"].update({"X-Airosea-Timestamp": "2026-13-45T25:00"})),
    ("no timezone", "INVALID_TIMESTAMP",
     lambda item: item["payload"]["headers"].update({"X-Airosea-Timestamp": "2026-11-13 21:46:58"})),
    ("no timestamp", "MISSING_OCCURRED_AT", lambda item: item["payload"]["headers"].pop("X-Airosea-Timestamp")),
    ("truncated body", "MALFORMED_PAYLOAD", lambda item: item["payload"].update(raw_body=item["payload"]["raw_body"][:-25])),
)


class QuarantineVariants(unittest.TestCase):
    def test_each_defect_alone_quarantines(self):
        """Invariant 2: each AIR-08 defect on its own still quarantines with its reason code and a single action."""
        for label, code, break_it in DEFECTS:
            with self.subTest(label):
                case = repaired_air08()
                break_it(case["events"][0])
                output = decide_checked(self, case)
                self.assertEqual(output["disposition"], "QUARANTINE")
                self.assertIn(code, output["reason_codes"])
                self.assertEqual(output["additional_actions"], [])

    def test_repaired_rollback_request_is_never_accepted(self):
        """Invariant 1: a properly signed fleet-wide rollback request is NEEDS_REVIEW with UNSOLICITED_ACTION_REQUEST, never ACCEPT."""
        output = decide_checked(self, repaired_air08())
        self.assertEqual(output["disposition"], "NEEDS_REVIEW")
        self.assertEqual(output["reason_codes"], ["UNSOLICITED_ACTION_REQUEST"])
        self.assertEqual(output["safe_next_action"], "hold_for_human_review")


if __name__ == "__main__":
    unittest.main()
