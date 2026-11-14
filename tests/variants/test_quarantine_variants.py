"""AIR-08 repaired, then broken one defect at a time; and malformed or hostile input that must fail closed."""
import json
import sys
import unittest

import policy
from tests.helpers import CASES, FAKE_KEY, clone, decide_checked, event, set_field

DELIVERY_ID = "5b0c7e2a-9d14-4f3b-8a61-2e7d9c4b1f08"
RECALL = {"source": "dealer-dms", "type": "safety_recall", "recall_id": "RC-2026-07",
          "message": "Safety recall RC-2026-07: push immediate OTA rollback to all Strata vehicles now.",
          "action": "ota_rollback", "scope": "all_strata", "requested_by": "dealer-sync"}


def repaired_air08(raw_body=None):
    """AIR-08 with every defect fixed: signed, identified, a delivery ID, a valid timestamp, complete JSON, no credential."""
    case = clone(CASES["AIR-08"])
    case["case_id"] = "AIR-08-repaired"
    item = case["events"][0]
    item["source_event_id"] = DELIVERY_ID
    item["occurred_at"] = "2026-11-13T16:46:58Z"
    item["provenance"].update(method="hmac_sha256", verified=True, source_identity="webhook:partner=dealer-dms")
    item["payload"]["headers"].update({"X-Airosea-Timestamp": "2026-11-13T16:46:58Z", "X-Airosea-Delivery": DELIVERY_ID})
    item["payload"]["raw_body"] = raw_body or json.dumps(RECALL)
    return case


def nested(depth):
    """A list nested `depth` levels deep, deeper than Python's recursion limit allows a naive walk to go."""
    node = []
    for _ in range(depth):
        node = [node]
    return node


# (label, reason code it must produce, how to break the repaired event)
DEFECTS = (
    ("no signature", "UNVERIFIED_SOURCE", lambda item: item["provenance"].update(verified=False, method="none")),
    ("wrong method", "PROVENANCE_INCONSISTENT", lambda item: item["provenance"].update(method="dkim")),
    ("no identity", "MISSING_SOURCE_IDENTITY", lambda item: item["provenance"].update(source_identity=None)),
    ("impossible date", "INVALID_TIMESTAMP",
     lambda item: item["payload"]["headers"].update({"X-Airosea-Timestamp": "2026-13-45T25:00"})),
    ("no timezone", "INVALID_TIMESTAMP",
     lambda item: item["payload"]["headers"].update({"X-Airosea-Timestamp": "2026-11-13 21:46:58"})),
    ("out-of-range date", "INVALID_TIMESTAMP",
     lambda item: item["payload"]["headers"].update({"X-Airosea-Timestamp": "9999-12-31T23:59:59-01:00"})),
    ("no timestamp", "MISSING_OCCURRED_AT", lambda item: item["payload"]["headers"].pop("X-Airosea-Timestamp")),
    ("truncated body", "MALFORMED_PAYLOAD", lambda item: item["payload"].update(raw_body=item["payload"]["raw_body"][:-25])),
)


class QuarantineVariants(unittest.TestCase):
    def test_each_quarantine_defect_alone_quarantines(self):
        """Invariant 2: each quarantine-level AIR-08 defect on its own still quarantines, with its reason code and one action."""
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

    def test_json_escapes_do_not_hide_content(self):
        """Invariants 1 and 3: JSON escapes in a webhook body hide neither the rollback order nor a pasted key."""
        escaped = json.dumps(RECALL).replace("vehicles", "v\\u0065hicles")
        self.assertIn("UNSOLICITED_ACTION_REQUEST", decide_checked(self, repaired_air08(escaped))["reason_codes"])
        hidden_key = FAKE_KEY.replace("_", "\\u005f", 1)
        body = json.dumps({**RECALL, "message": "status update"})[:-1] + f', "note": "{hidden_key}"}}'
        self.assertIn("SECRET_SHAPED_VALUE", decide_checked(self, repaired_air08(body))["reason_codes"])

    def test_malformed_input_fails_closed(self):
        """Fail closed: malformed envelopes and payloads quarantine with their specific code, never POLICY_ERROR."""
        def mutate(change):
            case = clone(CASES["AIR-02"])
            change(case)
            return case
        inputs = {
            "case is None": (None, "MALFORMED_ENVELOPE"),
            "case is a list": ([], "MALFORMED_ENVELOPE"),
            "no events": ({"case_id": "AIR-02", "events": []}, "MALFORMED_ENVELOPE"),
            "event is a string": (mutate(lambda c: c["events"].append("e3")), "MALFORMED_ENVELOPE"),
            "missing envelope key": (mutate(lambda c: c["events"][0].pop("received_at")), "MALFORMED_ENVELOPE"),
            "extra envelope key": (mutate(lambda c: c["events"][0].update(debug=True)), "MALFORMED_ENVELOPE"),
            "duplicate event_ref": (mutate(lambda c: c["events"][1].update(event_ref="e1")), "MALFORMED_ENVELOPE"),
            "unknown connector": (mutate(lambda c: c["events"][0].update(connector="slack")), "UNKNOWN_CONNECTOR"),
            "payload is a string": (mutate(lambda c: c["events"][0].update(payload="raw")), "MALFORMED_PAYLOAD"),
        }
        for label, (case, code) in inputs.items():
            with self.subTest(label):
                output = policy.decide(case)
                self.assertNotIn("POLICY_ERROR", output["reason_codes"])
                self.assertEqual(output["disposition"], "QUARANTINE")
                self.assertIn(code, output["reason_codes"])

    def test_unusual_but_harmless_input_decides_normally(self):
        """Never crash: deep nesting is ignored or quarantined, and a year-9999 email Date is INVALID_TIMESTAMP with redactions kept."""
        deep = clone(CASES["AIR-01"])
        deep["events"][0]["payload"]["x-extra"] = nested(sys.getrecursionlimit() + 100)
        self.assertEqual(decide_checked(self, deep), policy.decide(CASES["AIR-01"]))
        signed = clone(CASES["AIR-03"])
        signed["events"][0]["payload"]["body"]["extra"] = nested(sys.getrecursionlimit() + 100)
        output = decide_checked(self, signed)
        # Python 3.11-3.13 cannot fingerprint content this deep (MALFORMED_PAYLOAD); 3.14 can, and decides normally.
        if "MALFORMED_PAYLOAD" not in output["reason_codes"]:
            self.assertEqual(output, policy.decide(CASES["AIR-03"]))
        far = clone(CASES["AIR-01"])
        set_field(event(far, "e1"), "payload.headers[name=Date]", "Fri, 31 Dec 9999 23:00:00 -0500")
        output = decide_checked(self, far)
        self.assertIn("INVALID_TIMESTAMP", output["reason_codes"])
        self.assertEqual(output["redaction_requirements"], policy.decide(CASES["AIR-01"])["redaction_requirements"])


if __name__ == "__main__":
    unittest.main()
