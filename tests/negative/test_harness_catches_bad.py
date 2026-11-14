"""Deliberate negative tests: the same check() that passes the real policy must catch bad policies and decisions."""
import unittest
from unittest import mock

import policy
from tests.helpers import CASES, EXPECTED, NOTES, OUTPUT_KEYS, check


def stub_decision(case, disposition, codes, action, review):
    """A well-formed decision record, so the harness has to judge its content rather than its shape."""
    return {"case_id": case["case_id"], "disposition": disposition, "reason_codes": codes, "evidence_refs": [],
            "safe_next_action": action, "additional_actions": [], "human_review_required": review,
            "redaction_requirements": [], "notes_on_uncertainty": [NOTES[code] for code in codes],
            "observed_state": None, "summary": f"{disposition}."}


def always_accept(case):
    """A broken policy that accepts everything."""
    return stub_decision(case, "ACCEPT", [], "draft_incident_for_oncall", False)


def always_quarantine(case):
    """A broken policy that looks safe: it quarantines everything as unverified."""
    return stub_decision(case, "QUARANTINE", ["UNVERIFIED_SOURCE"], "quarantine_hold_verify_via_known_channel", True)


def hand_written_air06(observed_state):
    """AIR-06's expected decision written out by hand as a policy output, with a chosen observed_state."""
    decision = {key: EXPECTED["AIR-06"].get(key) for key in OUTPUT_KEYS}
    decision["case_id"] = "AIR-06"
    decision["summary"] = "ACCEPT for 3 event(s) from cloudwatch_sns."
    decision["observed_state"] = observed_state
    return decision


class HarnessCatchesBad(unittest.TestCase):
    def test_always_accept_policy_is_caught(self):
        """Negative: a policy that always returns ACCEPT produces violations on every case."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                self.assertNotEqual(check(case, always_accept(case), EXPECTED[case_id]), [])

    def test_always_quarantine_policy_is_caught(self):
        """Negative: a policy that always returns QUARANTINE produces violations on every case."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                self.assertNotEqual(check(case, always_quarantine(case), EXPECTED[case_id]), [])

    def test_wrong_air06_state_is_caught(self):
        """Negative (invariant 4): AIR-06 shown as recovered ("OK") is caught, even by the state oracle alone."""
        case = CASES["AIR-06"]
        self.assertEqual(check(case, hand_written_air06("ALARM"), EXPECTED["AIR-06"]), [])  # control: correct passes
        wrong = hand_written_air06("OK")
        self.assertNotEqual(check(case, wrong, EXPECTED["AIR-06"]), [])
        self.assertNotEqual(check(case, wrong), [])  # no answer key: the oracle alone catches it

    def test_always_crash_policy_is_caught(self):
        """Negative: a policy that crashes on everything is caught through POLICY_ERROR, and decide() still never raises."""
        with mock.patch.object(policy, "extract", side_effect=RuntimeError("crash")):
            for case_id, case in CASES.items():
                with self.subTest(case_id), self.assertLogs("policy", level="WARNING"):
                    self.assertIn("POLICY_ERROR present", check(case, policy.decide(case)))


if __name__ == "__main__":
    unittest.main()
