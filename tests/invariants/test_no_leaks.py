"""Invariant 3: sensitive or token-shaped values cannot appear in summaries, traces or logs."""
import json
import re
import unittest
from unittest import mock

import policy
from tests.helpers import CASES, FAKE_KEY, FAKE_PHONE, append_to_free_text, clone, decide_checked, leaked, set_field


class NoLeaks(unittest.TestCase):
    def decide_with_logs(self, case):
        """Decide a mutated case (checked clean) and return it with every log line the policy wrote."""
        with self.assertLogs("policy", level="DEBUG") as logs:
            output = decide_checked(self, case)
        return output, logs.output

    def test_planted_values_in_free_text_never_leak(self):
        """Invariant 3: a fake key and phone planted in every free-text field are detected and appear in neither output nor logs."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                output, logs = self.decide_with_logs(append_to_free_text(case, f" token {FAKE_KEY} call {FAKE_PHONE}"))
                self.assertEqual(leaked(output, logs), [])
                self.assertIn("SECRET_SHAPED_VALUE", output["reason_codes"])
                self.assertIn("PII_REDACTED", output["reason_codes"])

    def test_planted_key_in_id_header_and_dict_key_never_leaks(self):
        """Invariant 3: the fake key planted in an ID field, a header value and a dict key is detected and never leaks."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                mutated = clone(case)
                first = mutated["events"][0]
                set_field(first, policy.CONNECTORS[first["connector"]]["id"][0], FAKE_KEY)
                headers = first["payload"].setdefault("headers", {})
                if isinstance(headers, list):
                    headers.append({"name": "X-Debug-Token", "value": FAKE_KEY})
                else:
                    headers["X-Debug-Token"] = FAKE_KEY
                first["payload"][FAKE_KEY] = "debug"
                output, logs = self.decide_with_logs(mutated)
                self.assertEqual(leaked(output, logs), [])
                self.assertIn("SECRET_SHAPED_VALUE", output["reason_codes"])

    def test_diagnosis_survives_redaction(self):
        """Invariant 3: AIR-05 keeps its diagnosis ("HTTP 401 unauthorised") while the pasted key is masked and absent."""
        case = CASES["AIR-05"]
        output = policy.decide(case)
        self.assertIn("HTTP 401 unauthorised", output["summary"])
        self.assertIn({"ref": "e1:payload.Description", "kind": "api_key"}, output["redaction_requirements"])
        pasted = re.search(r"kpfake_\w+", policy.resolve(case["events"][0], "payload.Description")).group()
        self.assertNotIn(pasted, json.dumps(output))

    def test_exception_message_is_never_logged(self):
        """Invariant 3: when the policy crashes on input that echoes a secret, only the exception's type name is logged."""
        with mock.patch.object(policy, "extract", side_effect=ValueError(FAKE_KEY)):
            with self.assertLogs("policy", level="DEBUG") as logs:
                output = policy.decide(CASES["AIR-05"])
        self.assertEqual(output["reason_codes"], ["POLICY_ERROR"])
        self.assertEqual(leaked(output, logs.output), [])
        self.assertIn("ValueError", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
