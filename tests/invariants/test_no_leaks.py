"""Invariant 3: sensitive or token-shaped values cannot appear in summaries, traces or logs."""
import json
import re
import unittest
from unittest import mock

import policy
from tests.helpers import (CASES, FAKE_KEY, FAKE_PHONE, FREE_TEXT, ID_PATH, PII_FIELDS, add_text, clone,
                           decide_checked, leaked, set_field)


def plant_in_id(item):
    set_field(item, ID_PATH[item["connector"]], FAKE_KEY)


def plant_in_header(item):
    headers = item["payload"].setdefault("headers", {})
    if isinstance(headers, list):
        headers.append({"name": "X-Debug-Token", "value": FAKE_KEY})
    else:
        headers["X-Debug-Token"] = FAKE_KEY


def plant_as_dict_key(item):
    item["payload"][FAKE_KEY] = "debug"


class NoLeaks(unittest.TestCase):
    def decide_with_logs(self, case):
        """Decide a mutated case (checked clean) and return it with every log line the policy wrote."""
        with self.assertLogs("policy", level="DEBUG") as logs:
            output = decide_checked(self, case)
        return output, logs.output

    def test_planted_values_in_text_and_personal_fields_never_leak(self):
        """Invariant 3: a fake key and phone at the start and end of every free-text field, and in every personal-data field, are detected and never leak."""
        canaries = f" token {FAKE_KEY} call {FAKE_PHONE} "
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                mutated = add_text(add_text(case, FREE_TEXT, before=canaries, after=canaries), PII_FIELDS, after=canaries)
                output, logs = self.decide_with_logs(mutated)
                self.assertEqual(leaked(output, logs), [])
                self.assertIn("SECRET_SHAPED_VALUE", output["reason_codes"])
                self.assertIn("PII_REDACTED", output["reason_codes"])

    def test_key_planted_in_id_header_or_dict_key_never_leaks(self):
        """Invariant 3: the fake key planted in an ID field, a header value or a dict key (each alone) is detected and never leaks."""
        for case_id, case in CASES.items():
            for place, plant in (("id", plant_in_id), ("header", plant_in_header), ("dict key", plant_as_dict_key)):
                with self.subTest(case_id=case_id, place=place):
                    mutated = clone(case)
                    plant(mutated["events"][0])
                    output, logs = self.decide_with_logs(mutated)
                    self.assertEqual(leaked(output, logs), [])
                    self.assertIn("SECRET_SHAPED_VALUE", output["reason_codes"])
                    if place == "dict key":  # reported against the section, never under the attacker's key
                        self.assertIn({"ref": "e1:payload", "kind": "api_key"}, output["redaction_requirements"])

    def test_diagnosis_survives_redaction(self):
        """Invariant 3: AIR-05 keeps its diagnosis ("HTTP 401 unauthorised") while the pasted key is masked and absent."""
        case = CASES["AIR-05"]
        output = policy.decide(case)
        self.assertIn("HTTP 401 unauthorised", output["summary"])
        self.assertIn({"ref": "e1:payload.Description", "kind": "api_key"}, output["redaction_requirements"])
        pasted = re.search(r"kpfake_\w+", policy.resolve(case["events"][0], "payload.Description")).group()
        self.assertNotIn(pasted, json.dumps(output))

    def test_output_guard_replaces_a_leaking_record(self):
        """Invariant 3: if the summary ever echoed raw text, the output guard replaces the whole record and keeps the redactions."""
        case = CASES["AIR-05"]
        raw = policy.resolve(case["events"][0], "payload.Description")
        with mock.patch.object(policy, "summarise", return_value=raw):
            output = policy.decide(case)
        self.assertEqual(output["reason_codes"], ["OUTPUT_GUARD_TRIPPED"])
        self.assertEqual(output["disposition"], "QUARANTINE")
        self.assertEqual(output["redaction_requirements"], policy.decide(case)["redaction_requirements"])
        self.assertNotIn(raw, json.dumps(output))

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
