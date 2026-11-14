"""The eight fixture cases (AIR-01 to AIR-08) against fixtures/expected.jsonl.

Where the rest of the tests live:
  tests/invariants/  the brief's four safety invariants, one file each:
                     test_authority.py, test_no_fabrication.py, test_no_leaks.py, test_no_silent_resolve.py
  tests/variants/    AIR-08 repaired, then broken one defect at a time
  tests/negative/    proof that the harness catches bad policies and bad decisions
  tests/contract/    fixture coverage, output shape and byte-for-byte determinism
Shared code (the check() harness, state oracle, mutation helpers, canaries) is in tests/helpers.py.
"""
import unittest

import policy
from tests.helpers import CASES, EXPECTED, check


class FixtureCases(unittest.TestCase):
    def test_each_case_matches_expected(self):
        """All eight cases give their expected decision and pass every check() rule (shape, refs, evidence kinds, summary, state oracle)."""
        for case_id, case in CASES.items():
            with self.subTest(case_id):
                self.assertEqual(check(case, policy.decide(case), EXPECTED[case_id]), [])


if __name__ == "__main__":
    unittest.main()
