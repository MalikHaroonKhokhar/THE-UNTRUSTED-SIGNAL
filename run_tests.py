"""Run every test under tests/ and print "PASS n / FAIL m / SKIP k".

Each test method counts once, even when several of its subTests fail or skip; a method with any
failure counts as FAIL. An unexpected success counts as a failure. Exits 0 only when nothing
failed and nothing was skipped.
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.abspath(__file__))


class CountingResult(unittest.TextTestResult):
    """A test result that remembers which test methods failed or skipped, once per method."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.failed_ids, self.skipped_ids = set(), set()

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.failed_ids.add(test.id())

    def addError(self, test, err):
        super().addError(test, err)
        self.failed_ids.add(test.id())

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.failed_ids.add(test.id())

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.skipped_ids.add(getattr(test, "test_case", test).id())  # a skipped subTest belongs to its method

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.failed_ids.add(test.id())


def main():
    """Discover and run the whole tests/ tree, then print the one-line count."""
    if sys.version_info < (3, 11):
        sys.exit(f"Python 3.11+ is required (this is {sys.version.split()[0]})")
    sys.path.insert(0, ROOT)
    suite = unittest.defaultTestLoader.discover(os.path.join(ROOT, "tests"), top_level_dir=ROOT)
    result = unittest.TextTestRunner(resultclass=CountingResult, verbosity=2).run(suite)
    failed, skipped = len(result.failed_ids), len(result.skipped_ids - result.failed_ids)
    print(f"PASS {result.testsRun - failed - skipped} / FAIL {failed} / SKIP {skipped}")
    return 0 if failed == 0 and skipped == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
