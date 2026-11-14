# Submission summary

**What worked:** Everything runs offline with one command (`python3 run_tests.py`: PASS 38 / FAIL 0 / SKIP 0), all eight cases give the expected decision, the four safety rules still hold when I change the inputs (added injection text, removed IDs and times, shuffled events, planted fake secrets), and the tests catch bad policies that always accept, always quarantine or always crash.

**What failed:** The tests passed the first time, but I didn't trust that, so I had the build reviewed twice by reviewers whose only job was to break it; they found three bugs (an old Jira "Resolved" update could beat a newer reopen, two different updates could be treated as one duplicate, and a bad date could crash the policy) and showed that about half of a set of broken policies still passed my tests, and I fixed all of these and added a test for each.

**What I chose not to build:** real signature checking (I assume the adapter already did it), live connectors, any AI model or outside library, matching events by meaning or keywords, a large set of injection examples, mutation-testing tools, and a scoring report.

**Limits that remain:** The injection and secret checks use patterns, so they only warn and can miss things, such as an injection written with look-alike Cyrillic letters (a test shows it still changes nothing); names inside free text, and personal data in fields I didn't list, are not masked; and events from different sources are linked by time only, so the policy can suggest a link but never prove one.

**With access:** I would check my test cases, and my split between what counts as verified and what is only a claim, against real connector data with personal details removed, then run the real AI agent in place of my policy on these cases and track how often it breaks each safety rule on every release.
