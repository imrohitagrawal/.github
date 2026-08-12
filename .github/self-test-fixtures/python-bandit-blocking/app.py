"""C1 self-test fixture module (review finding): a deliberate, real bandit
finding, not present in the empty .bandit-baseline.json alongside this file.
Proves the "bandit (baseline) — blocking" step in reusable-pr-quality.yml
actually fails the gate on a real finding not covered by the baseline, not
just that the baseline-detection logic routes to the right step.

Named without the substring "test" deliberately, matching python-only's
self_check_python_only.py: bandit's own `-x tests,test,node_modules,.venv,
venv` exclude list matches on plain substring containment against the scan
path, not directory-boundary matching (verified locally: a scratch fixture
under a path containing "test" was silently excluded, 0 lines scanned) — a
module or directory named with "test" in it would make this fixture's
bandit coverage fake despite looking like real content.
"""

import subprocess


def run(cmd):
    subprocess.call(cmd, shell=True)
