"""WP1 self-test fixture module.

Exists only so the reusable workflow's `pip install -e .`, `ruff check`, and
`pytest` steps have real, importable content to run against — not so this
module does anything useful on its own.

Named without the substring "test" deliberately: bandit's own `-x
tests,test,node_modules,.venv,venv` exclude list (reusable-pr-quality.yml's
bandit steps) matches with plain substring containment, not directory-
boundary matching (verified against bandit 1.9.4's source,
bandit/core/manager.py::_is_file_included) — a module literally named
self_test_*.py would be silently excluded from bandit's scan by its own
filename, which would have made this fixture's bandit coverage fake (0
lines scanned) despite looking like real content. Caught during WP1's own
Phase-3 verification fan-out; fixed by renaming rather than left as a
residual, since the fix was free and the alternative (leaving a
self-test-fixture named so it isn't actually scanned by the tool it exists
to test) would have undermined this whole directory's "not fabricated"
claim.
"""


def add(a: int, b: int) -> int:
    return a + b
