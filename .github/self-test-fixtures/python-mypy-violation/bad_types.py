"""C1 self-test fixture module (review finding): a deliberate, unambiguous
type error, with mypy.ini alongside it so has_mypy_config is true. No other
plausible failure surface -- no requirements.txt (pip-audit has nothing to
audit), the code has no bandit-flaggable pattern (verified locally: bandit
reports "No issues identified" against this exact file), and ruff reports
"All checks passed!" against it too (verified locally) -- mypy is the only
step that can fail here.

Named without the substring "test" deliberately, matching python-only's
self_check_python_only.py and this package's own python-bandit-blocking
fixture -- see either for why.
"""


def add(a: int, b: int) -> int:
    return a + b


result: str = add(1, 2)
