"""WP1 self-test fixture module (monorepo backend half).

Exists only so ruff/pytest/bandit have real, importable content to run
against inside the python-directory this scenario declares.

Named without the substring "test" deliberately — see the matching note in
.github/self-test-fixtures/python-only/self_check_python_only.py for why
(bandit's exclude list is substring-matched, not directory-boundary
matched, so a self_test_*.py module name would silently exclude itself
from being scanned).
"""


def multiply(a: int, b: int) -> int:
    return a * b
