"""WP1 self-test fixture module (monorepo backend half).

Exists only so ruff/pytest/bandit have real, importable content to run
against inside the python-directory this scenario declares.
"""


def multiply(a: int, b: int) -> int:
    return a * b
