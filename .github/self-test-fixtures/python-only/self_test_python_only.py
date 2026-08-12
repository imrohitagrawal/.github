"""WP1 self-test fixture module.

Exists only so the reusable workflow's `pip install -e .`, `ruff check`, and
`pytest` steps have real, importable content to run against — not so this
module does anything useful on its own.
"""


def add(a: int, b: int) -> int:
    return a + b
