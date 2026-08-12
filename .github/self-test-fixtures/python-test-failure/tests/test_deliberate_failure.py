def _one():
    return 1


def test_deliberately_fails():
    # A genuine failing assertion — not "no tests collected" (pytest exit 5,
    # which reusable-pr-quality.yml correctly tolerates as "nothing to run
    # yet") and not an error/exception. This must make `pytest -q` exit 1,
    # the real "a test ran and failed" case the pytest step's own history
    # (see reusable-pr-quality.yml's header comment on the pre-c07ddce
    # `pytest -q || echo "pytest failed"` bug) is supposed to still block on.
    #
    # Round-2 review fix (real Codex + both Claude lens findings,
    # independently confirmed by running the reusable workflow's exact
    # pinned `ruff==0.16.2` against this file): the previous
    # `assert 1 == 2` was a literal constant-vs-constant comparison, which
    # ruff's default PLR0133 ("two constants compared in a comparison")
    # rule flags - `ruff check .` (reusable-pr-quality.yml's step
    # immediately before pytest, no continue-on-error, no `if: always()`)
    # failed on THIS fixture's own assertion and GitHub Actions' implicit
    # `success()` on the pytest step then skipped pytest entirely. The job
    # still correctly showed "failure" overall, but for ruff's reason, not
    # pytest's - so this fixture provided zero actual coverage of the
    # pytest-swallow bug it exists to guard, despite an explicit (false)
    # "verified by actually running every other step" claim in
    # self-test.yml. Computing the left-hand side at runtime via a
    # function call, rather than writing a second literal, keeps the
    # comparison outside PLR0133's purely-syntactic (no value-flow
    # analysis) literal-vs-literal check - confirmed by running the exact
    # pinned `ruff==0.16.2 check .` against this fixture after the change:
    # 0 findings, exit 0 - while pytest still genuinely fails (exit 1, not
    # collected-nothing's exit 5).
    actual = _one()
    expected = 2
    assert actual == expected, "WP1 self-test fixture: deliberate failure"
