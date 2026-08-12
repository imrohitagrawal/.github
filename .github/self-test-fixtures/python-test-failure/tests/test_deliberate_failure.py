def test_deliberately_fails():
    # A genuine failing assertion — not "no tests collected" (pytest exit 5,
    # which reusable-pr-quality.yml correctly tolerates as "nothing to run
    # yet") and not an error/exception. This must make `pytest -q` exit 1,
    # the real "a test ran and failed" case the pytest step's own history
    # (see reusable-pr-quality.yml's header comment on the pre-c07ddce
    # `pytest -q || echo "pytest failed"` bug) is supposed to still block on.
    assert 1 == 2, "WP1 self-test fixture: deliberate failure"
