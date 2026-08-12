"""C1/H7 self-test fixture (review finding): a deliberately failing
assertion. If the native pytest step ever runs against this fixture, the
job MUST fail. This fixture's whole point is that it should NOT run here -
the root Makefile's `test:` target names this exact directory (see
Makefile), so compute_makefile_trust should evaluate trust=true for this
directory and skip the native pytest step entirely, in favor of `make test`
(a trivial `cd <this dir> && true`, which always succeeds).

This is the previously-unexercised half of H7: prior self-test coverage
only proved the trust=false (untrusted) path works (H2's reproduction, and
every existing fixture, whose directory strings never appear in the root
Makefile's - previously all-trivial - recipes). This fixture is the first
one whose directory the root Makefile's test: target actually names, so
it's the first real exercise of trust=true actually suppressing the native
step, not just of the underlying compute_makefile_trust logic being
correct in isolation (verified separately, by hand, when H2/H7 first
shipped).

If a future edit to compute_makefile_trust's directory-matching logic
regresses (e.g. reintroduces H12's regex escaping bug, or breaks the
skip-condition wiring), this fixture goes red - a real regression signal
this file's own commit history didn't have before.
"""


def test_would_fail_if_ever_run():
    assert False, "native pytest ran against makefile-trust-positive - the trust=true skip path did not fire"
