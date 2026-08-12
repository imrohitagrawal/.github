# Empty on purpose. pytest's default (prepend) import mode adds the
# directory containing any conftest.py to sys.path — this lets
# `tests/test_smoke.py` import `self_test_python_only` (which lives in this
# same directory) without needing `pip install -e .` to have succeeded. See
# the "Deliberately no [build-system] table" comment in pyproject.toml for
# why this fixture doesn't rely on that install succeeding.
