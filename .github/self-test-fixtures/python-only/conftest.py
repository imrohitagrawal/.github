# Empty on purpose. pytest's default (prepend) import mode adds the
# directory containing any conftest.py to sys.path — this lets
# `tests/test_smoke.py` import `self_check_python_only` (which lives in this
# same directory) without needing `pip install -e .` to have succeeded. See
# requirements.txt's header comment for why this fixture avoids
# pyproject.toml and doesn't rely on an editable install succeeding.
