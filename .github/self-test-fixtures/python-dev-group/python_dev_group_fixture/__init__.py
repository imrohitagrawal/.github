"""WP-Consumer self-test fixture package.

Exists only so the reusable workflow's `pip install --group dev -e .` has a
real, buildable package to install editable - not so this module does
anything useful on its own. See ../pyproject.toml for why `freezegun` is the
dev-only dependency this fixture's test asserts is actually installed.
"""
