"""Proves the reusable workflow's `pip install --group dev -e .` path (the
WP-Consumer fix) actually installs a PEP 735 `[dependency-groups]` `dev`
dependency, not just that the workflow's YAML parses.

`freezegun` is declared ONLY in ../pyproject.toml's `[dependency-groups]
dev`, never in `[project.dependencies]`, and confirmed absent from every
transitive dependency of the reusable workflow's own pinned tools (see that
file's comment). If the detection (`tomllib`-based `HAS_DEV_GROUP` check) or
the install itself (`pip install --group dev -e .`) regresses, this import
fails with ModuleNotFoundError and this fixture goes red - the same
"prove it actually fails when broken" standard WP1's self-test already
holds every other scenario to.
"""

import datetime

from freezegun import freeze_time


def test_freezegun_dev_dependency_is_installed() -> None:
    with freeze_time("2026-01-01"):
        now = datetime.datetime.now(tz=datetime.UTC)
        assert now.date() == datetime.date(2026, 1, 1)
