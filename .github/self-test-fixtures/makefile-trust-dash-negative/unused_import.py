"""Round-4 self-test fixture: a real, deliberate ruff violation.

This file exists only to give `ruff check .` something to fail on, so that
whether the reusable workflow SKIPS its native ruff step is observable from
outside. See this fixture directory's requirements.txt for the full story.

The import below is deliberately unused and deliberately NOT suppressed -
ruff's default rule set flags it as F401. (Do not write the suppression
directive's name anywhere in this file, even inside prose: ruff matches that
token in a trailing comment and would silence the very finding this fixture
depends on - found the hard way while writing it.)
"""

import os
