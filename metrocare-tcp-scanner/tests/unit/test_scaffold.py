"""
Scaffolding smoke test.

Confirms pytest can discover the test suite and that every src/ submodule
named in docs/sdlc/03-algorithm-design.md is importable before any real
logic is added to it. This should stay green through every later commit --
if it ever breaks, the package layout itself is broken, independent of
whatever module is being worked on.
"""

import importlib

SUBMODULES = [
    "scope",
    "discovery",
    "scheduler",
    "scanner",
    "banners",
    "identify",
    "enumerate",
    "analyze",
    "evidence",
    "report",
]


def test_all_pipeline_submodules_importable():
    for name in SUBMODULES:
        module = importlib.import_module(name)
        assert module is not None
