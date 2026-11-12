"""Keep subprocess contract checks on the source tree selected by pytest."""

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def subprocess_source_path(monkeypatch):
    source = str(Path(__file__).resolve().parents[1] / "src")
    current = os.environ.get("PYTHONPATH")
    monkeypatch.setenv("PYTHONPATH", source + (os.pathsep + current if current else ""))
