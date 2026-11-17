"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/conftest.py
Purpose: Isolate every test in a temporary session with no network scans.
"""

from pathlib import Path
import pytest
from core.context import ScanContext
from core.database import init_db

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def ctx(tmp_path):
    context = ScanContext("Course_Lab", root=tmp_path)
    context.db_path = init_db(context)
    context.capture = False
    return context


@pytest.fixture
def fixture_xml():
    return FIXTURES / "discovery.xml"


"""
INPUT: pytest temporary directories and synthetic evidence.
OUTPUT: Independent non-privileged test contexts.
"""
