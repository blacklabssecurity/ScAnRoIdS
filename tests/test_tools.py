"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_tools.py
Purpose: Test adapter decisions without contacting training targets.
"""

from pathlib import Path
from modules.enum4linux import enum_flags
from modules.snmp_footprints import run_snmp_enum
from core.comparison import compare_sessions
from core.context import ScanContext
from core.database import init_db
from core.parser import import_scan
import json


def test_enum4linux_uses_transport_specific_evidence():
    assert enum_flags(set(), {137}) == ["-n", "-v"]
    assert enum_flags({445}, set()) == ["-S", "-M", "-v"]
    assert enum_flags({135, 139}, set()) == ["-U", "-G", "-P", "-o", "-v"]
    assert enum_flags(set(), set()) == []
    assert enum_flags({445}, set(), True) == ["-A", "-v"]


def test_single_snmp_community_is_written_to_a_file(ctx, monkeypatch):
    commands = []

    def execute(context, command, *args, **kwargs):
        commands.append(command)
        log = context.dirs["logs"] / f"tool_{len(commands)}.log"
        if command[0] == "onesixtyone":
            assert Path(command[2]).is_file()
            assert Path(command[2]).read_text() == "public\n"
            log.write_text("192.0.2.10 [public] Training SNMP agent\n")
        else:
            log.write_text("Synthetic SNMP inventory")
        return {"id": str(len(commands)), "status": "completed", "log": log}

    monkeypatch.setattr("modules.snmp_footprints.execute", execute)
    result = run_snmp_enum(ctx, "192.0.2.10")
    assert result.exists()
    assert commands[1] == ["snmp-check", "192.0.2.10", "-c", "public"]


def test_session_comparison_retains_service_identity(ctx, fixture_xml, tmp_path):
    import_scan(fixture_xml, ctx)
    other = ScanContext("Earlier", root=tmp_path)
    other.db_path = init_db(other)
    path = compare_sessions(ctx, other.base_path)
    report = json.loads(path.read_text())
    assert len(report["added"]) == 4
    assert report["removed"] == []


"""
INPUT: Observed port sets, adapter stubs and temporary sessions.
OUTPUT: Tool selection and version-reference regression checks.
"""
