"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_zombie_classification.py
Purpose: Match actual Nmap IPID outputs without accepting other sequence classes.
"""

import pytest
from core.parser import incremental_ipid, import_scan
from modules.zombie import validate_zombie


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Incremental!", True),
        ("Incremental", True),
        (" incremental! [used port 80] ", True),
        ("Broken incremental!", False),
        ("Random Positive Increments", False),
        ("Not incremental", False),
        ("Unknown", False),
    ],
)
def test_real_nmap_sequence_labels(value, expected):
    assert incremental_ipid(value) is expected


def test_hunter_exports_actual_nse_incremental_result(ctx, fixture_xml):
    import_scan(fixture_xml, ctx)
    candidates = (ctx.dirs["targets"] / "zombie_candidates.txt").read_text()
    assert "192.0.2.10 | incremental" in candidates


def test_idle_validation_accepts_actual_nse_label_without_expanding_targets(ctx, monkeypatch):
    import modules.zombie as zombie

    def run(context, command, **kwargs):
        output = command[command.index("-oA") + 1]
        from pathlib import Path

        Path(output).with_suffix(
            ".xml"
        ).write_text("""<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/></port></ports>
        <hostscript><script id="ipidseq" output="Incremental!"/></hostscript></host></nmaprun>""")
        return dict(status="completed")

    monkeypatch.setattr(zombie, "preflight", lambda *args, **kwargs: None)
    monkeypatch.setattr(zombie, "run_command", run)
    monkeypatch.setattr(zombie, "preflight", lambda *a, **kw: None)
    assert validate_zombie(ctx, "192.0.2.10", 80)
    assert not (ctx.dirs["targets"] / "hosts_all.txt").exists()


"""
INPUT: Actual NSE label formats and a controlled candidate-validation output.
OUTPUT: Regression checks for candidate detection and pre-idle suitability parsing.
"""
