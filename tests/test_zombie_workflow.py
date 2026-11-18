"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_zombie_workflow.py
Purpose: Verify explicit hunt scope, selection, durable history and fresh suitability checks.
"""

from pathlib import Path
import pytest
import main as app
from core.database import connect
from core.parser import import_scan
from core.zombies import candidate_rows, hunt_scope, validation_history, record_check
from modules import zombie


def test_hunt_scope_distinguishes_unknown_all_and_manual(ctx, fixture_xml):
    import_scan(fixture_xml, ctx)
    assert hunt_scope(ctx, "unknown") == ["192.0.2.11"]
    assert hunt_scope(ctx, "all") == ["192.0.2.10", "192.0.2.11"]
    assert hunt_scope(ctx, "manual", "192.0.2.0/28") == ["192.0.2.0/28"]
    with pytest.raises(ValueError, match="No live IPv4"):
        with connect(ctx.db_path) as conn:
            conn.execute("UPDATE hosts SET state='down'")
        hunt_scope(ctx, "unknown")


def test_hunter_os_detection_is_optional_and_probe_port_is_explicit():
    assert "-O" not in zombie.hunter_flags(443)
    assert "-O" in zombie.hunter_flags(443, True)
    assert "ipidseq.probeport=443" in zombie.hunter_flags(443)
    with pytest.raises(ValueError):
        zombie.hunter_flags(0)


def test_candidate_observations_are_idempotent_and_timestamped(ctx, fixture_xml):
    import_scan(fixture_xml, ctx)
    import_scan(fixture_xml, ctx)
    rows = candidate_rows(ctx, True)
    assert len(rows) == 1
    assert rows[0]["probe_port"] == 22
    assert rows[0]["checked"] and rows[0]["method"] == "ipidseq"
    assert len(validation_history(ctx)) == 1


def validation_stub(monkeypatch, labels, port_state="closed"):
    monkeypatch.setattr(zombie, "preflight", lambda *a, **k: None)
    iterator = iter(labels)

    def run(ctx, command, **kwargs):
        assert "ipidseq.probeport=80" in command
        label = next(iterator)
        output = Path(command[command.index("-oA") + 1])
        output.with_suffix(
            ".xml"
        ).write_text(f'''<nmaprun args="nmap --script-args ipidseq.probeport=80"><host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="{port_state}"/></port></ports>
        <hostscript><script id="ipidseq" output="{label}"/></hostscript></host></nmaprun>''')
        return dict(status="completed")

    monkeypatch.setattr(zombie, "run_command", run)


def test_closed_probe_port_with_fresh_incremental_replies_is_usable(ctx, monkeypatch):
    validation_stub(monkeypatch, ["Incremental!", "Incremental!"])
    result = zombie.validate_candidate(ctx, "192.0.2.20", 80, 2)
    assert result["status"] == "validated" and len(result["checks"]) == 2
    rows = validation_history(ctx)
    assert len(rows) == 2 and all(r["port_state"] == "closed" for r in rows)
    assert candidate_rows(ctx, True)[0]["status"] == "validated"
    assert not (ctx.dirs["targets"] / "hosts_all.txt").exists()


def test_unstable_second_check_rejects_previously_good_candidate(ctx, monkeypatch):
    validation_stub(monkeypatch, ["Incremental!", "Random Positive Increments"])
    result = zombie.validate_candidate(ctx, "192.0.2.20", 80, 2)
    assert result["status"] == "rejected"
    assert "Non-incremental" in result["reason"]
    assert candidate_rows(ctx, True) == []
    assert len(validation_history(ctx)) == 2


def test_missing_ipid_output_has_specific_reason(ctx, monkeypatch):
    monkeypatch.setattr(zombie, "preflight", lambda *a, **k: None)

    def run(context, command, **kwargs):
        output = Path(command[command.index("-oA") + 1])
        output.with_suffix(".xml").write_text(
            '<nmaprun><host><status state="up"/><address addr="192.0.2.20" addrtype="ipv4"/></host></nmaprun>'
        )
        return dict(status="completed")

    monkeypatch.setattr(zombie, "run_command", run)
    result = zombie.validate_candidate(ctx, "192.0.2.20")
    assert result["status"] == "rejected" and "No ipidseq result" in result["reason"]


def test_candidate_picker_uses_saved_probe_port(ctx, monkeypatch):
    with connect(ctx.db_path) as conn:
        record_check(
            conn,
            ip="192.0.2.20",
            port=443,
            classification="Incremental!",
            status="candidate",
            reason="observation",
            method="ipidseq",
            source="fixture",
        )
    monkeypatch.setattr(app, "ask", lambda prompt: "1")
    assert app.select_zombie(ctx, app.arguments([])) == ("192.0.2.20", 443)


def test_candidate_picker_keeps_manual_entry(ctx, monkeypatch):
    with connect(ctx.db_path) as conn:
        record_check(
            conn,
            ip="192.0.2.20",
            port=80,
            classification="Incremental!",
            status="candidate",
            reason="observation",
            method="ipidseq",
            source="fixture",
        )
    answers = iter(["m", "192.0.2.21:443"])
    monkeypatch.setattr(app, "ask", lambda prompt: next(answers))
    assert app.select_zombie(ctx, app.arguments([])) == ("192.0.2.21", 443)


def test_saved_candidate_is_always_freshly_revalidated(ctx, monkeypatch):
    called = []
    monkeypatch.setattr(zombie, "get_local_ips", lambda: [])
    monkeypatch.setattr(
        zombie,
        "validate_candidate",
        lambda context, ip, port, checks: (
            called.append((ip, port, checks)) or dict(status="validated", reason="fresh check")
        ),
    )
    args = app.arguments(
        ["--zombie", "192.0.2.20:80", "--idle-ports", "22", "--zombie-checks", "2"]
    )
    profile, targets = app.prepare_profile(ctx, "05", args, ["192.0.2.30"])
    assert called == [("192.0.2.20", 80, 2)]
    assert "-sI 192.0.2.20:80" in profile["flags"]


def test_zombie_cannot_be_scanner_or_part_of_target_scope(monkeypatch):
    monkeypatch.setattr(zombie, "get_local_ips", lambda: ["192.0.2.1"])
    with pytest.raises(ValueError, match="scanner itself"):
        zombie.ensure_separate_zombie("192.0.2.1", ["192.0.2.30"])
    with pytest.raises(ValueError, match="inside the target"):
        zombie.ensure_separate_zombie("192.0.2.20", ["192.0.2.0/24"])
    zombie.ensure_separate_zombie("192.0.2.20", ["192.0.2.30"])


"""
INPUT: Synthetic observations, explicit scopes and controlled validation outputs.
OUTPUT: Regression checks for repeatable operator workflows without actual idle scanning.
"""


def test_hunter_capture_retains_host_discovery_and_optional_os_probes():
    from config import SCAN_LIBRARY
    from core.scanner import capture_filter
    import shlex

    bpf = capture_filter(
        SCAN_LIBRARY["60"], ["192.0.2.20"], shlex.split(zombie.hunter_flags(80, True))
    )
    assert "port 80" not in bpf and "host 192.0.2.20" in bpf
