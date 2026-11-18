"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_capture_lifecycle.py
Purpose: Prevent wrong-interface and quietly empty captures while retaining scan evidence.
"""

from contextlib import contextmanager
import json
import os
import sys
from types import SimpleNamespace
import pytest
from core.capture import capture_plan, route_diagnostics
from core.runner import packet_capture
from core.scanner import deploy_scan


def test_explicit_wrong_nic_rejected_before_capture(ctx, monkeypatch):
    ctx.interface = "eth0"
    ctx.interface_explicit = True
    monkeypatch.setattr(
        "core.capture.route_diagnostics",
        lambda targets: [
            dict(
                target="192.168.159.129", interface="eth1", source="192.168.159.130", status="known"
            )
        ],
    )
    with pytest.raises(ValueError, match="eth1"):
        capture_plan(ctx, ["192.168.159.129"])


def test_explicit_correct_nic_and_any_are_supported(ctx, monkeypatch):
    ctx.interface_explicit = True
    routes = [dict(target="192.168.159.129", interface="eth1", status="known")]
    monkeypatch.setattr("core.capture.route_diagnostics", lambda targets: routes)
    for selected in ("eth1", "any"):
        ctx.interface = selected
        assert capture_plan(ctx, ["192.168.159.129"]) == (selected, routes)


def test_automatic_capture_includes_all_routed_interfaces(ctx, monkeypatch):
    ctx.interface = "eth0"
    ctx.interface_explicit = False
    routes = [
        dict(target="192.168.159.129", interface="eth1", status="known"),
        dict(target="192.0.2.10", interface="tun0", status="known"),
    ]
    monkeypatch.setattr("core.capture.route_diagnostics", lambda targets: routes)
    assert capture_plan(ctx, ["192.168.159.129", "192.0.2.10"]) == ("any", routes)
    assert ctx.interface == "eth0"  # Interface configuration is not mutated.


def test_local_discovery_still_requires_physical_nic(ctx):
    ctx.interface = "eth0"
    assert capture_plan(ctx, ["192.0.2.0/24"], local=True) == ("eth0", [])
    ctx.interface = "any"
    with pytest.raises(ValueError, match="physical"):
        capture_plan(ctx, ["ff02::1"], local=True)


def test_route_diagnostics_is_read_only_and_handles_failures(monkeypatch):
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout='[{"dev":"eth1","prefsrc":"192.168.159.130"}]')

    monkeypatch.setattr("core.capture.subprocess.run", run)
    result = route_diagnostics(["192.168.159.129"])
    assert result[0]["interface"] == "eth1"
    assert commands == [["ip", "-j", "route", "get", "192.168.159.129"]]
    monkeypatch.setattr(
        "core.capture.subprocess.run", lambda *a, **kw: SimpleNamespace(returncode=1, stdout="")
    )
    assert route_diagnostics(["192.0.2.10"])[0]["status"] == "unavailable"


def test_live_process_without_ready_capture_does_not_start_scan(ctx, tmp_path, monkeypatch):
    import core.runner as runner

    fake = tmp_path / "dumpcap"
    fake.write_text("#!" + sys.executable + "\nimport time\ntime.sleep(30)\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + os.environ["PATH"])
    monkeypatch.setattr(runner, "CAPTURE_STARTUP_TIMEOUT", 0.15)
    ctx.capture = True
    ctx.interface = "fixture0"
    with pytest.raises(RuntimeError, match="readiness"):
        with packet_capture(ctx, "not_ready", "host 192.0.2.10"):
            pytest.fail("Must not launch scan before dumpcap is ready")
    assert ctx.capture_result["status"] == "startup_failed"
    assert (ctx.dirs["artifacts"] / "not_ready_capture.json").exists()


def test_empty_capture_is_reported_and_finalized_with_sigint(ctx, tmp_path, monkeypatch, capsys):
    fake = tmp_path / "dumpcap"
    fake.write_text(
        "#!"
        + sys.executable
        + "\n"
        + """
import pathlib,signal,sys,time
args=sys.argv[1:];path=pathlib.Path(args[args.index('-w')+1]);path.write_bytes(b'fixture')
def stop(*args):
    print('Packets captured: 0',file=sys.stderr,flush=True)
    path.with_suffix('.drained').write_text('yes');sys.exit(0)
signal.signal(signal.SIGINT,stop)
print('File: '+str(path),file=sys.stderr,flush=True)
while True:time.sleep(.01)
"""
    )
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + os.environ["PATH"])
    ctx.capture = True
    ctx.interface = "fixture0"
    with packet_capture(
        ctx, "empty", "host 192.0.2.10", metadata={"routes": [{"interface": "fixture0"}]}
    ) as path:
        assert path.exists()
    report = json.loads((ctx.dirs["artifacts"] / "empty_capture.json").read_text())
    assert report["status"] == "empty" and report["packets"] == 0
    assert report["routes"] == [{"interface": "fixture0"}]
    assert path.with_suffix(".drained").read_text() == "yes"
    assert "WARNING" in capsys.readouterr().out


def test_open_nmap_result_is_retained_but_empty_required_capture_is_failure(ctx, monkeypatch):
    import core.scanner as scanner

    ctx.capture = True
    ctx.interface = "any"
    ctx.interface_explicit = True
    monkeypatch.setattr(scanner, "preflight", lambda *args: None)
    monkeypatch.setattr(scanner, "capture_plan", lambda *args, **kw: ("any", []))
    monkeypatch.setattr(scanner, "get_local_ips", lambda: [])

    @contextmanager
    def capture(context, *args, **kwargs):
        context.capture_result = None
        yield None
        context.capture_result = {"status": "empty", "packets": 0}

    monkeypatch.setattr(scanner, "packet_capture", capture)

    def run(context, command, **kwargs):
        from pathlib import Path

        output = Path(command[command.index("-oA") + 1])
        output.with_suffix(".xml").write_text(
            '<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>'
        )
        return {"status": "completed"}

    monkeypatch.setattr(scanner, "run_command", run)
    assert not deploy_scan(
        ctx, ["192.0.2.10"], {"flags": "-Pn -sT -p 22", "capture": "scope"}, 2, "50"
    )
    from modules.tools import services

    assert [r["port"] for r in services(ctx)] == [22]


"""
INPUT: Controlled route/capture processes and scan evidence.
OUTPUT: Regressions for routing alignment, readiness, graceful drain and visible empty captures.
"""
