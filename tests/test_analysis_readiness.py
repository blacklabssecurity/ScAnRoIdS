"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_analysis_readiness.py
Purpose: Distinguish plugin failures, capture permissions and empty-capture guidance.
"""

from types import SimpleNamespace
from modules import analysis


def test_zero_exit_plugin_error_is_still_unhealthy(monkeypatch):
    analysis._tshark_probe.cache_clear()
    monkeypatch.setattr(analysis.shutil, "which", lambda name: "/fixture/" + name)
    monkeypatch.setattr(
        analysis.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0,
            stdout="TShark 4.6",
            stderr="Couldn't load plugin 'falco-events.so': undefined symbol: grpc_error",
        ),
    )
    state = analysis.analysis_status()
    assert state["tshark"] == "plugin_error"
    analysis._tshark_probe.cache_clear()


def test_healthy_startup_enables_analysis(monkeypatch):
    analysis._tshark_probe.cache_clear()
    monkeypatch.setattr(analysis.shutil, "which", lambda name: "/fixture/" + name)
    monkeypatch.setattr(
        analysis.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="TShark 4.6", stderr=""),
    )
    assert analysis.analysis_status()["tshark"] == "ready"
    analysis._tshark_probe.cache_clear()


def test_guide_withholds_broken_tshark_and_uses_downloaded_filename(ctx, monkeypatch):
    monkeypatch.setattr(
        analysis,
        "analysis_status",
        lambda: dict(
            tshark="plugin_error", detail="Plugin/library mismatch", tcpdump=True, capinfos=True
        ),
    )
    (ctx.dirs["pcap"] / "training.pcapng").write_bytes(b"fixture")
    text = analysis.capture_guide(ctx).read_text()
    assert "tshark -r" not in text
    assert "capinfos training.pcapng" in text
    assert "tcpdump -nn -r training.pcapng -c 200" in text
    assert "zero packets" in text
    assert "root-owned" in text


def test_offline_analysis_skips_unhealthy_tshark(ctx, tmp_path, monkeypatch):
    source = tmp_path / "training.pcapng"
    source.write_bytes(b"fixture")
    monkeypatch.setattr(
        analysis,
        "analysis_status",
        lambda: dict(
            tshark="plugin_error", detail="Plugin/library mismatch", tcpdump=True, capinfos=True
        ),
    )
    commands = []

    def execute(context, command, **kwargs):
        commands.append(command)
        return None

    monkeypatch.setattr(analysis, "execute", execute)
    analysis.analyze_capture(ctx, source)
    assert [c[0] for c in commands] == ["capinfos", "tcpdump"]


"""
INPUT: Controlled tool startup responses and temporary PCAP artifacts.
OUTPUT: Regression checks for diagnostic-driven recipes and non-Tshark alternatives.
"""
