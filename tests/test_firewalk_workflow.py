"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_firewalk_workflow.py
Purpose: Verify Firewalk prerequisites, protocol/tuning scope and evidence interpretation.
"""

import json
import pytest
from modules import firewalker as fw
import main as app

TARGET = "203.0.113.10"
OUTPUT = "HOP HOST PROTOCOL BLOCKED PORTS\n1 192.0.2.1 tcp 22\n               udp 161\n2 198.51.100.1 tcp 443"


def fixture_xml(*, trace=True, eligible=True, script=None, changed=False):
    hops = (
        '<trace><hop ttl="1" ipaddr="192.0.2.1"/><hop ttl="2" ipaddr="198.51.100.1"/><hop ttl="3" ipaddr="203.0.113.10"/></trace>'
        if trace
        else ""
    )
    if changed:
        hops = hops.replace("192.0.2.1", "192.0.2.99")
    state = "filtered" if eligible else "closed"
    udp = "open|filtered" if eligible else "closed"
    scripts = ""
    if script is not None:
        import xml.sax.saxutils

        scripts = (
            '<hostscript><script id="firewalk" output='
            + xml.sax.saxutils.quoteattr(script)
            + "/></hostscript>"
        )
    return f'''<nmaprun><host><status state="up"/><address addr="{TARGET}" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="22"><state state="{state}" reason="no-response"/></port>
    <port protocol="udp" portid="161"><state state="{udp}" reason="no-response"/></port></ports>{hops}{scripts}</host></nmaprun>'''


def deploy_stub(ctx, monkeypatch, first, second=None):
    calls = []

    def deploy(context, targets, profile, phase, choice):
        calls.append(dict(profile=profile, choice=choice))
        assert targets == [TARGET]
        path = context.dirs["artifacts"] / (choice + ".xml")
        path.write_text(first if len(calls) == 1 else second)
        context.last_scan = dict(xml=path, capture=None)
        return True

    monkeypatch.setattr(fw, "deploy_scan", deploy)
    monkeypatch.setattr(fw, "get_local_ips", lambda: [])
    return calls


@pytest.mark.parametrize(
    "protocol,expected,absent",
    [
        ("tcp", "-sS", "-sU"),
        ("udp", "-sU", "-sS"),
        ("both", "-sU", None),
    ],
)
def test_protocol_configuration_is_explicit(protocol, expected, absent):
    settings = fw.options(protocol, tcp_ports="22,443", udp_ports="53,161")
    flags = fw.scan_flags(TARGET, settings, True)
    assert expected in flags
    if absent:
        assert absent not in flags
    assert "firewalk.max-probed-ports=7" in flags
    assert "--script firewalk" in flags
    assert "--script firewalk" not in fw.scan_flags(TARGET, settings)


@pytest.mark.parametrize(
    "settings",
    [
        dict(parallel=0),
        dict(retries=20),
        dict(probe_ms=1),
        dict(max_ports=0),
        dict(protocol="sctp"),
    ],
)
def test_invalid_tuning_is_rejected(settings):
    with pytest.raises(ValueError):
        fw.options(**settings)


def test_report_parser_preserves_continuation_protocol_rows():
    rows, unparsed = fw.parse_report(OUTPUT)
    assert [(r["hop"], r["host"], r["protocol"], r["ports"]) for r in rows] == [
        (1, "192.0.2.1", "tcp", [22]),
        (1, "192.0.2.1", "udp", [161]),
        (2, "198.51.100.1", "tcp", [443]),
    ]
    assert not unparsed


def test_gateway_focus_and_dedicated_report_are_retained(ctx, monkeypatch):
    calls = deploy_stub(ctx, monkeypatch, fixture_xml(), fixture_xml(script=OUTPUT))
    report = fw.run_firewalk(ctx, TARGET, fw.options("both", gateway="192.0.2.1"))
    assert len(calls) == 2 and report["status"] == "completed"
    assert len(report["rows"]) == 3 and len(report["selected_rows"]) == 2
    assert "Report focus only" in report["gateway_selection"]
    assert (ctx.base_path / report["artifact"]).is_file()
    from core.dashboard import snapshot

    assert snapshot(ctx)["firewalk_reports"][0]["id"] == report["id"]


def test_missing_trace_is_inconclusive_and_stops_probing(ctx, monkeypatch):
    calls = deploy_stub(ctx, monkeypatch, fixture_xml(trace=False))
    report = fw.run_firewalk(ctx, TARGET)
    assert len(calls) == 1 and report["status"] == "inconclusive"
    assert "did not establish" in report["summary"]


def test_directly_connected_target_is_not_a_firewall_conclusion(ctx, monkeypatch):
    xml = fixture_xml().replace(
        '<hop ttl="1" ipaddr="192.0.2.1"/><hop ttl="2" ipaddr="198.51.100.1"/><hop ttl="3" ipaddr="203.0.113.10"/>',
        '<hop ttl="1" ipaddr="203.0.113.10"/>',
    )
    calls = deploy_stub(ctx, monkeypatch, xml)
    report = fw.run_firewalk(ctx, TARGET)
    assert len(calls) == 1 and report["status"] == "inconclusive"
    assert "directly connected" in report["summary"]


def test_no_eligible_filtered_ports_is_reported_without_ttl_scan(ctx, monkeypatch):
    calls = deploy_stub(ctx, monkeypatch, fixture_xml(eligible=False))
    report = fw.run_firewalk(ctx, TARGET)
    assert len(calls) == 1 and report["status"] == "no_eligible_ports"


def test_unobserved_gateway_is_rejected_before_ttl_scan(ctx, monkeypatch):
    calls = deploy_stub(ctx, monkeypatch, fixture_xml())
    report = fw.run_firewalk(ctx, TARGET, fw.options(gateway="192.0.2.99"))
    assert len(calls) == 1 and report["status"] == "error"
    assert "not observed" in report["summary"]


@pytest.mark.parametrize("exception", [app.BackToMenu, app.ExitSession])
def test_navigation_at_gateway_prompt_preserves_preflight_report(ctx, monkeypatch, exception):
    calls = deploy_stub(ctx, monkeypatch, fixture_xml())

    def select(gateways):
        raise exception

    with pytest.raises(exception):
        fw.run_firewalk(ctx, TARGET, gateway_selector=select)
    reports = list(ctx.dirs["artifacts"].glob("firewalk_*.json"))
    assert len(calls) == 1 and len(reports) == 1
    assert json.loads(reports[0].read_text())["status"] == "cancelled"


def test_no_blocking_inferred_is_not_unrestricted_forwarding(ctx, monkeypatch):
    deploy_stub(ctx, monkeypatch, fixture_xml(), fixture_xml(script="None found"))
    report = fw.run_firewalk(ctx, TARGET)
    assert report["status"] == "no_blocking_inferred"
    assert "does not prove unrestricted" in report["summary"]


def test_changed_final_route_is_explicitly_inconclusive(ctx, monkeypatch):
    deploy_stub(ctx, monkeypatch, fixture_xml(), fixture_xml(script=OUTPUT, changed=True))
    report = fw.run_firewalk(ctx, TARGET, fw.options(gateway="192.0.2.1"))
    assert report["status"] == "inconclusive"
    assert any("route changed" in warning for warning in report["warnings"])


def test_no_script_report_does_not_claim_successful_firewalk(ctx, monkeypatch):
    deploy_stub(ctx, monkeypatch, fixture_xml(), fixture_xml())
    assert fw.run_firewalk(ctx, TARGET)["status"] == "inconclusive"


"""
INPUT: Synthetic route/NSE evidence and controlled Nmap stages.
OUTPUT: Regression checks for prerequisites, honest gateway attribution and report persistence.
"""


def test_firewalk_dry_run_prints_complete_commands_without_launching(ctx, monkeypatch, capsys):
    ctx.capture = True
    monkeypatch.setattr(app, "_BATCH", True)
    monkeypatch.setattr(app, "get_local_ips", lambda: ["192.0.2.50"])
    monkeypatch.setattr(
        fw, "run_firewalk", lambda *a, **k: pytest.fail("dry run launched workflow")
    )
    args = app.arguments(
        ["--scan", "61", "--targets", TARGET, "--firewalk-protocol", "both", "--dry-run"]
    )
    assert app.execute_selection(ctx, "61", args)
    output = capsys.readouterr().out
    assert "--exclude 192.0.2.50" in output
    assert "-sS -sU" in output and "PCAP filter:" in output
    assert "icmp[24:4]" in output and "--script firewalk" in output
