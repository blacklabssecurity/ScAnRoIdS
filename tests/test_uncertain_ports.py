"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_uncertain_ports.py
Purpose: Preserve uncertain Nmap evidence without promoting it into open-service workflows.
"""

from core.database import connect
from core.dashboard import snapshot
from core.parser import import_scan
from core.planner import audit_plan
from modules.tools import services


def test_uncertain_ports_visible_but_never_automatic_service_targets(ctx, tmp_path):
    source = tmp_path / "uncertain.xml"
    source.write_text("""<nmaprun><host><status state="up"/><address addr="192.0.2.30" addrtype="ipv4"/><ports>
    <port protocol="tcp" portid="22"><state state="open|filtered" reason="no-response"/><service name="ssh"/></port>
    <port protocol="tcp" portid="443"><state state="filtered" reason="no-response"/><service name="https"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http"/></port>
    <port protocol="tcp" portid="25"><state state="closed" reason="reset"/></port>
    </ports></host></nmaprun>""")
    assert import_scan(source, ctx) == (1, 1)
    state = snapshot(ctx)
    assert state["confirmed_open"] == 1 and state["uncertain"] == 2
    assert {r["state"] for r in state["results"]} == {"open", "open|filtered", "filtered"}
    ssh = next(r for r in state["results"] if r["port"] == 22)
    assert ssh["reason"] == "no-response"
    assert "--script" not in ssh["suggestion"] and "-sV" not in ssh["suggestion"]
    assert audit_plan(ctx)[0]["ports"] == [80]
    assert [r["port"] for r in services(ctx)] == [80]
    assert not (ctx.dirs["targets"] / "ssh_22_tcp" / "hosts_all.txt").exists()


def test_explicit_extraports_addresses_are_preserved(ctx, tmp_path):
    source = tmp_path / "summary.xml"
    source.write_text("""<nmaprun><host><status state="up"/><address addr="192.0.2.31" addrtype="ipv4"/><ports>
    <extraports state="open|filtered" count="2"><extrareasons reason="no-responses" count="2" proto="tcp" ports="22,443"/></extraports>
    </ports></host></nmaprun>""")
    assert import_scan(source, ctx) == (1, 0)
    assert {r["port"] for r in snapshot(ctx)["results"]} == {22, 443}
    assert audit_plan(ctx) == []


def test_unique_summary_complement_is_recoverable(ctx, tmp_path):
    source = tmp_path / "complement.xml"
    source.write_text("""<nmaprun><scaninfo protocol="tcp" services="22,80,443"/>
    <host><status state="up"/><address addr="192.0.2.32" addrtype="ipv4"/><ports>
    <extraports state="filtered" count="2"><extrareasons reason="no-responses" count="2"/></extraports>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port>
    </ports></host></nmaprun>""")
    assert import_scan(source, ctx) == (1, 1)
    state = snapshot(ctx)
    assert state["uncertain"] == 2
    assert {r["port"] for r in state["results"] if r["state"] == "filtered"} == {22, 443}


def test_ambiguous_aggregate_count_never_invents_port_ids(ctx, tmp_path):
    source = tmp_path / "ambiguous.xml"
    source.write_text("""<nmaprun><host><status state="up"/><address addr="192.0.2.33" addrtype="ipv4"/><ports>
    <extraports state="open|filtered" count="2"><extrareasons reason="no-responses" count="2"/></extraports>
    </ports></host></nmaprun>""")
    import_scan(source, ctx)
    assert snapshot(ctx)["results"] == []


def test_legacy_import_enrichment_does_not_overwrite_newer_state(ctx, tmp_path):
    source = tmp_path / "old.xml"
    source.write_text("""<nmaprun><host><status state="up"/><address addr="192.0.2.34" addrtype="ipv4"/><ports>
    <extraports state="open|filtered" count="2"><extrareasons reason="no-responses" proto="tcp" ports="22,443" count="2"/></extraports>
    </ports></host></nmaprun>""")
    import_scan(source, ctx)
    # Simulate the old importer missing the grouped result for port 443.
    with connect(ctx.db_path) as conn:
        conn.execute("DELETE FROM scan_results WHERE port=443")
        conn.execute("UPDATE scan_results SET state='closed',source='newer' WHERE port=22")
        conn.execute("UPDATE imports SET parser_version=1")
    import_scan(source, ctx)
    with connect(ctx.db_path) as conn:
        assert (
            conn.execute("SELECT state FROM scan_results WHERE port=22").fetchone()[0] == "closed"
        )
        assert (
            conn.execute("SELECT state FROM scan_results WHERE port=443").fetchone()[0]
            == "open|filtered"
        )
        assert conn.execute("SELECT COUNT(*) FROM imports").fetchone()[0] == 1


"""
INPUT: Synthetic inverse/SYN scan evidence and existing observation history.
OUTPUT: Regression checks for visible uncertainty, truthful counts and constrained handoffs.
"""
