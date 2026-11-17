"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_data.py
Purpose: Exercise import correctness, state transitions, legacy migration and exports.
"""

from pathlib import Path
import sqlite3
import xml.etree.ElementTree as ET
import pytest
from core.context import ScanContext
from core.database import connect, init_db
from core.parser import import_scan, parse_results, pre_flight_check
from core.planner import audit_plan, audit_flags


def scalar(ctx, sql):
    with connect(ctx.db_path) as conn:
        return conn.execute(sql).fetchone()[0]


def test_import_counts_and_dashboard_population(ctx, fixture_xml):
    assert import_scan(fixture_xml, ctx) == (3, 4)
    assert scalar(ctx, "SELECT COUNT(*) FROM hosts WHERE state='up'") == 3
    assert scalar(ctx, "SELECT COUNT(*) FROM scan_results WHERE state='open'") == 4
    assert (ctx.dirs["targets"] / "hosts_all.txt").read_text().splitlines() == [
        "192.0.2.10",
        "192.0.2.11",
        "2001:db8::10",
    ]
    assert not (ctx.dirs["targets"] / "https_443_tcp" / "hosts_all.txt").exists()
    assert not (ctx.dirs["targets"] / "isakmp_500_udp" / "hosts_all.txt").exists()
    assert "Linux 6.x" == scalar(ctx, "SELECT os FROM hosts WHERE ip='192.0.2.10'")
    assert "Unknown" == scalar(ctx, "SELECT os FROM hosts WHERE ip='192.0.2.11'")
    assert scalar(ctx, "SELECT hops FROM hosts WHERE ip='2001:db8::10'") is None


def test_idempotent_reimports_preserve_history(ctx, fixture_xml):
    import_scan(fixture_xml, ctx)
    import_scan(fixture_xml, ctx)
    assert scalar(ctx, "SELECT COUNT(*) FROM imports") == 1
    assert scalar(ctx, "SELECT COUNT(*) FROM scan_results") == 6
    assert scalar(ctx, "SELECT COUNT(*) FROM hosts") == 3


def test_closed_port_removes_export_and_audit_target(ctx, fixture_xml, tmp_path):
    import_scan(fixture_xml, ctx)
    path = tmp_path / "later.xml"
    path.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="closed"/></port></ports></host></nmaprun>'
    )
    import_scan(path, ctx)
    assert (
        not (ctx.dirs["targets"] / "ssh_22_tcp" / "hosts_all.txt")
        .read_text()
        .startswith("192.0.2.10")
    )
    assert (
        22
        not in next(
            j for j in audit_plan(ctx) if j["ip"] == "192.0.2.10" and j["protocol"] == "tcp"
        )["ports"]
    )
    # Replaying an earlier file must not roll current observations backward.
    import_scan(fixture_xml, ctx)
    assert (
        scalar(
            ctx,
            "SELECT state FROM scan_results WHERE ip='192.0.2.10' AND port=22 AND protocol='tcp'",
        )
        == "closed"
    )
    assert scalar(ctx, "SELECT COUNT(*) FROM imports") == 2


def test_protocols_and_host_only_targets(ctx, fixture_xml):
    import_scan(fixture_xml, ctx)
    plan = audit_plan(ctx)
    assert next(j for j in plan if j["ip"] == "192.0.2.10" and j["protocol"] == "tcp")["ports"] == [
        22,
        80,
    ]
    assert next(j for j in plan if j["protocol"] == "udp")["ports"] == [161]
    assert not any(j["ip"] == "192.0.2.11" for j in plan)
    udp = audit_flags(next(j for j in plan if j["protocol"] == "udp"), "-Pn -sS -sV -p 1-65535")
    assert "-sU" in udp and "-sS" not in udp and udp[-1] == "161"
    ipv6 = audit_flags(next(j for j in plan if ":" in j["ip"]), "-Pn -sV")
    assert "-6" in ipv6


def test_partial_xml_falls_back_to_ipv6_capable_gnmap(ctx, tmp_path):
    xml = tmp_path / "partial.xml"
    xml.write_text("<nmaprun><host>")
    gnmap = Path(__file__).parent / "fixtures" / "discovery.gnmap"
    assert parse_results(xml, gnmap, ctx) == (True, 2, 3)
    assert scalar(ctx, "SELECT COUNT(*) FROM hosts WHERE ip='2001:db8::20'") == 1
    assert scalar(ctx, "SELECT COUNT(*) FROM scan_results WHERE state='open'") == 3


def test_malformed_import_does_not_change_existing_data(ctx, fixture_xml, tmp_path):
    import_scan(fixture_xml, ctx)
    broken = tmp_path / "bad.xml"
    broken.write_text("<nmaprun><host>")
    with pytest.raises(ET.ParseError):
        import_scan(broken, ctx)
    assert scalar(ctx, "SELECT COUNT(*) FROM imports") == 1
    assert scalar(ctx, "SELECT COUNT(*) FROM hosts") == 3


def test_dns_list_scan_is_not_proof_host_is_up(ctx, tmp_path):
    path = tmp_path / "dns.xml"
    path.write_text(
        '<nmaprun><host><address addr="192.0.2.40" addrtype="ipv4"/><hostnames><hostname name="dns.training.test"/></hostnames></host></nmaprun>'
    )
    assert import_scan(path, ctx) == (0, 0)
    assert audit_plan(ctx) == []


def test_dc_requires_all_configured_tcp_ports(ctx, tmp_path):
    from config import DC_PORTS

    def write(ports, name):
        root = ET.Element("nmaprun")
        host = ET.SubElement(root, "host")
        ET.SubElement(host, "status", state="up")
        ET.SubElement(host, "address", addr="192.0.2.50", addrtype="ipv4")
        ps = ET.SubElement(host, "ports")
        for port in ports:
            p = ET.SubElement(ps, "port", protocol="tcp", portid=str(port))
            ET.SubElement(p, "state", state="open")
        path = tmp_path / name
        ET.ElementTree(root).write(path)
        return path

    import_scan(write([88], "one.xml"), ctx)
    assert scalar(ctx, "SELECT MAX(is_dc) FROM scan_results") == 0
    import_scan(write(DC_PORTS, "all.xml"), ctx)
    assert scalar(ctx, "SELECT MIN(is_dc) FROM scan_results") == 1


def test_service_names_cannot_escape_export_directory(ctx, tmp_path):
    path = tmp_path / "service.xml"
    path.write_text(
        '<nmaprun><host><status state="up"/><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/><service name="../../ssl/http"/></port></ports></host></nmaprun>'
    )
    import_scan(path, ctx)
    assert all(
        p.resolve().is_relative_to(ctx.dirs["targets"]) for p in ctx.dirs["targets"].rglob("*")
    )
    assert len(list(ctx.dirs["targets"].glob("*_443_tcp/hosts_all.txt"))) == 1


def test_session_resume_preserves_customer_and_directories(ctx):
    (ctx.dirs["logs"] / "evidence.log").write_text("keep")
    adopted = ScanContext(resume_path=ctx.base_path)
    assert adopted.customer == "Course_Lab"
    assert (adopted.dirs["logs"] / "evidence.log").read_text() == "keep"
    assert adopted.date_str == ctx.date_str


def test_legacy_resume_customer_with_underscores(tmp_path):
    path = tmp_path / "Course_Lab_20260101_1230"
    path.mkdir()
    ctx = ScanContext(resume_path=path)
    assert ctx.customer == "Course_Lab"
    assert ctx.dirs["pcap"].is_dir()


def test_new_sessions_do_not_collide(tmp_path):
    a = ScanContext("Course", root=tmp_path)
    b = ScanContext("Course", root=tmp_path)
    assert a.base_path != b.base_path


def test_legacy_database_migration_keeps_backup_and_deduplicates(ctx):
    # Reconstruct an old database from its original table shape.
    ctx.db_path.unlink()
    with sqlite3.connect(ctx.db_path) as conn:
        conn.execute(
            "CREATE TABLE scan_results (id INTEGER PRIMARY KEY,ip TEXT,os_guess TEXT,port INTEGER,protocol TEXT,service TEXT,reason TEXT,ttl INTEGER,hops INTEGER,service_link TEXT,is_interesting INTEGER,is_dc INTEGER,has_tactical INTEGER,last_seen TEXT)"
        )
        for index in (1, 2):
            conn.execute(
                "INSERT INTO scan_results VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    index,
                    "192.0.2.3",
                    "Unknown",
                    22,
                    "tcp",
                    "ssh",
                    "",
                    0,
                    0,
                    "ssh_22_tcp/hosts_all.txt",
                    0,
                    0,
                    0,
                    "2026-01-01",
                ),
            )
    init_db(ctx)
    assert scalar(ctx, "SELECT COUNT(*) FROM scan_results") == 1
    backup = ctx.dirs["artifacts"] / "session.legacy-backup.sqlite3"
    with sqlite3.connect(backup) as conn:
        assert conn.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0] == 2


def test_rehydrate_all_artifacts(ctx, fixture_xml):
    import shutil

    shutil.copyfile(fixture_xml, ctx.dirs["artifacts"] / "discovery_course_40.xml")
    assert pre_flight_check(ctx) == (3, 4)
    assert pre_flight_check(ctx) == (3, 4)


"""
INPUT: Synthetic scan fixtures and temporary databases.
OUTPUT: Regression checks for persistence and audit-scope correctness.
"""
