"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_dashboard.py
Purpose: Verify authenticated viewing, artifact containment, streaming and topology evidence.
"""

from datetime import datetime, timedelta, timezone
import re
import pytest
from core.dashboard import create_app, topology
from core.database import connect, event, now
from core.parser import import_scan


def login(client, password="test-password"):
    response = client.get("/login")
    csrf = re.search(rb'name="csrf" value="([^"]+)"', response.data)[1].decode()
    return client.post("/login", data={"username": "operator", "password": password, "csrf": csrf})


@pytest.fixture
def app(ctx):
    application = create_app(ctx, "test-password")
    application.config["TESTING"] = True
    return application


def test_anonymous_viewer_cannot_read_session(app):
    client = app.test_client()
    assert client.get("/").status_code == 302
    for path in ("/api/state", "/api/topology", "/api/events", "/files/logs/evidence.log"):
        assert client.get(path).status_code == 401


def test_csrf_and_credentials_are_required(app):
    client = app.test_client()
    assert (
        client.post(
            "/login", data={"username": "operator", "password": "test-password"}
        ).status_code
        == 400
    )
    assert b"Invalid credentials" in login(client, "wrong").data
    assert login(client).status_code == 302
    assert client.get("/api/state").status_code == 200


def test_authenticated_api_shows_host_only_inventory_and_specific_tactical_commands(
    app, ctx, fixture_xml
):
    import_scan(fixture_xml, ctx)
    client = app.test_client()
    login(client)
    data = client.get("/api/state").json
    assert len(data["hosts"]) == 3 and len(data["results"]) == 5
    ssh = next(r for r in data["results"] if r["ip"] == "192.0.2.10" and r["port"] == 22)
    snmp = next(r for r in data["results"] if r["protocol"] == "udp")
    assert "ssh-hostkey" in ssh["suggestion"] and "-p 22" in ssh["suggestion"]
    assert "-sU" in snmp["suggestion"] and "snmp-info" in snmp["suggestion"]
    assert not data["active"]


def test_files_are_authenticated_and_contained(app, ctx, tmp_path):
    path = ctx.dirs["logs"] / "evidence.log"
    path.write_text("evidence")
    outside = tmp_path / "outside.txt"
    outside.write_text("private")
    (ctx.dirs["artifacts"] / "escape.txt").symlink_to(outside)
    client = app.test_client()
    login(client)
    assert client.get("/files/logs/evidence.log").data == b"evidence"
    assert client.get("/files/artifacts/escape.txt").status_code == 404
    assert client.get("/files/artifacts/session.db").status_code == 404
    assert client.get("/files/../session.json").status_code == 404
    assert client.get("/files/.viewer-secret").status_code == 404


def test_dashboard_exposes_no_scan_control_routes(app):
    client = app.test_client()
    login(client)
    for path in ("/api/start", "/api/stop", "/api/scan", "/api/state"):
        assert client.post(path, json={"command": "nmap"}).status_code in (404, 405)


def test_event_stream_replays_by_id(app, ctx):
    event(ctx.db_path, "first event")
    event(ctx.db_path, "second event")
    client = app.test_client()
    login(client)
    response = client.get("/api/events?after=1", buffered=False)
    chunk = next(iter(response.response)).decode()
    assert "second event" in chunk and "first event" not in chunk
    response.close()


def test_topology_requires_traceroute_not_ttl_guesses(ctx, fixture_xml):
    import_scan(fixture_xml, ctx)
    data = topology(ctx)
    assert data["edges"] == [{"source": "192.0.2.1", "target": "192.0.2.10"}]
    assert any(n["id"] == "2001:db8::10" and n["hops"] is None for n in data["nodes"])
    assert not any(e["target"] == "2001:db8::10" for e in data["edges"])


def test_stale_heartbeat_is_not_active(app, ctx):
    old = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    with connect(ctx.db_path) as conn:
        conn.execute(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("old", "nmap", "1", "nmap", "running", now(), None, None, "logs/old.log", old),
        )
    client = app.test_client()
    login(client)
    assert client.get("/api/state").json["active"] is False
    with connect(ctx.db_path) as conn:
        conn.execute("UPDATE jobs SET heartbeat=?", (now(),))
    assert client.get("/api/state").json["active"] is True


def test_artifact_and_service_text_is_not_injected_into_html(app, ctx, tmp_path):
    # API payloads are rendered as textContent in the viewer; templates escape labels.
    (ctx.dirs["artifacts"] / "<img onerror=alert(1)>.txt").write_text("fixture")
    client = app.test_client()
    login(client)
    html = client.get("/").data
    assert b"<img onerror=" not in html
    assert client.get("/api/state").status_code == 200
    assert b"script-src 'self'" in client.get("/").headers["Content-Security-Policy"].encode()


def test_logout_requires_post_and_token(app):
    client = app.test_client()
    login(client)
    assert client.get("/logout").status_code == 405
    assert client.post("/logout", data={}).status_code == 400
    with client.session_transaction() as session:
        token = session["csrf"]
    assert client.post("/logout", data={"csrf": token}).status_code == 302
    assert client.get("/api/state").status_code == 401


"""
INPUT: Flask test clients and synthetic session evidence.
OUTPUT: Viewer authentication, containment and observation-accuracy regression checks.
"""
