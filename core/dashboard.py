#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/dashboard.py
Purpose: Authenticated LAN viewing API, live events and contained artifact downloads.
"""

from datetime import datetime, timezone
from functools import wraps
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import secrets
import shlex
import threading
import time
from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    stream_with_context,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from core.database import connect, init_db
from config import TACTICAL_SUGGESTIONS, UDP_SUGGESTIONS


def artifact_path(ctx, relative):
    path = (ctx.base_path / relative).resolve()
    if not path.is_relative_to(ctx.base_path.resolve()):
        return None
    parts = path.relative_to(ctx.base_path.resolve()).parts
    if not parts or parts[0] not in ("artifacts", "targets", "pcap", "logs"):
        return None
    if (
        path.name.startswith(".")
        or path.suffix in (".db", ".sqlite3")
        or path.name.startswith("session.db")
    ):
        return None
    return path if path.is_file() else None


def _suggestion(row):
    if row["state"] != "open":
        # An unanswered probe is not proof of an open service. Offer verification
        # only; do not suggest service/version scripts against uncertain results.
        return shlex.join(
            [
                "nmap",
                "-Pn",
                "-n",
                "-sU"
                if row["protocol"] == "udp"
                else "-sY"
                if row["protocol"] == "sctp"
                else "-sT",
                *(["-6"] if ":" in row["ip"] else []),
                "-p",
                str(row["port"]),
                "--reason",
                row["ip"],
            ]
        )
    flags = (
        UDP_SUGGESTIONS
        if row["protocol"] == "udp"
        else TACTICAL_SUGGESTIONS
        if row["protocol"] == "tcp"
        else {}
    ).get(row["port"])
    if not flags:
        return ""
    return shlex.join(
        [
            "nmap",
            "-Pn",
            "-n",
            "-vv",
            "-sU" if row["protocol"] == "udp" else "-sT",
            *(["-6"] if ":" in row["ip"] else []),
            "-sV",
            "-p",
            str(row["port"]),
            *shlex.split(flags),
            row["ip"],
        ]
    )


def topology(ctx):
    """Only Nmap traceroute provides edges. Discovered hosts are separately identified."""
    with connect(ctx.db_path) as conn:
        observations = [
            json.loads(r[0]) for r in conn.execute("SELECT records FROM imports ORDER BY imported")
        ]
        hosts = [dict(r) for r in conn.execute("SELECT ip,os,hops FROM hosts")]
    nodes = {h["ip"]: dict(id=h["ip"], kind="target", os=h["os"], hops=h["hops"]) for h in hosts}
    edges = set()
    for records in observations:
        for host in records:
            previous, previous_ttl = None, None
            for hop in sorted(host.get("trace", []), key=lambda h: int(h.get("ttl", 0))):
                address = hop.get("ipaddr")
                ttl = int(hop.get("ttl", 0))
                if not address:
                    previous, previous_ttl = None, None
                    continue
                nodes.setdefault(address, dict(id=address, kind="hop", os="Unknown", hops=ttl))
                if previous and previous_ttl + 1 == ttl:
                    edges.add((previous, address))
                previous, previous_ttl = address, ttl
    return dict(
        nodes=list(nodes.values()),
        edges=[dict(source=a, target=b) for a, b in sorted(edges)],
    )


def snapshot(ctx):
    with connect(ctx.db_path) as conn:
        meta = dict(conn.execute("SELECT * FROM session_info WHERE id=1").fetchone())
        hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts ORDER BY ip")]
        results = [
            dict(r)
            for r in conn.execute("""SELECT s.* FROM scan_results s JOIN hosts h
                ON h.ip=s.ip WHERE s.state IN ('open','open|filtered','filtered','unfiltered') AND h.state='up' ORDER BY s.ip,s.port,s.protocol""")
        ]
        jobs = [dict(r) for r in conn.execute("SELECT * FROM jobs ORDER BY started DESC LIMIT 500")]
        imports = [
            dict(r)
            for r in conn.execute(
                "SELECT digest,source,imported FROM imports ORDER BY imported DESC"
            )
        ]
    for row in results:
        row["suggestion"] = _suggestion(row)
    active = False
    for job in jobs:
        if job["status"] == "running" and job["heartbeat"]:
            age = (
                datetime.now(timezone.utc) - datetime.fromisoformat(job["heartbeat"])
            ).total_seconds()
            active |= age < 15
    artifacts = []
    for directory in ctx.dirs.values():
        for path in directory.rglob("*"):
            relative = path.relative_to(ctx.base_path).as_posix()
            safe = artifact_path(ctx, relative)
            if safe:
                artifacts.append(dict(path=relative, size=safe.stat().st_size))
            if len(artifacts) >= 5000:
                break
    from modules.analysis import analysis_status
    from core.zombies import candidate_rows, validation_history

    with connect(ctx.db_path) as conn:
        reports = []
        for row in conn.execute(
            "SELECT data FROM specialized_reports WHERE kind='firewalk' ORDER BY created DESC,id DESC LIMIT 20"
        ):
            try:
                reports.append(json.loads(row["data"]))
            except ValueError:
                continue

    return dict(
        zombie_candidates=candidate_rows(ctx),
        zombie_history=validation_history(ctx),
        firewalk_reports=reports,
        analysis=analysis_status(),
        confirmed_open=sum(row["state"] == "open" for row in results),
        uncertain=sum(row["state"] != "open" for row in results),
        meta=meta,
        hosts=hosts,
        results=results,
        jobs=jobs,
        imports=imports,
        active=active,
        artifacts=sorted(artifacts, key=lambda f: f["path"]),
    )


def create_app(ctx, password=None, secure_cookie=False):
    ctx.db_path = init_db(ctx)
    app = Flask(__name__, template_folder="../web/templates", static_folder="../web/static")
    key_path = ctx.base_path / ".viewer-secret"
    if not key_path.exists():
        fd = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secrets.token_hex(32))
    app.secret_key = key_path.read_text().strip()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=secure_cookie,
        MAX_CONTENT_LENGTH=16384,
        PERMANENT_SESSION_LIFETIME=28800,
    )
    app.config["PASSWORD_HASH"] = generate_password_hash(
        password or f"{ctx.customer}_{datetime.now().year}"
    )
    attempts = {}
    attempts_lock = threading.Lock()

    def protected(function):
        @wraps(function)
        def wrapped(*args, **kwargs):
            if not session.get("viewer"):
                if request.path.startswith("/api/") or request.path.startswith("/files/"):
                    abort(401)
                return redirect(url_for("login"))
            return function(*args, **kwargs)

        return wrapped

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        session.setdefault("csrf", secrets.token_hex(24))
        if request.method == "POST":
            if not secrets.compare_digest(
                request.form.get("csrf", "").encode(), session["csrf"].encode()
            ):
                abort(400)
            address = request.remote_addr or "unknown"
            with attempts_lock:
                cutoff = time.monotonic() - 60
                for key in list(attempts):
                    attempts[key] = [t for t in attempts[key] if t > cutoff]
                    if not attempts[key]:
                        del attempts[key]
                history = attempts.get(address, [])
                if len(history) >= 10:
                    abort(429)
                attempts.setdefault(address, []).append(time.monotonic())
            valid = check_password_hash(
                app.config["PASSWORD_HASH"], request.form.get("password", "")
            )
            if request.form.get("username") == "operator" and valid:
                session.clear()
                session.update(viewer=True, csrf=secrets.token_hex(24))
                session.permanent = True
                with attempts_lock:
                    attempts.pop(address, None)
                return redirect(url_for("index"))
            error = "Invalid credentials"
        return render_template("login.html", error=error, csrf=session["csrf"])

    @app.post("/logout")
    @protected
    def logout():
        if not secrets.compare_digest(
            request.form.get("csrf", "").encode(), session.get("csrf", "").encode()
        ):
            abort(400)
        session.clear()
        return redirect(url_for("login"))

    @app.get("/")
    @protected
    def index():
        return render_template(
            "dashboard.html",
            customer=ctx.customer,
            csrf=session["csrf"],
            session_name=ctx.session_name,
        )

    @app.get("/api/state")
    @protected
    def state():
        return jsonify(snapshot(ctx))

    @app.get("/api/topology")
    @protected
    def topology_data():
        return jsonify(topology(ctx))

    @app.get("/api/events")
    @protected
    def events():
        try:
            cursor = max(
                0,
                int(request.headers.get("Last-Event-ID") or request.args.get("after", "0")),
            )
        except ValueError:
            abort(400)

        @stream_with_context
        def stream():
            nonlocal cursor
            end = time.monotonic() + 20
            while time.monotonic() < end:
                with connect(ctx.db_path) as conn:
                    rows = conn.execute(
                        "SELECT * FROM events WHERE id>? ORDER BY id LIMIT 100",
                        (cursor,),
                    ).fetchall()
                for row in rows:
                    cursor = row["id"]
                    yield f"id: {cursor}\ndata: {json.dumps(dict(row))}\n\n"
                if not rows:
                    yield ": heartbeat\n\n"
                    time.sleep(1)

        return Response(stream(), mimetype="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/gallery")
    @protected
    def gallery():
        screenshots = [
            f
            for f in snapshot(ctx)["artifacts"]
            if Path(f["path"]).suffix.lower() in (".png", ".jpg", ".jpeg", ".webp")
        ]
        return render_template("gallery.html", screenshots=screenshots, customer=ctx.customer)

    @app.get("/images/<path:relative>")
    @protected
    def images(relative):
        path = artifact_path(ctx, relative)
        if path is None or path.suffix.lower() not in (
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
        ):
            abort(404)
        return send_file(path)

    @app.get("/files/<path:relative>")
    @protected
    def files(relative):
        path = artifact_path(ctx, relative)
        if path is None:
            abort(404)
        return send_file(path, as_attachment=True, download_name=path.name)

    return app


def start_dashboard(ctx, host="0.0.0.0", port=8888, password=None, threads=32):
    """Waitress serves multiple LAN viewers; terminal owns the server lifetime."""
    from waitress import create_server

    app = create_app(ctx, password)
    handler = RotatingFileHandler(
        ctx.dirs["logs"] / "dashboard.log", maxBytes=5 * 1024 * 1024, backupCount=3
    )
    app.logger.addHandler(handler)
    logging.getLogger("waitress").addHandler(handler)
    server = create_server(app, host=host, port=port, threads=threads)
    thread = threading.Thread(target=server.run, name="dashboard", daemon=True)
    thread.start()
    return server


"""
INPUT: Session context, viewer credentials and persisted scan/event records.
OUTPUT: Viewing-only HTTP interface; no routes can launch, stop or modify scan jobs.
"""
