#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/runner.py
Purpose: Own subprocess groups, stream output, persist job state and finalize captures.
"""

from contextlib import contextmanager
from datetime import datetime
import os
import json
import re
from pathlib import Path
import selectors
import shlex
import signal
import subprocess
import time
from uuid import uuid4
from core.database import connect, event, now, set_status


def stop_process(proc):
    """Terminate the owned process group, including children of an exited leader."""
    if proc is None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
    # A helper may outlive an already-exited leader. It still belongs to this
    # job's process group and must not survive controller cleanup.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def identifier():
    return datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + uuid4().hex[:8]


class RotatingJobLog:
    """Bound individual execution logs to 5 MB plus three retained generations."""

    def __init__(self, path, limit=5 * 1024 * 1024, backups=3):
        self.path, self.limit, self.backups = path, limit, backups
        self.stream = None

    def __enter__(self):
        self.stream = self.path.open("wb")
        return self

    def __exit__(self, *exc):
        self.stream.close()

    def _rotate(self):
        self.stream.close()
        oldest = self.path.with_name(self.path.name + f".{self.backups}")
        oldest.unlink(missing_ok=True)
        for index in range(self.backups - 1, 0, -1):
            previous = self.path.with_name(self.path.name + f".{index}")
            if previous.exists():
                previous.replace(self.path.with_name(self.path.name + f".{index + 1}"))
        self.path.replace(self.path.with_name(self.path.name + ".1"))
        self.stream = self.path.open("wb")

    def write(self, payload):
        while payload:
            remaining = self.limit - self.stream.tell()
            if not remaining:
                self._rotate()
                remaining = self.limit
            self.stream.write(payload[:remaining])
            payload = payload[remaining:]

    def flush(self):
        self.stream.flush()


def run_command(
    ctx, command, phase="tool", tool=None, timeout=None, cwd=None, display_command=None
):
    """Use argv, never a shell. Output drains as bytes so quiet tools still time out."""
    command = [str(v) for v in command]
    tool = tool or Path(command[0]).name
    job_id = identifier()
    log_path = ctx.dirs["logs"] / f"{tool}_{job_id}.log"
    echo = display_command or shlex.join(command)
    print(f"\n[*] {echo}", flush=True)
    event(ctx.db_path, f"[{tool}] {echo}")
    with connect(ctx.db_path) as conn:
        conn.execute(
            "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                job_id,
                tool,
                str(phase),
                echo,
                "running",
                now(),
                None,
                None,
                log_path.relative_to(ctx.base_path).as_posix(),
                now(),
            ),
        )
    set_status(ctx.db_path, f"{tool} running", True, phase, echo)
    proc = None
    status, returncode = "failed", None
    deadline = time.monotonic() + (timeout if timeout is not None else ctx.timeout)
    heartbeat_at = time.monotonic()
    try:
        with RotatingJobLog(log_path) as logfile:
            logfile.write((echo + "\n").encode())
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                cwd=cwd,
            )
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"{tool} exceeded its execution timeout")
                    for key, _ in selector.select(timeout=0.25):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        logfile.write(chunk)
                        logfile.flush()
                        text = chunk.decode("utf-8", errors="replace")
                        print(text, end="", flush=True)
                        event(ctx.db_path, text)
                    if time.monotonic() - heartbeat_at >= 2:
                        with connect(ctx.db_path) as conn:
                            conn.execute(
                                "UPDATE jobs SET heartbeat=? WHERE id=?",
                                (now(), job_id),
                            )
                        heartbeat_at = time.monotonic()
            remaining = max(0.01, deadline - time.monotonic())
            returncode = proc.wait(timeout=remaining)
            status = "completed" if returncode == 0 else "failed"
    except KeyboardInterrupt:
        status = "cancelled"
        event(ctx.db_path, f"{tool} cancelled by operator")
        raise
    except (OSError, TimeoutError, subprocess.TimeoutExpired) as exc:
        status = (
            "timed_out" if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)) else "failed"
        )
        event(ctx.db_path, f"{tool}: {exc}")
        print(f"[!] {exc}", flush=True)
    finally:
        stop_process(proc)
        if proc is not None:
            returncode = proc.returncode
            proc.stdout.close()
        with connect(ctx.db_path) as conn:
            conn.execute(
                "UPDATE jobs SET status=?,finished=?,returncode=?,heartbeat=? WHERE id=?",
                (status, now(), returncode, now(), job_id),
            )
        set_status(ctx.db_path, f"{tool} {status}")
        event(ctx.db_path, f"{tool} {status} (exit {returncode})")
    return dict(id=job_id, status=status, returncode=returncode, log=log_path)


CAPTURE_STARTUP_TIMEOUT = 10.0
CAPTURE_SHUTDOWN_TIMEOUT = 10.0


def capture_packet_count(text):
    matches = re.findall(r"Packets captured:\s*(\d+)", text)
    return int(matches[-1]) if matches else None


@contextmanager
def packet_capture(ctx, stem, capture_filter, *, interface=None, metadata=None):
    """Wait for dumpcap readiness, drain on SIGINT, and retain diagnostic evidence."""
    ctx.capture_result = None
    if not ctx.capture:
        yield None
        return
    interface = interface or ctx.interface
    if not interface:
        raise ValueError("Select a capture interface or use --interface any")
    path = ctx.dirs["pcap"] / (stem + ".pcapng")
    log = ctx.dirs["logs"] / (stem + "_capture.log")
    report_path = ctx.dirs["artifacts"] / (stem + "_capture.json")
    command = ["dumpcap", "-i", interface, "-w", str(path), "-f", capture_filter, "-q"]
    report = dict(
        status="starting",
        interface=interface,
        filter=capture_filter,
        command=shlex.join(command),
        started=now(),
        pcap=path.relative_to(ctx.base_path).as_posix(),
        log=log.relative_to(ctx.base_path).as_posix(),
        packets=None,
        forced_stop=False,
        **(metadata or {}),
    )
    print(f"[*] Capture interface: {interface} | Filter: {capture_filter}", flush=True)
    event(ctx.db_path, "Capture: " + shlex.join(command))
    proc = None
    ready = False
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    with log.open("wb") as output:
        try:
            proc = subprocess.Popen(
                command,
                stdout=output,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=env,
            )
            deadline = time.monotonic() + CAPTURE_STARTUP_TIMEOUT
            while True:
                text = log.read_text(errors="replace")
                if proc.poll() is not None:
                    raise RuntimeError(f"Packet capture failed before readiness: {text}")
                # File: is emitted after capture-file setup. Alive alone, or a
                # fixed two-second delay, does not establish readiness.
                if re.search(r"(?m)^File:\s*", text) and path.exists():
                    ready = True
                    report["status"] = "ready"
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"dumpcap did not confirm capture readiness within {CAPTURE_STARTUP_TIMEOUT}s: {text}"
                    )
                time.sleep(0.05)
            event(ctx.db_path, f"Capture ready on {interface}: {path.name}")
            yield path
        finally:
            if proc is not None:
                if proc.poll() is None:
                    try:
                        proc.send_signal(signal.SIGINT)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=CAPTURE_SHUTDOWN_TIMEOUT)
                    except subprocess.TimeoutExpired:
                        report["forced_stop"] = True
                stop_process(proc)
                report["returncode"] = proc.returncode
            text = log.read_text(errors="replace")
            count = capture_packet_count(text)
            report.update(finished=now(), packets=count)
            report["status"] = (
                "startup_failed"
                if not ready
                else "failed"
                if report["forced_stop"] or proc.returncode not in (0, -signal.SIGINT)
                else "empty"
                if count == 0
                else "captured"
                if count is not None
                else "unverified"
            )
            report_path.write_text(json.dumps(report, indent=2) + "\n")
            ctx.capture_result = report
            if report["status"] != "captured":
                message = f"WARNING: capture {report['status']} on {interface}; packets={count}; filter={capture_filter}. Inspect {log.name} and {report_path.name}. Check the target route and capture interface."
                print("[!] " + message, flush=True)
                event(ctx.db_path, message)
            else:
                event(ctx.db_path, f"Capture finalized: {count} packets on {interface}")


"""
INPUT: Explicit command argv, session context and validated capture filter.
OUTPUT: Process status, durable job logs, live events and finalized capture artifacts.
"""
