#!/usr/bin/env python3
"""
Project: ScAnRoIdS Red Team Orchestrator
Module: core/runner.py
Purpose: Own subprocess groups, stream output, persist job state and finalize captures.
"""

from contextlib import contextmanager
from datetime import datetime
import os
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


@contextmanager
def packet_capture(ctx, stem, capture_filter):
    """A failed capture is visible and prevents a silently uncaptured scan."""
    if not ctx.capture:
        yield None
        return
    if not ctx.interface:
        raise ValueError("Select an interface with --interface, or use --no-capture")
    path = ctx.dirs["pcap"] / (stem + ".pcapng")
    log = ctx.dirs["logs"] / (stem + "_capture.log")
    # dumpcap captures packets without loading Tshark's protocol/epan plugins.
    # It performs no name resolution, so Tshark's -n option is unnecessary.
    command = [
        "dumpcap",
        "-i",
        ctx.interface,
        "-w",
        str(path),
        "-f",
        capture_filter,
        "-q",
    ]
    event(ctx.db_path, "Capture: " + shlex.join(command))
    proc = None
    with log.open("wb") as output:
        try:
            proc = subprocess.Popen(
                command,
                stdout=output,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
            )
            # No network probes are launched until capture startup has been checked.
            time.sleep(2)
            if proc.poll() is not None:
                raise RuntimeError(f"Packet capture failed: {log.read_text(errors='replace')}")
            yield path
        finally:
            stop_process(proc)
            if proc is not None and proc.returncode not in (0, -signal.SIGTERM):
                event(ctx.db_path, f"Capture exited {proc.returncode}; inspect {log.name}")


"""
INPUT: Explicit command argv, session context and validated capture filter.
OUTPUT: Process status, durable job logs, live events and finalized capture artifacts.
"""
