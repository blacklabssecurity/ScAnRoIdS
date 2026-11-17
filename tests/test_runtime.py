"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_runtime.py
Purpose: Verify command/capture planning and actual local process lifecycle behavior.
"""

import json
import os
import sys
import time
import pytest
from config import SCAN_LIBRARY, get_banner
from core.database import connect
from core.runner import packet_capture, run_command
from core.scanner import build_command, capture_filter, validate_flags
from core.system import nmap_to_bpf, target_tokens
from main import arguments, main


def test_menu_ids_match_supplied_specification():
    expected = {
        "01",
        "02",
        "03",
        "04",
        "05",
        "10",
        "11",
        "12",
        "13",
        "14",
        "20",
        "21",
        "22",
        "23",
        "30",
        "31",
        "32",
        "33",
        "34",
        "40",
        "41",
        "42",
        "43",
        "44",
        "45",
        "46",
        "50",
        "51",
        "52",
        "60",
        "61",
        "70",
        "71",
        "72",
        "73",
        "99",
    }
    assert set(SCAN_LIBRARY) == expected
    for key in expected:
        assert key + "." in get_banner()


def test_argv_preserves_quotes_and_expands_input_file(tmp_path):
    hosts = tmp_path / "host list.txt"
    hosts.write_text("192.0.2.10 # note\n192.0.2.11\n")
    cmd = build_command(
        '--script "default and not broadcast" -sT',
        f'-iL "{hosts}"',
        tmp_path / "with space",
        local_ips=["192.0.2.1", "2001:db8::1"],
    )
    assert "default and not broadcast" in cmd
    assert cmd[-2:] == ["192.0.2.10", "192.0.2.11"]
    assert cmd[cmd.index("--exclude") + 1] == "192.0.2.1"
    assert str(tmp_path / "with space") in cmd


@pytest.mark.parametrize(
    "flags",
    [
        "-oA /tmp/escape",
        "-oX/tmp/escape",
        "--exclude 192.0.2.5",
        "--resume last.nmap",
        "-sV 192.0.2.200",
        "--script",
    ],
)
def test_managed_scope_and_outputs_cannot_be_overridden(flags):
    with pytest.raises(ValueError):
        validate_flags(flags)


def test_scope_bpf_supports_cidr_ranges_and_host_files(tmp_path):
    assert "net 192.0.2.0/28" in nmap_to_bpf("192.0.2.0/28")
    assert nmap_to_bpf("192.0.2.10-11") == "(host 192.0.2.10 or host 192.0.2.11)"
    assert "2001:db8::10" in nmap_to_bpf("2001:db8::10")
    path = tmp_path / "scope"
    path.write_text("192.0.2.10\n192.0.2.11")
    assert "host 192.0.2.11" in nmap_to_bpf(f"-iL {path}")
    with pytest.raises(ValueError):
        target_tokens("192.0.2.999")


def test_capture_ports_keep_protocols_separate():
    result = capture_filter(
        SCAN_LIBRARY["44"], ["192.0.2.10"], ["-sS", "-sU", "-p", "T:22,80,U:161,500"]
    )
    assert "tcp port 22" in result and "tcp port 80" in result
    assert "udp port 161" in result and "udp port 500" in result
    assert "icmp" in result
    idle = capture_filter(SCAN_LIBRARY["05"], ["192.0.2.10"], ["-sI", "192.0.2.15:80"])
    assert idle == "host 192.0.2.15"


def test_runner_streams_stdout_and_stderr_and_records_failure(ctx):
    command = [
        sys.executable,
        "-u",
        "-c",
        "import sys;print('live output');print('diagnostic',file=sys.stderr);sys.exit(7)",
    ]
    result = run_command(ctx, command, timeout=5)
    assert result["status"] == "failed" and result["returncode"] == 7
    assert "live output" in result["log"].read_text() and "diagnostic" in result["log"].read_text()
    with connect(ctx.db_path) as conn:
        job = conn.execute("SELECT * FROM jobs").fetchone()
        assert job["status"] == "failed"
        assert "live output" in "".join(r[0] for r in conn.execute("SELECT message FROM events"))


def test_runner_times_out_even_without_output(ctx):
    started = time.monotonic()
    result = run_command(ctx, [sys.executable, "-c", "import time;time.sleep(30)"], timeout=0.3)
    assert result["status"] == "timed_out"
    assert time.monotonic() - started < 5


def test_runner_cancellation_terminates_child_and_records_cancel(ctx, monkeypatch, tmp_path):
    import core.runner as runner

    pidfile = tmp_path / "child.pid"
    original = runner.selectors.DefaultSelector

    class InterruptingSelector:
        def __enter__(self):
            self.actual = original()
            return self

        def __exit__(self, *args):
            self.actual.close()

        def register(self, *args):
            return self.actual.register(*args)

        def get_map(self):
            return self.actual.get_map()

        def select(self, timeout):
            deadline = time.monotonic() + 2
            while not pidfile.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            raise KeyboardInterrupt

    monkeypatch.setattr(runner.selectors, "DefaultSelector", InterruptingSelector)
    with pytest.raises(KeyboardInterrupt):
        run_command(
            ctx,
            [
                sys.executable,
                "-c",
                f"import os,pathlib,time;pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()));time.sleep(30)",
            ],
            timeout=5,
        )
    pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    with connect(ctx.db_path) as conn:
        assert conn.execute("SELECT status FROM jobs").fetchone()[0] == "cancelled"


def test_missing_executable_is_failed_job(ctx):
    result = run_command(ctx, ["/definitely/not/a/tool"], timeout=1)
    assert result["status"] == "failed"
    assert result["returncode"] is None


def test_capture_failure_stops_body(ctx, tmp_path, monkeypatch):
    fake = tmp_path / "tshark"
    fake.write_text('#!/bin/sh\necho "capture permission denied" >&2\nexit 1\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + ":" + os.environ["PATH"])
    ctx.capture = True
    ctx.interface = "fixture0"
    with pytest.raises(RuntimeError, match="permission denied"):
        with packet_capture(ctx, "failure", "host 192.0.2.10"):
            pytest.fail("Tool must not run when capture fails")


def test_dry_run_executes_no_tools(tmp_path, capsys):
    assert (
        main(
            [
                "--customer",
                "Dry_Run",
                "--data-dir",
                str(tmp_path),
                "--scan",
                "40",
                "--targets",
                "192.0.2.0/28",
                "--no-capture",
                "--dry-run",
            ]
        )
        == 0
    )
    assert "nmap -n -vv -sS" in capsys.readouterr().out
    assert not list(tmp_path.rglob("*.pcapng"))


def test_profile_cli_overrides_take_precedence(tmp_path):
    path = tmp_path / "profile.json"
    path.write_text(json.dumps({"scan": "43", "targets": "192.0.2.10", "timeout": 60}))
    args = arguments(["--profile", str(path), "--timeout", "120"])
    assert args.scan == "43" and args.timeout == 120


"""
INPUT: Temporary tool stubs, local Python subprocesses and scan profiles.
OUTPUT: Regression checks for safe command composition, failure and cancellation.
"""


def test_job_log_rotation_is_bounded_and_ordered(tmp_path):
    from core.runner import RotatingJobLog

    path = tmp_path / "job.log"
    with RotatingJobLog(path, limit=8, backups=2) as log:
        log.write(b"0000000011111111222222223333")
        log.flush()
    assert path.read_bytes() == b"3333"
    assert path.with_name("job.log.1").read_bytes() == b"22222222"
    assert path.with_name("job.log.2").read_bytes() == b"11111111"
    assert len(list(tmp_path.iterdir())) == 3
