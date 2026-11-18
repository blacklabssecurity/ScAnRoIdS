"""
Project: ScAnRoIdS Red Team Orchestrator
Module: tests/test_navigation.py
Purpose: Exercise nested back/exit commands without starting scan or capture processes.
"""

from types import SimpleNamespace
import pytest
import main as app
from core.database import connect


def answers(monkeypatch, values):
    iterator = iter(values)
    monkeypatch.setattr(app, "log_question", lambda prompt: next(iterator))
    monkeypatch.setattr(app, "get_default_interface", lambda: "fixture0")


@pytest.mark.parametrize(
    "choice,nested",
    [
        ("42", ["b"]),
        ("72", ["192.0.2.10", "b"]),
        ("99", ["192.0.2.10", "b"]),
        ("05", ["192.0.2.10", "b"]),
        ("05", ["192.0.2.10", "192.0.2.20", "b"]),
        ("i", ["b"]),
    ],
)
def test_back_from_selected_workflow_returns_to_menu_without_scan(
    tmp_path, monkeypatch, choice, nested, capsys
):
    answers(monkeypatch, [choice, *nested, "q"])
    monkeypatch.setattr(
        app, "deploy_scan", lambda *args, **kw: pytest.fail("Back must prevent scan launch")
    )
    result = app.main(
        ["--customer", "Navigation", "--data-dir", str(tmp_path), "--no-dashboard", "--no-capture"]
    )
    assert result == 0
    output = capsys.readouterr().out
    assert "Returned to main menu" in output
    assert "ERROR:" not in output
    assert not app._SESSION_NAVIGATION.get()


def test_q_at_nested_prompt_exits_and_closes_viewer(tmp_path, monkeypatch):
    closed = []
    answers(monkeypatch, ["42", "q"])
    monkeypatch.setattr(
        "core.dashboard.start_dashboard",
        lambda *a, **k: SimpleNamespace(close=lambda: closed.append(True)),
    )
    monkeypatch.setattr(
        app, "deploy_scan", lambda *args, **kw: pytest.fail("Exit must prevent scan launch")
    )
    assert (
        app.main(
            [
                "--customer",
                "Navigation",
                "--data-dir",
                str(tmp_path),
                "--host",
                "127.0.0.1",
                "--no-capture",
            ]
        )
        == 0
    )
    assert closed == [True]
    db = next(tmp_path.glob("*/artifacts/session.db"))
    with connect(db) as conn:
        assert conn.execute("SELECT status FROM session_info").fetchone()[0] == "Controller stopped"
    assert not app._SESSION_NAVIGATION.get()


def test_back_after_completed_scan_preserves_artifacts_and_skips_remaining_steps(
    tmp_path, monkeypatch
):
    answers(monkeypatch, ["42", "192.0.2.10", "b", "q"])
    completed = []

    def scan(ctx, *args, **kwargs):
        proof = ctx.dirs["artifacts"] / "completed.txt"
        proof.write_text("retain completed evidence")
        completed.append(proof)
        return True

    monkeypatch.setattr(app, "deploy_scan", scan)
    monkeypatch.setattr(
        app, "external_tools", lambda *args: pytest.fail("Back must skip remaining offers")
    )
    assert (
        app.main(
            [
                "--customer",
                "Navigation",
                "--data-dir",
                str(tmp_path),
                "--no-dashboard",
                "--no-capture",
            ]
        )
        == 0
    )
    assert len(completed) == 1
    assert completed[0].read_text() == "retain completed evidence"


def test_back_at_main_menu_is_a_noop(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["b", "q"])
    assert (
        app.main(
            [
                "--customer",
                "Navigation",
                "--data-dir",
                str(tmp_path),
                "--no-dashboard",
                "--no-capture",
            ]
        )
        == 0
    )
    assert "Already at the main session menu" in capsys.readouterr().out


def test_back_from_cli_selected_scan_enters_main_menu(tmp_path, monkeypatch, capsys):
    answers(monkeypatch, ["b", "q"])
    assert (
        app.main(
            [
                "--customer",
                "Navigation",
                "--data-dir",
                str(tmp_path),
                "--scan",
                "42",
                "--no-dashboard",
                "--no-capture",
            ]
        )
        == 0
    )
    assert "Returned to main menu" in capsys.readouterr().out


def test_exit_cleanup_closes_viewer_even_if_guide_refresh_fails(tmp_path, monkeypatch):
    answers(monkeypatch, ["42", "q"])
    closed = []
    calls = []
    monkeypatch.setattr(
        "core.dashboard.start_dashboard",
        lambda *a, **k: SimpleNamespace(close=lambda: closed.append(True)),
    )

    def guide(ctx):
        calls.append(True)
        if len(calls) > 1:
            raise OSError("guide refresh failed")

    monkeypatch.setattr(app, "capture_guide", guide)
    assert (
        app.main(
            [
                "--customer",
                "Navigation",
                "--data-dir",
                str(tmp_path),
                "--host",
                "127.0.0.1",
                "--no-capture",
            ]
        )
        == 1
    )
    assert closed == [True]
    assert not app._SESSION_NAVIGATION.get()


"""
INPUT: Scripted instructor input and controlled scan/viewer stubs.
OUTPUT: Regression checks for back navigation, clean exit and retained session evidence.
"""
