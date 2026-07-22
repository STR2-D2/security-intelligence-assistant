from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = PROJECT_ROOT / ".github" / "workflows" / "test.yml"


def test_github_actions_workflow_exists() -> None:
    assert WORKFLOW_PATH.exists()


def test_workflow_runs_on_push_and_pull_request() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "push:" in workflow
    assert "pull_request:" in workflow


def test_workflow_uses_expected_python_versions() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert '"3.11"' in workflow
    assert '"3.12"' in workflow
    assert "matrix.python-version" in workflow


def test_workflow_installs_dependencies_and_runs_pytest() -> None:
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "python -m pip install --upgrade pip" in workflow
    assert "pip install -r requirements.txt" in workflow
    assert "python -m pytest" in workflow
    assert "PYTHONPATH: ." in workflow
    assert 'cache: "pip"' in workflow
