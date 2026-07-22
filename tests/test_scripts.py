from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"


def read_script(name: str) -> str:
    return (SCRIPTS_DIR / name).read_text(encoding="utf-8")


def test_script_files_exist() -> None:
    assert (SCRIPTS_DIR / "run_weekly_report.ps1").exists()
    assert (SCRIPTS_DIR / "collect.ps1").exists()
    assert (SCRIPTS_DIR / "generate_report.ps1").exists()
    assert (SCRIPTS_DIR / "send_report.ps1").exists()
    assert (SCRIPTS_DIR / "README.md").exists()


def test_run_weekly_report_contains_expected_workflow_commands() -> None:
    script = read_script("run_weekly_report.ps1")

    assert '$ErrorActionPreference = "Stop"' in script
    assert ".venv\\Scripts\\python.exe" in script
    assert "app.main" in script
    assert "app.generate_report" in script
    assert "app.send_report" in script
    assert "Workflow completed successfully." in script


def test_single_purpose_scripts_contain_expected_commands() -> None:
    assert "app.main" in read_script("collect.ps1")
    assert "app.generate_report" in read_script("generate_report.ps1")
    assert "app.send_report" in read_script("send_report.ps1")


def test_scripts_do_not_assume_current_working_directory() -> None:
    for script_name in [
        "run_weekly_report.ps1",
        "collect.ps1",
        "generate_report.ps1",
        "send_report.ps1",
    ]:
        script = read_script(script_name)
        assert "$PSScriptRoot" in script
        assert "Set-Location $ProjectRoot" in script


def test_readme_documents_scripts() -> None:
    readme = (SCRIPTS_DIR / "README.md").read_text(encoding="utf-8")

    assert "scripts\\run_weekly_report.ps1" in readme
    assert "scripts\\collect.ps1" in readme
    assert "scripts\\generate_report.ps1" in readme
    assert "scripts\\send_report.ps1" in readme
    assert ".venv" in readme
    assert ".env" in readme
    assert "reports/" in readme
