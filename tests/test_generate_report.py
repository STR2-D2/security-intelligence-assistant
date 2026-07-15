from datetime import UTC, datetime
from pathlib import Path

from app import generate_report as cli
from database.models import Vulnerability
from watchlist.models import WatchKeyword


def vulnerability(title: str = "Azure", cve_id: str | None = "CVE-2099-0001") -> Vulnerability:
    return Vulnerability(
        id=1,
        source="test",
        source_url=None,
        cve_id=cve_id,
        title=title,
        description="Description",
        vendor=None,
        product=None,
        severity=None,
        cvss_score=None,
        published_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=None,
        has_poc=False,
        in_kev=False,
        ai_summary=None,
        status="new",
    )


def patch_watchlists(monkeypatch) -> None:
    monkeypatch.setattr(
        cli,
        "load_watchlists",
        lambda: [WatchKeyword("Azure", "cloud", ("Azure",), ("cloud",), 100)],
    )


def test_output_file_creation(tmp_path, monkeypatch) -> None:
    patch_watchlists(monkeypatch)
    output = tmp_path / "report.md"

    path = cli.generate_report([vulnerability()], output=output)

    assert path == output
    assert output.exists()
    assert "# 每周安全漏洞预警报告" in output.read_text(encoding="utf-8")


def test_custom_output_path(tmp_path, monkeypatch) -> None:
    patch_watchlists(monkeypatch)
    output = tmp_path / "nested" / "custom.md"

    path = cli.generate_report([vulnerability()], output=output)

    assert path == output
    assert output.exists()


def test_empty_database_report_generation(tmp_path, monkeypatch) -> None:
    patch_watchlists(monkeypatch)
    output = tmp_path / "empty.md"

    cli.generate_report([], output=output)

    markdown = output.read_text(encoding="utf-8")
    assert "数据库漏洞总数: 0" in markdown
    assert "本次范围内没有企业关注命中的重点漏洞" in markdown


def test_main_uses_mocked_database_data(tmp_path, monkeypatch) -> None:
    patch_watchlists(monkeypatch)
    output = tmp_path / "main.md"
    monkeypatch.setattr(cli, "load_vulnerabilities", lambda: [vulnerability()])
    monkeypatch.setattr(
        "sys.argv",
        ["generate_report", "--output", str(output), "--limit", "1"],
    )

    cli.main()

    assert output.exists()
