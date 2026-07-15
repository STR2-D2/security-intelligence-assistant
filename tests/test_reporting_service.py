from datetime import UTC, datetime, timedelta

from database.models import Vulnerability
from priority.engine import EnterprisePriorityEngine
from priority.models import PriorityLevel
from reporting.service import WeeklyReportService
from risk.engine import VulnerabilityRiskEngine
from watchlist.matcher import WatchlistMatcher
from watchlist.models import WatchKeyword


START = datetime(2026, 1, 1, tzinfo=UTC)
END = datetime(2026, 1, 8, tzinfo=UTC)


def vulnerability(
    id: int,
    title: str,
    cve_id: str | None = None,
    published_at: datetime | None = None,
    updated_at: datetime | None = None,
    in_kev: bool = False,
    has_poc: bool = False,
    cvss_score: float | None = None,
) -> Vulnerability:
    return Vulnerability(
        id=id,
        source="test",
        source_url=None,
        cve_id=cve_id,
        title=title,
        description="Description",
        vendor=None,
        product=None,
        severity=None,
        cvss_score=cvss_score,
        published_at=published_at,
        updated_at=updated_at,
        has_poc=has_poc,
        in_kev=in_kev,
        ai_summary=None,
        status="new",
    )


def service() -> WeeklyReportService:
    risk_engine = VulnerabilityRiskEngine()
    matcher = WatchlistMatcher(
        [
            WatchKeyword("Azure", "cloud", ("Azure",), ("cloud",), 100),
            WatchKeyword("Windows", "operating_system", ("Windows",), ("os",), 50),
            WatchKeyword("RCE", "vulnerability_type", ("RCE",), ("critical",), 100),
        ]
    )
    priority_engine = EnterprisePriorityEngine(risk_engine, matcher)
    return WeeklyReportService(risk_engine, matcher, priority_engine)


def build(vulnerabilities: list[Vulnerability], **overrides):
    values = {
        "start_at": START,
        "end_at": END,
        "generated_at": END,
    }
    values.update(overrides)
    return service().build_report(vulnerabilities, **values)


def test_published_at_period_inclusion() -> None:
    report = build(
        [vulnerability(1, "Azure", "CVE-1", published_at=START)],
        period_only=True,
    )

    assert report.period_vulnerability_count == 1


def test_updated_at_period_inclusion() -> None:
    report = build(
        [vulnerability(1, "Azure", "CVE-1", updated_at=START + timedelta(days=1))],
        period_only=True,
    )

    assert report.period_vulnerability_count == 1


def test_outside_period_excluded_when_period_only() -> None:
    report = build(
        [vulnerability(1, "Azure", "CVE-1", published_at=START - timedelta(days=1))],
        period_only=True,
    )

    assert report.period_vulnerability_count == 0


def test_missing_source_dates_excluded_from_period_only_scope() -> None:
    report = build([vulnerability(1, "Azure", "CVE-1")], period_only=True)

    assert report.period_vulnerability_count == 0


def test_period_only_false_evaluates_all_records() -> None:
    report = build([vulnerability(1, "Azure", "CVE-1")], period_only=False)

    assert report.period_vulnerability_count == 1
    assert report.total_database_vulnerabilities == 1


def test_relevance_only_focus_filtering() -> None:
    report = build(
        [
            vulnerability(1, "RCE", "CVE-1"),
            vulnerability(2, "Azure", "CVE-2"),
        ]
    )

    assert [item.cve_id for item in report.focus_items] == ["CVE-2"]


def test_focus_sorting() -> None:
    report = build(
        [
            vulnerability(1, "Windows", "CVE-1", published_at=START + timedelta(days=2), in_kev=True),
            vulnerability(2, "Azure RCE", "CVE-2", published_at=START + timedelta(days=1)),
            vulnerability(3, "Azure", "CVE-3", published_at=START + timedelta(days=3), in_kev=True),
        ]
    )

    assert [item.cve_id for item in report.focus_items] == ["CVE-3", "CVE-1", "CVE-2"]


def test_focus_limit() -> None:
    report = build(
        [
            vulnerability(1, "Azure", "CVE-1"),
            vulnerability(2, "Windows", "CVE-2"),
        ],
        limit=1,
    )

    assert len(report.focus_items) == 1


def test_priority_distribution() -> None:
    report = build(
        [
            vulnerability(1, "nothing", "CVE-1"),
            vulnerability(2, "Azure", "CVE-2"),
            vulnerability(3, "Azure RCE", "CVE-3", in_kev=True, has_poc=True, cvss_score=9.8),
        ]
    )

    assert report.priority_distribution[PriorityLevel.LOW] == 1
    assert report.priority_distribution[PriorityLevel.MEDIUM] == 1
    assert report.priority_distribution[PriorityLevel.CRITICAL] == 1


def test_keyword_and_tag_counting() -> None:
    report = build(
        [
            vulnerability(1, "Azure RCE", "CVE-1"),
            vulnerability(2, "Windows", "CVE-2"),
        ]
    )

    assert report.top_keyword_counts == (("Azure", 1), ("RCE", 1), ("Windows", 1))
    assert report.top_tag_counts == (("cloud", 1), ("critical", 1), ("os", 1))


def test_empty_database_handling() -> None:
    report = build([])

    assert report.total_database_vulnerabilities == 0
    assert report.period_vulnerability_count == 0
    assert report.relevance_matched_count == 0
    assert report.focus_items == []
