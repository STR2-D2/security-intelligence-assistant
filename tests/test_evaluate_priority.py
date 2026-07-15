from app.evaluate_priority import (
    evaluate_priorities,
    get_distribution,
    get_top_results,
    keyword_counts,
    tag_counts,
)
from database.models import Vulnerability
from priority.engine import EnterprisePriorityEngine
from priority.models import PriorityLevel
from risk.engine import VulnerabilityRiskEngine
from watchlist.matcher import WatchlistMatcher
from watchlist.models import WatchKeyword


def vulnerability(
    id: int,
    title: str,
    cve_id: str | None = None,
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
        description=None,
        vendor=None,
        product=None,
        severity=None,
        cvss_score=cvss_score,
        published_at=None,
        updated_at=None,
        has_poc=has_poc,
        in_kev=in_kev,
        ai_summary=None,
        status="new",
    )


def engine() -> EnterprisePriorityEngine:
    return EnterprisePriorityEngine(
        VulnerabilityRiskEngine(),
        WatchlistMatcher(
            [
                WatchKeyword("Azure", "cloud", ("Azure",), ("cloud",), 100),
                WatchKeyword("Windows", "operating_system", ("Windows",), ("os",), 50),
                WatchKeyword("RCE", "vulnerability_type", ("RCE",), ("critical",), 100),
            ]
        ),
    )


def test_distribution_counts() -> None:
    results = evaluate_priorities(
        [
            vulnerability(1, "nothing", "CVE-1"),
            vulnerability(2, "Azure", "CVE-2"),
            vulnerability(3, "Azure RCE", "CVE-3", in_kev=True, has_poc=True, cvss_score=9.8),
        ],
        engine(),
    )

    distribution = get_distribution(results)

    assert distribution[PriorityLevel.LOW] == 1
    assert distribution[PriorityLevel.MEDIUM] == 1
    assert distribution[PriorityLevel.CRITICAL] == 1


def test_keyword_and_tag_counts() -> None:
    results = evaluate_priorities(
        [
            vulnerability(1, "Azure RCE", "CVE-1"),
            vulnerability(2, "Windows", "CVE-2"),
        ],
        engine(),
    )

    assert keyword_counts(results) == {"Azure": 1, "RCE": 1, "Windows": 1}
    assert tag_counts(results) == {"cloud": 1, "critical": 1, "os": 1}


def test_top_results_include_only_relevance_matched_records() -> None:
    results = evaluate_priorities(
        [
            vulnerability(1, "RCE", "CVE-1", in_kev=True, has_poc=True, cvss_score=9.8),
            vulnerability(2, "Azure", "CVE-2"),
            vulnerability(3, "Azure RCE", "CVE-3"),
        ],
        engine(),
    )

    top = get_top_results(results, limit=3)

    assert [item[0].cve_id for item in top] == ["CVE-3", "CVE-2"]


def test_top_results_sort_by_level_score_risk_and_identity() -> None:
    results = evaluate_priorities(
        [
            vulnerability(1, "Azure", "CVE-3", in_kev=True),
            vulnerability(2, "Azure RCE", "CVE-2"),
            vulnerability(3, "Windows", "CVE-1", in_kev=True),
        ],
        engine(),
    )

    top = get_top_results(results, limit=3)

    assert [item[0].cve_id for item in top] == ["CVE-3", "CVE-1", "CVE-2"]


def test_empty_results_are_handled() -> None:
    assert get_distribution([]) == {
        PriorityLevel.LOW: 0,
        PriorityLevel.MEDIUM: 0,
        PriorityLevel.HIGH: 0,
        PriorityLevel.CRITICAL: 0,
    }
    assert keyword_counts([]) == {}
    assert tag_counts([]) == {}
    assert get_top_results([]) == []
