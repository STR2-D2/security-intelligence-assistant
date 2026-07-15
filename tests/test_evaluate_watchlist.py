from app.evaluate_watchlist import (
    canonical_counts,
    evaluate_watchlists,
    tag_counts,
    top_matches,
)
from database.models import Vulnerability
from watchlist.matcher import WatchlistMatcher
from watchlist.models import WatchKeyword


def vulnerability(
    id: int,
    title: str,
    cve_id: str | None = None,
    in_kev: bool = False,
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
        has_poc=False,
        in_kev=in_kev,
        ai_summary=None,
        status="new",
    )


def test_counts_and_tags() -> None:
    matcher = WatchlistMatcher(
        [
            WatchKeyword("Azure", "cloud", ("Azure",), ("cloud",), 30),
            WatchKeyword("RCE", "type", ("RCE",), ("critical",), 30),
        ]
    )
    results = evaluate_watchlists(
        [vulnerability(1, "Azure RCE"), vulnerability(2, "Azure")],
        matcher,
    )

    assert canonical_counts(results) == {"Azure": 2, "RCE": 1}
    assert tag_counts(results) == {"cloud": 2, "critical": 1}


def test_top_sorting_uses_watchlist_score_then_risk_then_identity() -> None:
    matcher = WatchlistMatcher(
        [
            WatchKeyword("Azure", "cloud", ("Azure",), ("cloud",), 30),
            WatchKeyword("RCE", "type", ("RCE",), ("critical",), 30),
        ]
    )
    results = evaluate_watchlists(
        [
            vulnerability(1, "Azure", "CVE-3", in_kev=True),
            vulnerability(2, "Azure RCE", "CVE-2"),
            vulnerability(3, "Azure", "CVE-1"),
        ],
        matcher,
    )

    top = top_matches(results, limit=3)

    assert [item[0].cve_id for item in top] == ["CVE-2", "CVE-3", "CVE-1"]


def test_top_matches_excludes_vulnerability_type_only_results() -> None:
    matcher = WatchlistMatcher(
        [
            WatchKeyword("RCE", "vulnerability_type", ("RCE",), ("critical",), 80),
            WatchKeyword("Azure", "cloud", ("Azure",), ("cloud",), 20),
        ]
    )
    results = evaluate_watchlists(
        [
            vulnerability(1, "RCE", "CVE-1"),
            vulnerability(2, "Azure", "CVE-2"),
            vulnerability(3, "Azure RCE", "CVE-3"),
        ],
        matcher,
    )

    top = top_matches(results, limit=3)

    assert [item[0].cve_id for item in top] == ["CVE-3", "CVE-2"]


def test_empty_results_are_handled() -> None:
    assert canonical_counts([]) == {}
    assert tag_counts([]) == {}
    assert top_matches([]) == []
