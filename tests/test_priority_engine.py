from database.models import Vulnerability
from priority.engine import EnterprisePriorityEngine
from priority.models import PriorityLevel
from risk.engine import VulnerabilityRiskEngine
from watchlist.matcher import WatchlistMatcher
from watchlist.models import WatchKeyword


def vulnerability(**overrides: object) -> Vulnerability:
    values = {
        "id": 1,
        "source": "test",
        "source_url": None,
        "cve_id": "CVE-2099-0001",
        "title": "Test Vulnerability",
        "description": "",
        "vendor": "",
        "product": "",
        "severity": None,
        "cvss_score": None,
        "published_at": None,
        "updated_at": None,
        "has_poc": False,
        "in_kev": False,
        "ai_summary": None,
        "status": "new",
    }
    values.update(overrides)
    return Vulnerability(**values)


def keyword(
    name: str,
    category: str,
    score: int,
    tags: tuple[str, ...] = ("tag",),
) -> WatchKeyword:
    return WatchKeyword(name, category, (name,), tags, score)


def engine(keywords: list[WatchKeyword]) -> EnterprisePriorityEngine:
    return EnterprisePriorityEngine(
        VulnerabilityRiskEngine(),
        WatchlistMatcher(keywords),
    )


def test_weighted_score_calculation() -> None:
    assessment = engine(
        [
            keyword("Azure", "cloud", 40),
            keyword("RCE", "vulnerability_type", 50),
        ]
    ).evaluate(vulnerability(title="Azure RCE", in_kev=True))

    assert assessment.generic_risk_score == 50
    assert assessment.relevance_score == 40
    assert assessment.vulnerability_type_score == 50
    assert assessment.score == 47


def test_half_up_rounding() -> None:
    assessment = engine([keyword("Azure", "cloud", 35)]).evaluate(
        vulnerability(title="Azure")
    )

    assert assessment.score == 11


def test_score_clamping() -> None:
    assessment = engine(
        [
            keyword("A", "cloud", 100),
            keyword("B", "database", 100),
            keyword("C", "vulnerability_type", 100),
        ]
    ).evaluate(vulnerability(title="A B C", in_kev=True, has_poc=True, cvss_score=9.8))

    assert assessment.score == 100
    assert assessment.level == PriorityLevel.CRITICAL


def test_low_medium_high_and_critical_level_mappings() -> None:
    low = engine([keyword("Azure", "cloud", 35)]).evaluate(vulnerability(title="Azure"))
    medium = engine([keyword("Azure", "cloud", 100)]).evaluate(vulnerability(title="Azure"))
    high = engine([keyword("Azure", "cloud", 40)]).evaluate(
        vulnerability(title="Azure", in_kev=True, cvss_score=9.8)
    )
    critical = engine(
        [
            keyword("Azure", "cloud", 100),
            keyword("RCE", "vulnerability_type", 100),
        ]
    ).evaluate(vulnerability(title="Azure RCE", in_kev=True, has_poc=True, cvss_score=9.8))

    assert low.level == PriorityLevel.LOW
    assert medium.level == PriorityLevel.MEDIUM
    assert high.level == PriorityLevel.HIGH
    assert critical.level == PriorityLevel.CRITICAL


def test_vulnerability_type_only_match_cannot_exceed_medium_level() -> None:
    keywords = [
        keyword(f"Type{i}", "vulnerability_type", 100)
        for i in range(8)
    ]
    assessment = engine(keywords).evaluate(
        vulnerability(title=" ".join(keyword.canonical_name for keyword in keywords))
    )

    assert assessment.relevance_matched is False
    assert assessment.score == 80
    assert assessment.level == PriorityLevel.MEDIUM
    assert assessment.components[-1].component_id == "relevance_guardrail"


def test_relevance_match_allows_high_and_critical_normally() -> None:
    high = engine([keyword("Azure", "cloud", 40)]).evaluate(
        vulnerability(title="Azure", in_kev=True, cvss_score=9.8)
    )
    critical = engine(
        [
            keyword("Azure", "cloud", 100),
            keyword("Windows", "operating_system", 100),
        ]
    ).evaluate(vulnerability(title="Azure Windows", in_kev=True, has_poc=True, cvss_score=9.8))

    assert high.level == PriorityLevel.HIGH
    assert critical.level == PriorityLevel.CRITICAL


def test_critical_generic_risk_with_strong_relevance_escalates_to_high() -> None:
    assessment = engine([keyword("Azure", "cloud", 30)]).evaluate(
        vulnerability(title="Azure", in_kev=True, cvss_score=9.8)
    )

    assert assessment.score == 57
    assert assessment.level == PriorityLevel.HIGH
    assert assessment.components[-1].component_id == "critical_relevance_escalation"


def test_component_order_is_deterministic() -> None:
    assessment = engine([keyword("Azure", "cloud", 30)]).evaluate(
        vulnerability(title="Azure", in_kev=True, cvss_score=9.8)
    )

    assert [component.component_id for component in assessment.components] == [
        "generic_risk",
        "watchlist_relevance",
        "vulnerability_type",
        "critical_relevance_escalation",
    ]


def test_matched_keywords_and_tags_are_preserved() -> None:
    assessment = engine(
        [
            keyword("Azure", "cloud", 20, tags=("cloud",)),
            keyword("RCE", "vulnerability_type", 20, tags=("critical",)),
        ]
    ).evaluate(vulnerability(title="Azure RCE"))

    assert assessment.matched_keywords == ("Azure", "RCE")
    assert assessment.tags == ("cloud", "critical")


def test_evaluating_priority_does_not_mutate_vulnerability() -> None:
    item = vulnerability(title="Azure", in_kev=True, cvss_score=9.8)
    before = {
        "title": item.title,
        "in_kev": item.in_kev,
        "cvss_score": item.cvss_score,
        "status": item.status,
    }

    engine([keyword("Azure", "cloud", 30)]).evaluate(item)

    assert {
        "title": item.title,
        "in_kev": item.in_kev,
        "cvss_score": item.cvss_score,
        "status": item.status,
    } == before
