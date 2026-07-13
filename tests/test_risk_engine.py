from database.models import Vulnerability
from risk.engine import VulnerabilityRiskEngine
from risk.models import RiskLevel


def make_vulnerability(**overrides: object) -> Vulnerability:
    values = {
        "id": 1,
        "source": "test",
        "source_url": None,
        "cve_id": "CVE-2099-0001",
        "title": "Test Vulnerability",
        "description": "Description",
        "vendor": "Vendor",
        "product": "Product",
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


def evaluate(**overrides: object):
    return VulnerabilityRiskEngine().evaluate(make_vulnerability(**overrides))


def test_kev_only_gives_medium_score() -> None:
    assessment = evaluate(in_kev=True)

    assert assessment.score == 50
    assert assessment.level == RiskLevel.MEDIUM


def test_kev_and_poc_gives_high_score() -> None:
    assessment = evaluate(in_kev=True, has_poc=True)

    assert assessment.score == 70
    assert assessment.level == RiskLevel.HIGH


def test_kev_and_critical_cvss_gives_critical_score() -> None:
    assessment = evaluate(in_kev=True, cvss_score=9.8)

    assert assessment.score == 80
    assert assessment.level == RiskLevel.CRITICAL


def test_poc_and_critical_cvss_gives_medium_score() -> None:
    assessment = evaluate(has_poc=True, cvss_score=9.8)

    assert assessment.score == 50
    assert assessment.level == RiskLevel.MEDIUM


def test_high_cvss_gives_low_score() -> None:
    assessment = evaluate(cvss_score=7.5)

    assert assessment.score == 20
    assert assessment.level == RiskLevel.LOW


def test_medium_cvss_gives_low_score() -> None:
    assessment = evaluate(cvss_score=5.0)

    assert assessment.score == 10
    assert assessment.level == RiskLevel.LOW


def test_severity_critical_fallback_gives_medium_score() -> None:
    assessment = evaluate(severity="critical")

    assert assessment.score == 30
    assert assessment.level == RiskLevel.MEDIUM


def test_severity_is_ignored_when_cvss_exists() -> None:
    assessment = evaluate(cvss_score=5.0, severity="critical")

    assert assessment.score == 10
    assert [reason.rule_id for reason in assessment.reasons] == ["cvss_medium"]


def test_severity_comparison_is_case_insensitive() -> None:
    assessment = evaluate(severity="HiGh")

    assert assessment.score == 20
    assert assessment.reasons[0].rule_id == "severity_high"


def test_unknown_severity_contributes_zero() -> None:
    assessment = evaluate(severity="informational")

    assert assessment.score == 0
    assert assessment.level == RiskLevel.LOW
    assert assessment.reasons == []


def test_score_never_exceeds_100() -> None:
    assessment = evaluate(in_kev=True, has_poc=True, cvss_score=10.0)

    assert assessment.score == 100
    assert assessment.level == RiskLevel.CRITICAL


def test_reasons_are_in_deterministic_order() -> None:
    assessment = evaluate(in_kev=True, has_poc=True, cvss_score=9.8)

    assert [reason.rule_id for reason in assessment.reasons] == [
        "known_exploited",
        "public_poc",
        "cvss_critical",
    ]


def test_evaluating_vulnerability_does_not_mutate_it() -> None:
    vulnerability = make_vulnerability(in_kev=True, has_poc=True, cvss_score=9.8)
    before = {
        "in_kev": vulnerability.in_kev,
        "has_poc": vulnerability.has_poc,
        "cvss_score": vulnerability.cvss_score,
        "severity": vulnerability.severity,
        "status": vulnerability.status,
    }

    VulnerabilityRiskEngine().evaluate(vulnerability)

    assert {
        "in_kev": vulnerability.in_kev,
        "has_poc": vulnerability.has_poc,
        "cvss_score": vulnerability.cvss_score,
        "severity": vulnerability.severity,
        "status": vulnerability.status,
    } == before

