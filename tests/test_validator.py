from collectors.base import NormalizedVulnerability
from skills.validator import validate_vulnerabilities


def make_vulnerability(**overrides: object) -> NormalizedVulnerability:
    values = {
        "source": "dummy",
        "source_url": "https://example.com/advisories/dummy",
        "cve_id": "CVE-2099-0001",
        "title": "Valid advisory",
        "description": None,
        "vendor": None,
        "product": None,
        "severity": None,
        "cvss_score": 5.0,
        "published_at": None,
        "updated_at": None,
    }
    values.update(overrides)
    return NormalizedVulnerability(**values)


def test_valid_vulnerability() -> None:
    valid, rejected = validate_vulnerabilities([make_vulnerability()])

    assert len(valid) == 1
    assert len(rejected) == 0


def test_missing_source_is_rejected() -> None:
    valid, rejected = validate_vulnerabilities([make_vulnerability(source="")])

    assert len(valid) == 0
    assert len(rejected) == 1


def test_missing_title_is_rejected() -> None:
    valid, rejected = validate_vulnerabilities([make_vulnerability(title="")])

    assert len(valid) == 0
    assert len(rejected) == 1


def test_cvss_lower_than_zero_is_rejected() -> None:
    valid, rejected = validate_vulnerabilities([make_vulnerability(cvss_score=-0.1)])

    assert len(valid) == 0
    assert len(rejected) == 1


def test_cvss_higher_than_ten_is_rejected() -> None:
    valid, rejected = validate_vulnerabilities([make_vulnerability(cvss_score=10.1)])

    assert len(valid) == 0
    assert len(rejected) == 1


def test_missing_cve_id_is_accepted() -> None:
    valid, rejected = validate_vulnerabilities([make_vulnerability(cve_id=None)])

    assert len(valid) == 1
    assert len(rejected) == 0
