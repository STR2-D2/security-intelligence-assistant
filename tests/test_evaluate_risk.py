from collections.abc import Generator
from contextlib import contextmanager

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app import evaluate_risk
from database.models import Base, Vulnerability
from risk.models import RiskLevel


@pytest.fixture()
def isolated_risk_db(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'risk.db'}")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    @contextmanager
    def get_test_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    monkeypatch.setattr(evaluate_risk, "get_db_session", get_test_session)
    return session_factory


def make_vulnerability(**overrides: object) -> Vulnerability:
    values = {
        "source": "test",
        "source_url": None,
        "cve_id": None,
        "title": "Test Vulnerability",
        "description": None,
        "vendor": None,
        "product": None,
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


def insert_vulnerabilities(session_factory, vulnerabilities: list[Vulnerability]) -> None:
    session = session_factory()
    try:
        session.add_all(vulnerabilities)
        session.commit()
    finally:
        session.close()


def test_distribution_counting(isolated_risk_db) -> None:
    insert_vulnerabilities(
        isolated_risk_db,
        [
            make_vulnerability(title="low"),
            make_vulnerability(title="medium", in_kev=True),
            make_vulnerability(title="high", in_kev=True, has_poc=True),
            make_vulnerability(title="critical", in_kev=True, cvss_score=9.8),
        ],
    )

    results = evaluate_risk.evaluate_vulnerabilities(evaluate_risk.load_vulnerabilities())
    distribution = evaluate_risk.get_distribution(results)

    assert distribution[RiskLevel.LOW] == 1
    assert distribution[RiskLevel.MEDIUM] == 1
    assert distribution[RiskLevel.HIGH] == 1
    assert distribution[RiskLevel.CRITICAL] == 1


def test_top_results_are_sorted_by_score_then_cve_or_title() -> None:
    vulnerabilities = [
        make_vulnerability(cve_id="CVE-2099-0002", title="B", in_kev=True),
        make_vulnerability(cve_id="CVE-2099-0001", title="A", in_kev=True),
        make_vulnerability(cve_id=None, title="Alpha", has_poc=True),
        make_vulnerability(cve_id="CVE-2099-0003", title="C", in_kev=True, has_poc=True),
    ]

    results = evaluate_risk.evaluate_vulnerabilities(vulnerabilities)
    top = evaluate_risk.get_top_results(results, limit=4)

    assert [item[0].cve_id or item[0].title for item in top] == [
        "CVE-2099-0003",
        "CVE-2099-0001",
        "CVE-2099-0002",
        "Alpha",
    ]


def test_empty_database_is_handled_cleanly(isolated_risk_db) -> None:
    vulnerabilities = evaluate_risk.load_vulnerabilities()
    results = evaluate_risk.evaluate_vulnerabilities(vulnerabilities)
    distribution = evaluate_risk.get_distribution(results)
    top = evaluate_risk.get_top_results(results)

    assert vulnerabilities == []
    assert results == []
    assert top == []
    assert distribution == {
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 0,
        RiskLevel.HIGH: 0,
        RiskLevel.CRITICAL: 0,
    }

