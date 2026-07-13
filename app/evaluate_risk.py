from collections import Counter

from loguru import logger
from sqlalchemy import select

from app.config import settings
from app.logging import setup_logging
from database.models import Vulnerability
from database.session import get_db_session
from risk.engine import VulnerabilityRiskEngine
from risk.models import RiskAssessment, RiskLevel


def evaluate_vulnerabilities(
    vulnerabilities: list[Vulnerability],
) -> list[tuple[Vulnerability, RiskAssessment]]:
    engine = VulnerabilityRiskEngine()
    return [
        (vulnerability, engine.evaluate(vulnerability))
        for vulnerability in vulnerabilities
    ]


def get_distribution(
    results: list[tuple[Vulnerability, RiskAssessment]],
) -> dict[RiskLevel, int]:
    counts = Counter(assessment.level for _, assessment in results)
    return {level: counts.get(level, 0) for level in RiskLevel}


def get_top_results(
    results: list[tuple[Vulnerability, RiskAssessment]],
    limit: int = 10,
) -> list[tuple[Vulnerability, RiskAssessment]]:
    return sorted(
        results,
        key=lambda item: (
            -item[1].score,
            (item[0].cve_id or item[0].title or "").lower(),
        ),
    )[:limit]


def load_vulnerabilities() -> list[Vulnerability]:
    with get_db_session() as session:
        vulnerabilities = list(session.scalars(select(Vulnerability)).all())
        for vulnerability in vulnerabilities:
            session.expunge(vulnerability)
        return vulnerabilities


def log_results(results: list[tuple[Vulnerability, RiskAssessment]]) -> None:
    distribution = get_distribution(results)
    logger.info(f"Risk evaluation total evaluated: {len(results)}")
    logger.info(
        "Risk distribution: "
        + ", ".join(f"{level.value}={distribution[level]}" for level in RiskLevel)
    )

    for vulnerability, assessment in get_top_results(results):
        reasons = "; ".join(reason.message for reason in assessment.reasons)
        logger.info(
            "Top risk vulnerability: "
            f"score={assessment.score}, "
            f"level={assessment.level.value}, "
            f"cve_id={assessment.cve_id}, "
            f"title={vulnerability.title}, "
            f"reasons={reasons}"
        )


def main() -> None:
    setup_logging(settings.log_level)
    vulnerabilities = load_vulnerabilities()
    results = evaluate_vulnerabilities(vulnerabilities)
    log_results(results)


if __name__ == "__main__":
    main()
