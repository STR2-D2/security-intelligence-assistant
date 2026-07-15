from collections import Counter

from loguru import logger
from sqlalchemy import select

from app.config import settings
from app.logging import setup_logging
from database.models import Vulnerability
from database.session import get_db_session
from priority.engine import EnterprisePriorityEngine
from priority.models import EnterprisePriorityAssessment, PriorityLevel
from risk.engine import VulnerabilityRiskEngine
from watchlist.loader import load_watchlists
from watchlist.matcher import WatchlistMatcher


def load_vulnerabilities() -> list[Vulnerability]:
    with get_db_session() as session:
        vulnerabilities = list(session.scalars(select(Vulnerability)).all())
        for vulnerability in vulnerabilities:
            session.expunge(vulnerability)
        return vulnerabilities


def evaluate_priorities(
    vulnerabilities: list[Vulnerability],
    engine: EnterprisePriorityEngine,
) -> list[tuple[Vulnerability, EnterprisePriorityAssessment]]:
    return [(vulnerability, engine.evaluate(vulnerability)) for vulnerability in vulnerabilities]


def get_distribution(
    results: list[tuple[Vulnerability, EnterprisePriorityAssessment]],
) -> dict[PriorityLevel, int]:
    counts = Counter(assessment.level for _, assessment in results)
    return {level: counts.get(level, 0) for level in PriorityLevel}


def keyword_counts(
    results: list[tuple[Vulnerability, EnterprisePriorityAssessment]],
) -> Counter[str]:
    counts: Counter[str] = Counter()
    for _, assessment in results:
        for keyword in assessment.matched_keywords:
            counts[keyword] += 1
    return counts


def tag_counts(
    results: list[tuple[Vulnerability, EnterprisePriorityAssessment]],
) -> Counter[str]:
    counts: Counter[str] = Counter()
    for _, assessment in results:
        for tag in assessment.tags:
            counts[tag] += 1
    return counts


def get_top_results(
    results: list[tuple[Vulnerability, EnterprisePriorityAssessment]],
    limit: int = 20,
) -> list[tuple[Vulnerability, EnterprisePriorityAssessment]]:
    return sorted(
        [
            (vulnerability, assessment)
            for vulnerability, assessment in results
            if assessment.relevance_matched
        ],
        key=lambda item: (
            -_priority_rank(item[1].level),
            -item[1].score,
            -item[1].generic_risk_score,
            (item[0].cve_id or item[0].title or "").lower(),
        ),
    )[:limit]


def log_results(
    results: list[tuple[Vulnerability, EnterprisePriorityAssessment]],
) -> None:
    distribution = get_distribution(results)
    relevance_matched_count = sum(1 for _, assessment in results if assessment.relevance_matched)
    logger.info(f"Priority evaluation total evaluated: {len(results)}")
    logger.info(f"Priority relevance matched count: {relevance_matched_count}")
    logger.info(
        "Priority distribution: "
        + ", ".join(f"{level.value}={distribution[level]}" for level in PriorityLevel)
    )
    logger.info(f"Priority top canonical keywords: {dict(keyword_counts(results).most_common(20))}")
    logger.info(f"Priority top tags: {dict(tag_counts(results).most_common(20))}")

    for vulnerability, assessment in get_top_results(results):
        components = "; ".join(component.message for component in assessment.components)
        logger.info(
            "Top enterprise priority: "
            f"priority_score={assessment.score}, "
            f"priority_level={assessment.level.value}, "
            f"generic_risk_score={assessment.generic_risk_score}, "
            f"relevance_score={assessment.relevance_score}, "
            f"vulnerability_type_score={assessment.vulnerability_type_score}, "
            f"cve_id={assessment.cve_id}, "
            f"title={vulnerability.title}, "
            f"matched_keywords={', '.join(assessment.matched_keywords)}, "
            f"tags={', '.join(assessment.tags)}, "
            f"components={components}"
        )


def main() -> None:
    setup_logging(settings.log_level)
    matcher = WatchlistMatcher(load_watchlists())
    engine = EnterprisePriorityEngine(VulnerabilityRiskEngine(), matcher)
    results = evaluate_priorities(load_vulnerabilities(), engine)
    log_results(results)


def _priority_rank(level: PriorityLevel) -> int:
    return {
        PriorityLevel.LOW: 0,
        PriorityLevel.MEDIUM: 1,
        PriorityLevel.HIGH: 2,
        PriorityLevel.CRITICAL: 3,
    }[level]


if __name__ == "__main__":
    main()
