from collections import Counter

from loguru import logger
from sqlalchemy import select

from app.config import settings
from app.evaluate_risk import evaluate_vulnerabilities
from app.logging import setup_logging
from database.models import Vulnerability
from database.session import get_db_session
from watchlist.loader import load_watchlists
from watchlist.matcher import WatchlistMatcher
from watchlist.models import WatchlistMatchResult


def load_vulnerabilities() -> list[Vulnerability]:
    with get_db_session() as session:
        vulnerabilities = list(session.scalars(select(Vulnerability)).all())
        for vulnerability in vulnerabilities:
            session.expunge(vulnerability)
        return vulnerabilities


def evaluate_watchlists(
    vulnerabilities: list[Vulnerability],
    matcher: WatchlistMatcher,
) -> list[tuple[Vulnerability, WatchlistMatchResult]]:
    return [(vulnerability, matcher.evaluate(vulnerability)) for vulnerability in vulnerabilities]


def canonical_counts(
    results: list[tuple[Vulnerability, WatchlistMatchResult]],
) -> Counter[str]:
    counts: Counter[str] = Counter()
    for _, result in results:
        for canonical_name in {match.canonical_name for match in result.matches}:
            counts[canonical_name] += 1
    return counts


def tag_counts(results: list[tuple[Vulnerability, WatchlistMatchResult]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for _, result in results:
        for tag in result.tags:
            counts[tag] += 1
    return counts


def top_matches(
    results: list[tuple[Vulnerability, WatchlistMatchResult]],
    limit: int = 20,
) -> list[tuple[Vulnerability, WatchlistMatchResult, int]]:
    risk_scores = {
        vulnerability.id: assessment.score
        for vulnerability, assessment in evaluate_vulnerabilities(
            [vulnerability for vulnerability, result in results if result.relevance_matched]
        )
    }
    enriched = [
        (vulnerability, result, risk_scores.get(vulnerability.id, 0))
        for vulnerability, result in results
        if result.relevance_matched
    ]
    return sorted(
        enriched,
        key=lambda item: (
            -item[1].score,
            -item[2],
            (item[0].cve_id or item[0].title or "").lower(),
        ),
    )[:limit]


def log_results(results: list[tuple[Vulnerability, WatchlistMatchResult]]) -> None:
    matched_count = sum(1 for _, result in results if result.matched)
    relevance_matched_count = sum(1 for _, result in results if result.relevance_matched)
    vulnerability_type_only_count = sum(
        1
        for _, result in results
        if result.vulnerability_type_matched and not result.relevance_matched
    )
    completely_unmatched_count = sum(1 for _, result in results if not result.matched)
    logger.info(f"Watchlist total vulnerabilities evaluated: {len(results)}")
    logger.info(f"Watchlist total matched by any keyword: {matched_count}")
    logger.info(f"Watchlist total relevance matched: {relevance_matched_count}")
    logger.info(
        f"Watchlist total vulnerability-type-only matched: {vulnerability_type_only_count}"
    )
    logger.info(f"Watchlist total completely unmatched: {completely_unmatched_count}")
    logger.info(f"Watchlist canonical keyword counts: {dict(canonical_counts(results))}")
    logger.info(f"Watchlist tag counts: {dict(tag_counts(results))}")

    for vulnerability, result, risk_score in top_matches(results):
        canonical = ", ".join(dict.fromkeys(match.canonical_name for match in result.matches))
        categories = ", ".join(dict.fromkeys(match.category for match in result.matches))
        details = "; ".join(
            f"{match.matched_alias}@{match.matched_field}" for match in result.matches
        )
        logger.info(
            "Top watchlist match: "
            f"relevance_score={result.relevance_score}, "
            f"vulnerability_type_score={result.vulnerability_type_score}, "
            f"watchlist_score={result.score}, "
            f"risk_score={risk_score}, "
            f"cve_id={vulnerability.cve_id}, "
            f"title={vulnerability.title}, "
            f"canonical_keywords={canonical}, "
            f"categories={categories}, "
            f"matches={details}, "
            f"tags={', '.join(result.tags)}"
        )


def main() -> None:
    setup_logging(settings.log_level)
    keywords = load_watchlists()
    matcher = WatchlistMatcher(keywords)
    results = evaluate_watchlists(load_vulnerabilities(), matcher)
    log_results(results)


if __name__ == "__main__":
    main()
