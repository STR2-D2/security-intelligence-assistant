from collections import Counter
from datetime import UTC, datetime, timedelta

from database.models import Vulnerability
from priority.engine import EnterprisePriorityEngine
from priority.models import PriorityLevel
from reporting.models import ReportItem, ReportPeriod, WeeklyReport
from risk.engine import VulnerabilityRiskEngine
from watchlist.matcher import WatchlistMatcher


class WeeklyReportService:
    def __init__(
        self,
        risk_engine: VulnerabilityRiskEngine,
        watchlist_matcher: WatchlistMatcher,
        priority_engine: EnterprisePriorityEngine,
    ) -> None:
        self.risk_engine = risk_engine
        self.watchlist_matcher = watchlist_matcher
        self.priority_engine = priority_engine

    def build_report(
        self,
        vulnerabilities: list[Vulnerability],
        period_days: int = 7,
        period_only: bool = False,
        limit: int = 20,
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        generated_at: datetime | None = None,
    ) -> WeeklyReport:
        generated = _as_utc(generated_at or datetime.now(UTC))
        period = _build_period(generated, period_days, start_at, end_at)
        period_vulnerabilities = [
            vulnerability
            for vulnerability in vulnerabilities
            if _in_period(vulnerability, period)
        ]
        scoped_vulnerabilities = period_vulnerabilities if period_only else vulnerabilities

        evaluated = [
            (
                vulnerability,
                self.risk_engine.evaluate(vulnerability),
                self.watchlist_matcher.evaluate(vulnerability),
                self.priority_engine.evaluate(vulnerability),
            )
            for vulnerability in scoped_vulnerabilities
        ]

        distribution_counter = Counter(priority.level for _, _, _, priority in evaluated)
        priority_distribution = {
            level: distribution_counter.get(level, 0) for level in PriorityLevel
        }
        keyword_counter: Counter[str] = Counter()
        tag_counter: Counter[str] = Counter()
        for _, _, _, priority in evaluated:
            keyword_counter.update(priority.matched_keywords)
            tag_counter.update(priority.tags)

        focus_items = [
            _build_report_item(vulnerability, risk, priority)
            for vulnerability, risk, _, priority in evaluated
            if priority.relevance_matched
        ]
        focus_items = sorted(focus_items, key=_focus_sort_key)[:limit]

        return WeeklyReport(
            generated_at=generated,
            period=period,
            total_database_vulnerabilities=len(vulnerabilities),
            period_vulnerability_count=len(scoped_vulnerabilities),
            relevance_matched_count=sum(
                1 for _, _, _, priority in evaluated if priority.relevance_matched
            ),
            priority_distribution=priority_distribution,
            top_keyword_counts=tuple(keyword_counter.most_common(10)),
            top_tag_counts=tuple(tag_counter.most_common(10)),
            focus_items=focus_items,
        )


def _build_report_item(vulnerability, risk, priority) -> ReportItem:
    return ReportItem(
        vulnerability_id=vulnerability.id,
        cve_id=vulnerability.cve_id,
        title=vulnerability.title,
        source=vulnerability.source,
        source_url=vulnerability.source_url,
        published_at=vulnerability.published_at,
        updated_at=vulnerability.updated_at,
        priority_score=priority.score,
        priority_level=priority.level,
        generic_risk_score=priority.generic_risk_score,
        relevance_score=priority.relevance_score,
        vulnerability_type_score=priority.vulnerability_type_score,
        matched_keywords=priority.matched_keywords,
        tags=priority.tags,
        risk_reasons=tuple(reason.message for reason in risk.reasons),
        priority_reasons=tuple(component.message for component in priority.components),
        description=vulnerability.description,
    )


def _build_period(
    generated_at: datetime,
    period_days: int,
    start_at: datetime | None,
    end_at: datetime | None,
) -> ReportPeriod:
    if start_at is not None and end_at is not None:
        return ReportPeriod(_as_utc(start_at), _as_utc(end_at))

    end = datetime(
        generated_at.year,
        generated_at.month,
        generated_at.day,
        tzinfo=UTC,
    ) + timedelta(days=1)
    start = end - timedelta(days=period_days)
    return ReportPeriod(start, end)


def _in_period(vulnerability: Vulnerability, period: ReportPeriod) -> bool:
    dates = [vulnerability.published_at, vulnerability.updated_at]
    return any(
        value is not None and period.start_at <= _as_utc(value) < period.end_at
        for value in dates
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _focus_sort_key(item: ReportItem) -> tuple[int, int, int, float, str]:
    published_timestamp = (
        -_as_utc(item.published_at).timestamp()
        if item.published_at is not None
        else float("inf")
    )
    return (
        -_priority_rank(item.priority_level),
        -item.priority_score,
        -item.generic_risk_score,
        published_timestamp,
        (item.cve_id or item.title or "").lower(),
    )


def _priority_rank(level: PriorityLevel) -> int:
    return {
        PriorityLevel.LOW: 0,
        PriorityLevel.MEDIUM: 1,
        PriorityLevel.HIGH: 2,
        PriorityLevel.CRITICAL: 3,
    }[level]
