from dataclasses import dataclass
from datetime import datetime

from priority.models import PriorityLevel


@dataclass(frozen=True)
class ReportPeriod:
    start_at: datetime
    end_at: datetime


@dataclass(frozen=True)
class ReportItem:
    vulnerability_id: int
    cve_id: str | None
    title: str
    source: str
    source_url: str | None
    published_at: datetime | None
    updated_at: datetime | None
    priority_score: int
    priority_level: PriorityLevel
    generic_risk_score: int
    relevance_score: int
    vulnerability_type_score: int
    matched_keywords: tuple[str, ...]
    tags: tuple[str, ...]
    risk_reasons: tuple[str, ...]
    priority_reasons: tuple[str, ...]
    description: str | None


@dataclass(frozen=True)
class WeeklyReport:
    generated_at: datetime
    period: ReportPeriod
    total_database_vulnerabilities: int
    period_vulnerability_count: int
    relevance_matched_count: int
    priority_distribution: dict[PriorityLevel, int]
    top_keyword_counts: tuple[tuple[str, int], ...]
    top_tag_counts: tuple[tuple[str, int], ...]
    focus_items: list[ReportItem]
