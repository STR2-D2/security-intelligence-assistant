from dataclasses import dataclass
from enum import Enum


class PriorityLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class PriorityComponent:
    component_id: str
    raw_score: int
    weight: float
    weighted_score: float
    message: str


@dataclass(frozen=True)
class EnterprisePriorityAssessment:
    vulnerability_id: int | None
    cve_id: str | None
    score: int
    level: PriorityLevel
    generic_risk_score: int
    relevance_score: int
    vulnerability_type_score: int
    relevance_matched: bool
    components: list[PriorityComponent]
    matched_keywords: tuple[str, ...]
    tags: tuple[str, ...]
