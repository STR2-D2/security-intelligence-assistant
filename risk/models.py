from dataclasses import dataclass
from enum import Enum


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class RiskReason:
    rule_id: str
    score: int
    message: str


@dataclass(frozen=True)
class RiskAssessment:
    vulnerability_id: int | None
    cve_id: str | None
    score: int
    level: RiskLevel
    reasons: list[RiskReason]

