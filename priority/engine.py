from decimal import Decimal, ROUND_HALF_UP

from database.models import Vulnerability
from priority.models import (
    EnterprisePriorityAssessment,
    PriorityComponent,
    PriorityLevel,
)
from risk.engine import VulnerabilityRiskEngine
from risk.models import RiskLevel
from watchlist.matcher import WatchlistMatcher


GENERIC_RISK_WEIGHT = 0.60
RELEVANCE_WEIGHT = 0.30
VULNERABILITY_TYPE_WEIGHT = 0.10


class EnterprisePriorityEngine:
    def __init__(
        self,
        risk_engine: VulnerabilityRiskEngine,
        watchlist_matcher: WatchlistMatcher,
    ) -> None:
        self.risk_engine = risk_engine
        self.watchlist_matcher = watchlist_matcher

    def evaluate(self, vulnerability: Vulnerability) -> EnterprisePriorityAssessment:
        risk = self.risk_engine.evaluate(vulnerability)
        watchlist = self.watchlist_matcher.evaluate(vulnerability)

        components = [
            PriorityComponent(
                "generic_risk",
                risk.score,
                GENERIC_RISK_WEIGHT,
                risk.score * GENERIC_RISK_WEIGHT,
                "Generic vulnerability risk score",
            ),
            PriorityComponent(
                "watchlist_relevance",
                watchlist.relevance_score,
                RELEVANCE_WEIGHT,
                watchlist.relevance_score * RELEVANCE_WEIGHT,
                "Organization watchlist relevance score",
            ),
            PriorityComponent(
                "vulnerability_type",
                watchlist.vulnerability_type_score,
                VULNERABILITY_TYPE_WEIGHT,
                watchlist.vulnerability_type_score * VULNERABILITY_TYPE_WEIGHT,
                "Matched vulnerability type score",
            ),
        ]

        weighted_score = sum(component.weighted_score for component in components)
        score = min(100, max(0, _round_half_up(weighted_score)))
        level = _level_for_score(score)

        if not watchlist.relevance_matched and _severity_rank(level) > _severity_rank(
            PriorityLevel.MEDIUM
        ):
            level = PriorityLevel.MEDIUM
            components.append(
                PriorityComponent(
                    "relevance_guardrail",
                    score,
                    0.0,
                    0.0,
                    "Priority level capped at MEDIUM because no organization relevance matched",
                )
            )

        if (
            risk.level == RiskLevel.CRITICAL
            and watchlist.relevance_matched
            and watchlist.relevance_score >= 30
            and _severity_rank(level) < _severity_rank(PriorityLevel.HIGH)
        ):
            level = PriorityLevel.HIGH
            components.append(
                PriorityComponent(
                    "critical_relevance_escalation",
                    score,
                    0.0,
                    0.0,
                    "Critical generic risk with strong organization relevance escalates priority to at least HIGH",
                )
            )

        return EnterprisePriorityAssessment(
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            score=score,
            level=level,
            generic_risk_score=risk.score,
            relevance_score=watchlist.relevance_score,
            vulnerability_type_score=watchlist.vulnerability_type_score,
            relevance_matched=watchlist.relevance_matched,
            components=components,
            matched_keywords=tuple(
                dict.fromkeys(match.canonical_name for match in watchlist.matches)
            ),
            tags=watchlist.tags,
        )


def _round_half_up(value: float) -> int:
    return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _level_for_score(score: int) -> PriorityLevel:
    if score >= 80:
        return PriorityLevel.CRITICAL
    if score >= 60:
        return PriorityLevel.HIGH
    if score >= 30:
        return PriorityLevel.MEDIUM
    return PriorityLevel.LOW


def _severity_rank(level: PriorityLevel) -> int:
    return {
        PriorityLevel.LOW: 0,
        PriorityLevel.MEDIUM: 1,
        PriorityLevel.HIGH: 2,
        PriorityLevel.CRITICAL: 3,
    }[level]
