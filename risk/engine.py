from database.models import Vulnerability
from risk.models import RiskAssessment, RiskLevel, RiskReason


class VulnerabilityRiskEngine:
    def evaluate(self, vulnerability: Vulnerability) -> RiskAssessment:
        reasons: list[RiskReason] = []

        if vulnerability.in_kev is True:
            reasons.append(
                RiskReason(
                    rule_id="known_exploited",
                    score=50,
                    message="Listed in CISA Known Exploited Vulnerabilities catalog",
                )
            )

        if vulnerability.has_poc is True:
            reasons.append(
                RiskReason(
                    rule_id="public_poc",
                    score=20,
                    message="Public proof-of-concept or exploit is available",
                )
            )

        cvss_reason = self._evaluate_cvss(vulnerability.cvss_score)
        if cvss_reason is not None:
            reasons.append(cvss_reason)
        elif vulnerability.cvss_score is None:
            severity_reason = self._evaluate_severity(vulnerability.severity)
            if severity_reason is not None:
                reasons.append(severity_reason)

        score = min(100, max(0, sum(reason.score for reason in reasons)))
        return RiskAssessment(
            vulnerability_id=vulnerability.id,
            cve_id=vulnerability.cve_id,
            score=score,
            level=self._level_for_score(score),
            reasons=reasons,
        )

    def _evaluate_cvss(self, cvss_score: float | None) -> RiskReason | None:
        if cvss_score is None:
            return None
        if cvss_score >= 9.0:
            return RiskReason("cvss_critical", 30, "CVSS score is critical")
        if cvss_score >= 7.0:
            return RiskReason("cvss_high", 20, "CVSS score is high")
        if cvss_score >= 4.0:
            return RiskReason("cvss_medium", 10, "CVSS score is medium")
        return None

    def _evaluate_severity(self, severity: str | None) -> RiskReason | None:
        if severity is None:
            return None

        normalized = severity.strip().lower()
        if normalized == "critical":
            return RiskReason("severity_critical", 30, "Severity is critical")
        if normalized == "high":
            return RiskReason("severity_high", 20, "Severity is high")
        if normalized in {"medium", "moderate"}:
            return RiskReason("severity_medium", 10, "Severity is medium")
        return None

    def _level_for_score(self, score: int) -> RiskLevel:
        if score >= 80:
            return RiskLevel.CRITICAL
        if score >= 60:
            return RiskLevel.HIGH
        if score >= 30:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

