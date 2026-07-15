import argparse
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger
from sqlalchemy import select

from app.config import settings
from app.logging import setup_logging
from database.models import Vulnerability
from database.session import get_db_session
from priority.engine import EnterprisePriorityEngine
from reporting.markdown import MarkdownReportRenderer
from reporting.service import WeeklyReportService
from risk.engine import VulnerabilityRiskEngine
from watchlist.loader import load_watchlists
from watchlist.matcher import WatchlistMatcher


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate weekly security advisory report")
    parser.add_argument("--period-days", type=int, default=7)
    parser.add_argument("--period-only", action="store_true")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()


def load_vulnerabilities() -> list[Vulnerability]:
    with get_db_session() as session:
        vulnerabilities = list(session.scalars(select(Vulnerability)).all())
        for vulnerability in vulnerabilities:
            session.expunge(vulnerability)
        return vulnerabilities


def generate_report(
    vulnerabilities: list[Vulnerability],
    period_days: int = 7,
    period_only: bool = False,
    limit: int = 20,
    output: Path | None = None,
) -> Path:
    risk_engine = VulnerabilityRiskEngine()
    matcher = WatchlistMatcher(load_watchlists())
    priority_engine = EnterprisePriorityEngine(risk_engine, matcher)
    service = WeeklyReportService(risk_engine, matcher, priority_engine)
    report = service.build_report(
        vulnerabilities,
        period_days=period_days,
        period_only=period_only,
        limit=limit,
    )
    markdown = MarkdownReportRenderer().render(report)

    output_path = output or _default_output_path(report.generated_at)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(markdown, encoding="utf-8")
    logger.info(f"Security advisory report written to {output_path}")
    logger.info(f"Security advisory report focus items: {len(report.focus_items)}")
    return output_path


def main() -> None:
    args = parse_args()
    setup_logging(settings.log_level)
    generate_report(
        load_vulnerabilities(),
        period_days=args.period_days,
        period_only=args.period_only,
        limit=args.limit,
        output=args.output,
    )


def _default_output_path(generated_at: datetime) -> Path:
    date_text = generated_at.astimezone(UTC).date().isoformat()
    return Path("reports") / f"security_advisory_{date_text}.md"


if __name__ == "__main__":
    main()
