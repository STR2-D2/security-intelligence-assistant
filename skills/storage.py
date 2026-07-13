from sqlalchemy import select
from sqlalchemy.orm import Session

from collectors.base import NormalizedVulnerability
from database.models import Vulnerability
from database.session import get_db_session


def save_vulnerabilities(vulnerabilities: list[NormalizedVulnerability]) -> int:
    inserted_count = 0

    with get_db_session() as session:
        for vulnerability in vulnerabilities:
            if _exists(session, vulnerability):
                continue

            session.add(Vulnerability(**vulnerability.__dict__))
            inserted_count += 1

    return inserted_count


def _exists(session: Session, vulnerability: NormalizedVulnerability) -> bool:
    if vulnerability.cve_id:
        statement = select(Vulnerability).where(
            Vulnerability.cve_id == vulnerability.cve_id
        )
    else:
        statement = select(Vulnerability).where(
            Vulnerability.source == vulnerability.source,
            Vulnerability.title == vulnerability.title,
            Vulnerability.source_url == vulnerability.source_url,
        )

    return session.execute(statement).first() is not None
