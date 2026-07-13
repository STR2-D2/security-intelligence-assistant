from dataclasses import dataclass

from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from collectors.base import NormalizedVulnerability
from database.models import Vulnerability
from database.session import get_db_session


@dataclass(frozen=True)
class StorageResult:
    inserted_count: int = 0
    updated_count: int = 0
    unchanged_count: int = 0


MUTABLE_FIELDS = (
    "source",
    "source_url",
    "title",
    "description",
    "vendor",
    "product",
    "severity",
    "cvss_score",
    "published_at",
    "updated_at",
    "has_poc",
    "in_kev",
    "ai_summary",
    "status",
)

TEXT_FIELDS = {
    "source",
    "source_url",
    "title",
    "description",
    "vendor",
    "product",
    "severity",
    "ai_summary",
    "status",
}


def save_vulnerabilities(
    vulnerabilities: list[NormalizedVulnerability],
) -> StorageResult:
    inserted_count = 0
    updated_count = 0
    unchanged_count = 0

    with get_db_session() as session:
        for vulnerability in (_normalize_vulnerability(item) for item in vulnerabilities):
            existing = _find_existing(session, vulnerability)
            if existing is None:
                result = _insert_vulnerability(session, vulnerability)
                inserted_count += result.inserted_count
                updated_count += result.updated_count
                unchanged_count += result.unchanged_count
                continue

            if _update_existing(existing, vulnerability):
                updated_count += 1
            else:
                unchanged_count += 1

    return StorageResult(
        inserted_count=inserted_count,
        updated_count=updated_count,
        unchanged_count=unchanged_count,
    )


def _normalize_vulnerability(
    vulnerability: NormalizedVulnerability,
) -> NormalizedVulnerability:
    normalized_source = vulnerability.source.strip()
    normalized_title = vulnerability.title.strip()
    normalized_source_url = _normalize_optional_string(vulnerability.source_url)
    normalized_cve_id = None
    if vulnerability.cve_id is not None:
        normalized_cve_id = vulnerability.cve_id.strip().upper() or None

    return NormalizedVulnerability(
        **{
            **vulnerability.__dict__,
            "source": normalized_source,
            "source_url": normalized_source_url,
            "cve_id": normalized_cve_id,
            "title": normalized_title,
        }
    )


def _normalize_optional_string(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip() or None


def _insert_vulnerability(
    session: Session,
    vulnerability: NormalizedVulnerability,
) -> StorageResult:
    nested = session.begin_nested()
    integrity_error: IntegrityError | None = None
    try:
        session.add(Vulnerability(**vulnerability.__dict__))
        session.flush()
        nested.commit()
        return StorageResult(inserted_count=1)
    except IntegrityError as exc:
        integrity_error = exc
        nested.rollback()
        logger.warning(f"Vulnerability insert hit integrity constraint: {exc}")

    existing = _find_existing(session, vulnerability)
    if existing is None:
        raise integrity_error

    if _update_existing(existing, vulnerability):
        return StorageResult(updated_count=1)
    return StorageResult(unchanged_count=1)


def _find_existing(
    session: Session,
    vulnerability: NormalizedVulnerability,
) -> Vulnerability | None:
    if vulnerability.cve_id:
        statement = select(Vulnerability).where(
            func.upper(func.trim(Vulnerability.cve_id)) == vulnerability.cve_id
        )
    else:
        statement = select(Vulnerability).where(
            func.trim(Vulnerability.source) == vulnerability.source,
            func.trim(Vulnerability.title) == vulnerability.title,
            func.coalesce(func.trim(Vulnerability.source_url), "")
            == (vulnerability.source_url or ""),
        )

    return session.scalars(statement).first()


def _update_existing(
    existing: Vulnerability,
    vulnerability: NormalizedVulnerability,
) -> bool:
    changed = False

    for field in MUTABLE_FIELDS:
        new_value = getattr(vulnerability, field)
        # Preserve populated text when an incoming source sends None or blank text.
        if field in TEXT_FIELDS and _is_empty_text(new_value) and not _is_empty_text(
            getattr(existing, field)
        ):
            continue
        if getattr(existing, field) != new_value:
            setattr(existing, field, new_value)
            changed = True

    return changed


def _is_empty_text(value: object) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())
