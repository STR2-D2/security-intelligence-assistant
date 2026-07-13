from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime

import pytest
from sqlalchemy import create_engine, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from collectors.base import NormalizedVulnerability
from database.models import Base, Vulnerability
from skills import storage


@pytest.fixture()
def isolated_storage(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    @contextmanager
    def get_test_session() -> Generator[Session, None, None]:
        session = session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    monkeypatch.setattr(storage, "get_db_session", get_test_session)
    return session_factory


def make_vulnerability(**overrides: object) -> NormalizedVulnerability:
    values = {
        "source": "test",
        "source_url": "https://example.com/advisory",
        "cve_id": "CVE-2099-0001",
        "title": "Test Vulnerability",
        "description": "Original description",
        "vendor": "Original Vendor",
        "product": "Original Product",
        "severity": None,
        "cvss_score": None,
        "published_at": datetime(2099, 1, 1),
        "updated_at": None,
    }
    values.update(overrides)
    return NormalizedVulnerability(**values)


def get_one(session_factory) -> Vulnerability:
    session = session_factory()
    try:
        return session.scalars(select(Vulnerability)).one()
    finally:
        session.close()


def count_rows(session_factory) -> int:
    session = session_factory()
    try:
        return session.scalar(select(func.count()).select_from(Vulnerability)) or 0
    finally:
        session.close()


def test_new_cve_record_is_inserted(isolated_storage) -> None:
    result = storage.save_vulnerabilities([make_vulnerability()])

    assert result.inserted_count == 1
    assert result.updated_count == 0
    assert result.unchanged_count == 0


def test_identical_cve_record_is_unchanged(isolated_storage) -> None:
    vulnerability = make_vulnerability()
    storage.save_vulnerabilities([vulnerability])
    result = storage.save_vulnerabilities([vulnerability])

    assert result.inserted_count == 0
    assert result.updated_count == 0
    assert result.unchanged_count == 1


def test_changed_cve_description_updates_existing_record(isolated_storage) -> None:
    storage.save_vulnerabilities([make_vulnerability()])
    result = storage.save_vulnerabilities(
        [make_vulnerability(description="Changed description")]
    )
    existing = get_one(isolated_storage)

    assert result.updated_count == 1
    assert existing.description == "Changed description"


def test_changed_vendor_or_product_updates_existing_record(isolated_storage) -> None:
    storage.save_vulnerabilities([make_vulnerability()])
    result = storage.save_vulnerabilities(
        [make_vulnerability(vendor="New Vendor", product="New Product")]
    )
    existing = get_one(isolated_storage)

    assert result.updated_count == 1
    assert existing.vendor == "New Vendor"
    assert existing.product == "New Product"


def test_false_and_zero_values_can_update_existing_record(isolated_storage) -> None:
    storage.save_vulnerabilities(
        [make_vulnerability(has_poc=True, in_kev=True, cvss_score=9.1)]
    )
    result = storage.save_vulnerabilities(
        [make_vulnerability(has_poc=False, in_kev=False, cvss_score=0.0)]
    )
    existing = get_one(isolated_storage)

    assert result.updated_count == 1
    assert existing.has_poc is False
    assert existing.in_kev is False
    assert existing.cvss_score == 0.0


def test_populated_text_is_not_overwritten_by_empty_incoming_value(
    isolated_storage,
) -> None:
    storage.save_vulnerabilities([make_vulnerability()])
    result = storage.save_vulnerabilities(
        [make_vulnerability(description="", vendor=None, product="   ")]
    )
    existing = get_one(isolated_storage)

    assert result.unchanged_count == 1
    assert existing.description == "Original description"
    assert existing.vendor == "Original Vendor"
    assert existing.product == "Original Product"


def test_no_cve_record_is_deduplicated_by_identity(isolated_storage) -> None:
    vulnerability = make_vulnerability(cve_id=None)
    storage.save_vulnerabilities([vulnerability])
    result = storage.save_vulnerabilities([vulnerability])

    assert result.inserted_count == 0
    assert result.unchanged_count == 1


def test_empty_cve_string_is_normalized_to_none(isolated_storage) -> None:
    result = storage.save_vulnerabilities(
        [
            make_vulnerability(cve_id=""),
            make_vulnerability(cve_id="   "),
        ]
    )

    assert result.inserted_count == 1
    assert result.unchanged_count == 1
    assert get_one(isolated_storage).cve_id is None


def test_cve_id_is_normalized_before_matching(isolated_storage) -> None:
    storage.save_vulnerabilities([make_vulnerability(cve_id=" cve-2099-0001 ")])
    result = storage.save_vulnerabilities([make_vulnerability(cve_id="CVE-2099-0001")])
    existing = get_one(isolated_storage)

    assert result.unchanged_count == 1
    assert existing.cve_id == "CVE-2099-0001"


def test_duplicate_differently_cased_cves_do_not_create_two_rows(
    isolated_storage,
) -> None:
    result = storage.save_vulnerabilities(
        [
            make_vulnerability(cve_id="cve-2099-0001"),
            make_vulnerability(cve_id="CVE-2099-0001"),
        ]
    )

    assert result.inserted_count == 1
    assert result.unchanged_count == 1
    assert count_rows(isolated_storage) == 1


def test_no_cve_none_and_empty_source_url_deduplicate(isolated_storage) -> None:
    result = storage.save_vulnerabilities(
        [
            make_vulnerability(cve_id=None, source_url=None),
            make_vulnerability(cve_id=None, source_url=""),
        ]
    )

    assert result.inserted_count == 1
    assert result.unchanged_count == 1
    assert get_one(isolated_storage).source_url is None


def test_no_cve_source_and_title_are_stripped_for_identity(isolated_storage) -> None:
    result = storage.save_vulnerabilities(
        [
            make_vulnerability(
                cve_id=None,
                source=" test ",
                title=" Test Vulnerability ",
            ),
            make_vulnerability(cve_id=None, source="test", title="Test Vulnerability"),
        ]
    )

    assert result.inserted_count == 1
    assert result.unchanged_count == 1


def test_different_no_cve_records_can_both_be_inserted(isolated_storage) -> None:
    result = storage.save_vulnerabilities(
        [
            make_vulnerability(cve_id=None, title="First"),
            make_vulnerability(cve_id=None, title="Second"),
        ]
    )

    assert result.inserted_count == 2


def test_database_rejects_duplicate_non_null_cve_id(isolated_storage) -> None:
    session = isolated_storage()
    try:
        session.add(Vulnerability(**make_vulnerability().__dict__))
        session.add(Vulnerability(**make_vulnerability().__dict__))
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.close()


def test_database_rejects_duplicate_no_cve_identity(isolated_storage) -> None:
    session = isolated_storage()
    try:
        session.add(
            Vulnerability(**make_vulnerability(cve_id=None, source_url=None).__dict__)
        )
        session.add(
            Vulnerability(**make_vulnerability(cve_id=None, source_url=None).__dict__)
        )
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.close()


def test_integrity_error_race_leaves_storage_recoverable(
    monkeypatch,
    isolated_storage,
) -> None:
    storage.save_vulnerabilities([make_vulnerability()])
    original_find_existing = storage._find_existing
    call_count = 0

    def flaky_find_existing(
        session: Session,
        vulnerability: NormalizedVulnerability,
    ) -> Vulnerability | None:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return None
        return original_find_existing(session, vulnerability)

    monkeypatch.setattr(storage, "_find_existing", flaky_find_existing)

    result = storage.save_vulnerabilities(
        [
            make_vulnerability(),
            make_vulnerability(cve_id="CVE-2099-0002"),
        ]
    )

    assert result.inserted_count == 1
    assert result.unchanged_count == 1
    assert count_rows(isolated_storage) == 2


def test_created_at_is_preserved_during_update(isolated_storage) -> None:
    storage.save_vulnerabilities([make_vulnerability()])
    original_created_at = get_one(isolated_storage).created_at

    result = storage.save_vulnerabilities([make_vulnerability(description="Changed")])
    updated_created_at = get_one(isolated_storage).created_at

    assert result.updated_count == 1
    assert updated_created_at == original_created_at


def test_modified_at_exists_on_insert(isolated_storage) -> None:
    storage.save_vulnerabilities([make_vulnerability()])
    existing = get_one(isolated_storage)

    assert existing.modified_at is not None


def test_local_audit_columns_are_configured_timezone_aware() -> None:
    assert Vulnerability.__table__.c.created_at.type.timezone is True
    assert Vulnerability.__table__.c.modified_at.type.timezone is True
