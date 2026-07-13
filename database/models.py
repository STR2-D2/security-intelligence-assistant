from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, Index, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(255))
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_id: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
        index=True,
        unique=True,
    )
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    has_poc: Mapped[bool] = mapped_column(default=False)
    in_kev: Mapped[bool] = mapped_column(default=False)
    ai_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="new")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
    modified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    __table_args__ = (
        Index(
            "uq_vulnerabilities_no_cve_identity",
            source,
            title,
            func.coalesce(source_url, ""),
            unique=True,
            sqlite_where=cve_id.is_(None),
        ),
    )
