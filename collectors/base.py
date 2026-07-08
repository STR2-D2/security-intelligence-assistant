from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class RawAdvisory:
    source: str
    title: str
    url: str | None
    published_at: datetime | None
    raw_data: dict[str, Any]


@dataclass(frozen=True)
class NormalizedVulnerability:
    source: str
    source_url: str | None
    cve_id: str | None
    title: str
    description: str | None
    vendor: str | None
    product: str | None
    severity: str | None
    cvss_score: float | None
    published_at: datetime | None
    updated_at: datetime | None
    has_poc: bool = False
    in_kev: bool = False
    ai_summary: str | None = None
    status: str = "new"


class BaseCollector(ABC):
    name: str

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def fetch(self) -> list[RawAdvisory]:
        """Fetch raw advisory items."""

    @abstractmethod
    def normalize(
        self,
        raw_items: list[RawAdvisory],
    ) -> list[NormalizedVulnerability]:
        """Normalize raw advisory items."""

