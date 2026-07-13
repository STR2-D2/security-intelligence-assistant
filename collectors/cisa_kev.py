from datetime import datetime
from typing import Any

import httpx
from loguru import logger

from collectors.base import BaseCollector, NormalizedVulnerability, RawAdvisory


CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
USER_AGENT = "Security Intelligence Assistant/0.1 (+https://github.com/STR2-D2/security-intelligence-assistant)"


class CisaKevCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__(name="cisa_kev")

    def fetch(self) -> list[RawAdvisory]:
        logger.info("CISA KEV fetch start")
        response = httpx.get(
            FEED_URL,
            headers={"User-Agent": USER_AGENT},
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities")

        if not isinstance(vulnerabilities, list):
            raise ValueError("CISA KEV feed is missing a vulnerabilities list")

        logger.info(f"CISA KEV downloaded entry count: {len(vulnerabilities)}")

        return [
            RawAdvisory(
                source=self.name,
                title=str(entry.get("vulnerabilityName") or ""),
                url=CATALOG_URL,
                published_at=_parse_date(entry.get("dateAdded")),
                raw_data=entry,
            )
            for entry in vulnerabilities
            if isinstance(entry, dict)
        ]

    def normalize(
        self,
        raw_items: list[RawAdvisory],
    ) -> list[NormalizedVulnerability]:
        return [
            NormalizedVulnerability(
                source=self.name,
                source_url=raw.url,
                cve_id=_optional_text(raw.raw_data.get("cveID")),
                title=_optional_text(raw.raw_data.get("vulnerabilityName")) or raw.title,
                description=_build_description(raw.raw_data),
                vendor=_optional_text(raw.raw_data.get("vendorProject")),
                product=_optional_text(raw.raw_data.get("product")),
                severity=None,
                cvss_score=None,
                published_at=_parse_date(raw.raw_data.get("dateAdded")),
                updated_at=None,
                has_poc=False,
                in_kev=True,
                ai_summary=None,
                status="new",
            )
            for raw in raw_items
        ]


def _parse_date(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d")
    except ValueError:
        return None


def _optional_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _build_description(entry: dict[str, Any]) -> str | None:
    fields = [
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
        "notes",
    ]
    parts = [
        f"{field}: {value.strip()}"
        for field in fields
        if isinstance(value := entry.get(field), str) and value.strip()
    ]
    return "\n".join(parts) if parts else None
