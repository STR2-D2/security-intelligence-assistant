from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

import httpx
from loguru import logger

from app.config import settings as app_settings
from collectors.base import BaseCollector, NormalizedVulnerability, RawAdvisory


USER_AGENT = "Security Intelligence Assistant/0.1 (+https://github.com/STR2-D2/security-intelligence-assistant)"


class NvdSettings(Protocol):
    nvd_api_url: str
    nvd_api_key: str | None
    nvd_results_per_page: int
    nvd_request_delay_seconds: float
    nvd_lookback_days: int


class NvdCollector(BaseCollector):
    def __init__(
        self,
        settings: NvdSettings = app_settings,
        client: httpx.Client | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(name="nvd")
        self.settings = settings
        self.client = client or httpx.Client(transport=transport)
        self.sleep = sleep or __import__("time").sleep
        self.now = now or (lambda: datetime.now(UTC))

    def fetch(self) -> list[RawAdvisory]:
        start_date, end_date = self._date_range()
        start_index = 0
        total_results: int | None = None
        raw_items: list[RawAdvisory] = []

        logger.info("NVD fetch start")
        while total_results is None or start_index < total_results:
            data = self._fetch_page(start_index, start_date, end_date)
            vulnerabilities = data.get("vulnerabilities")
            total_results_value = data.get("totalResults")

            if not isinstance(vulnerabilities, list):
                raise ValueError("NVD response vulnerabilities must be a list")
            if not isinstance(total_results_value, int) or total_results_value < 0:
                raise ValueError("NVD response totalResults must be a non-negative integer")

            total_results = total_results_value
            raw_items.extend(self._to_raw_advisories(vulnerabilities))
            start_index += self.settings.nvd_results_per_page

            if start_index < total_results:
                self.sleep(self.settings.nvd_request_delay_seconds)

        logger.info(f"NVD downloaded entry count: {len(raw_items)}")
        return raw_items

    def normalize(
        self,
        raw_items: list[RawAdvisory],
    ) -> list[NormalizedVulnerability]:
        return [self._normalize_one(raw) for raw in raw_items]

    def _fetch_page(
        self,
        start_index: int,
        start_date: datetime,
        end_date: datetime,
    ) -> dict[str, Any]:
        headers = {"User-Agent": USER_AGENT}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key

        response = self.client.get(
            self.settings.nvd_api_url,
            params={
                "lastModStartDate": _format_nvd_datetime(start_date),
                "lastModEndDate": _format_nvd_datetime(end_date),
                "startIndex": start_index,
                "resultsPerPage": self.settings.nvd_results_per_page,
            },
            headers=headers,
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("NVD response must be a JSON object")
        return data

    def _date_range(self) -> tuple[datetime, datetime]:
        end_date = self.now()
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=UTC)
        end_date = end_date.astimezone(UTC)
        return end_date - timedelta(days=self.settings.nvd_lookback_days), end_date

    def _to_raw_advisories(
        self,
        vulnerabilities: list[Any],
    ) -> list[RawAdvisory]:
        raw_items: list[RawAdvisory] = []
        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue
            cve = item.get("cve")
            if not isinstance(cve, dict):
                continue
            cve_id = _optional_text(cve.get("id"))
            raw_items.append(
                RawAdvisory(
                    source=self.name,
                    title=cve_id or "",
                    url=_nvd_detail_url(cve_id),
                    published_at=_parse_nvd_datetime(cve.get("published")),
                    raw_data=item,
                )
            )
        return raw_items

    def _normalize_one(self, raw: RawAdvisory) -> NormalizedVulnerability:
        cve = raw.raw_data.get("cve")
        if not isinstance(cve, dict):
            cve = {}

        cve_id = _optional_text(cve.get("id"))
        description = _english_description(cve)
        cvss_score, severity = _extract_cvss(cve)

        return NormalizedVulnerability(
            source=self.name,
            source_url=_nvd_detail_url(cve_id),
            cve_id=cve_id,
            title=_title_for_cve(cve_id, description),
            description=description,
            vendor=None,
            product=None,
            severity=severity,
            cvss_score=cvss_score,
            published_at=_parse_nvd_datetime(cve.get("published")),
            updated_at=_parse_nvd_datetime(cve.get("lastModified")),
            has_poc=False,
            in_kev=False,
            ai_summary=None,
            status="new",
        )


def _format_nvd_datetime(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_nvd_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _optional_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None


def _nvd_detail_url(cve_id: str | None) -> str | None:
    if not cve_id:
        return None
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"


def _english_description(cve: dict[str, Any]) -> str | None:
    descriptions = cve.get("descriptions")
    if not isinstance(descriptions, list):
        return None
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        if str(item.get("lang", "")).lower() == "en":
            return _optional_text(item.get("value"))
    return None


def _title_for_cve(cve_id: str | None, description: str | None) -> str:
    if description and len(description) <= 140:
        return description
    return cve_id or "Unknown CVE"


def _extract_cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics")
    if not isinstance(metrics, dict):
        return None, None

    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_items = metrics.get(key)
        if not isinstance(metric_items, list):
            continue
        for metric in metric_items:
            score, severity = _extract_metric(metric)
            if score is not None or severity is not None:
                return score, severity
    return None, None


def _extract_metric(metric: Any) -> tuple[float | None, str | None]:
    if not isinstance(metric, dict):
        return None, None
    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        return None, _optional_text(metric.get("baseSeverity"))

    score = cvss_data.get("baseScore")
    if not isinstance(score, int | float):
        score = None
    severity = _optional_text(cvss_data.get("baseSeverity")) or _optional_text(
        metric.get("baseSeverity")
    )
    return float(score) if score is not None else None, severity
