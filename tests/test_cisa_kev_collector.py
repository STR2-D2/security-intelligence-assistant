import json
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from collectors.cisa_kev import CATALOG_URL, FEED_URL, CisaKevCollector, _parse_date


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "cisa_kev_sample.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def make_response(status_code: int, json_data: dict) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=json_data,
        request=httpx.Request("GET", FEED_URL),
    )


def test_successful_fetch_returns_two_raw_advisories(monkeypatch) -> None:
    def fake_get(url: str, headers: dict[str, str], timeout: int) -> httpx.Response:
        assert url == FEED_URL
        assert timeout == 30
        assert "Security Intelligence Assistant" in headers["User-Agent"]
        return make_response(200, load_fixture())

    monkeypatch.setattr("httpx.get", fake_get)

    raw_items = CisaKevCollector().fetch()

    assert len(raw_items) == 2
    assert raw_items[0].source == "cisa_kev"
    assert raw_items[0].title == "Example Product Command Injection Vulnerability"
    assert raw_items[0].url == CATALOG_URL
    assert raw_items[0].published_at == datetime(2024, 1, 15)
    assert raw_items[0].raw_data["cveID"] == "CVE-2024-0001"


def test_normalize_maps_cve_vendor_product_and_description(monkeypatch) -> None:
    monkeypatch.setattr(
        "httpx.get",
        lambda *args, **kwargs: make_response(200, load_fixture()),
    )

    raw_items = CisaKevCollector().fetch()
    vulnerabilities = CisaKevCollector().normalize(raw_items)

    assert vulnerabilities[0].cve_id == "CVE-2024-0001"
    assert vulnerabilities[0].vendor == "Example Vendor"
    assert vulnerabilities[0].product == "Example Product"
    assert vulnerabilities[0].in_kev is True
    assert vulnerabilities[0].published_at == datetime(2024, 1, 15)
    assert vulnerabilities[0].description is not None
    assert "Apply updates per vendor instructions." in vulnerabilities[0].description


def test_invalid_date_returns_none() -> None:
    assert _parse_date("not-a-date") is None
    assert _parse_date("") is None
    assert _parse_date(None) is None


def test_missing_vulnerabilities_raises_value_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "httpx.get",
        lambda *args, **kwargs: make_response(200, {"title": "missing"}),
    )

    with pytest.raises(ValueError):
        CisaKevCollector().fetch()


def test_non_list_vulnerabilities_raises_value_error(monkeypatch) -> None:
    monkeypatch.setattr(
        "httpx.get",
        lambda *args, **kwargs: make_response(200, {"vulnerabilities": {}}),
    )

    with pytest.raises(ValueError):
        CisaKevCollector().fetch()


def test_http_errors_propagate(monkeypatch) -> None:
    request = httpx.Request("GET", FEED_URL)
    response = httpx.Response(500, request=request)
    monkeypatch.setattr("httpx.get", lambda *args, **kwargs: response)

    with pytest.raises(httpx.HTTPStatusError):
        CisaKevCollector().fetch()
