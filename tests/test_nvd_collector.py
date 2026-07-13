import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from collectors.nvd import NvdCollector, _parse_nvd_datetime


FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class FakeSettings:
    nvd_api_url: str = "https://example.test/nvd"
    nvd_api_key: str | None = None
    nvd_results_per_page: int = 1
    nvd_request_delay_seconds: float = 0.01
    nvd_lookback_days: int = 7


class FakeClient:
    def __init__(self, responses: list[httpx.Response]) -> None:
        self.responses = responses
        self.calls: list[dict] = []

    def get(self, url, params, headers, timeout):
        self.calls.append(
            {
                "url": url,
                "params": params,
                "headers": headers,
                "timeout": timeout,
            }
        )
        return self.responses.pop(0)


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def make_response(data: dict, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        json=data,
        request=httpx.Request("GET", "https://example.test/nvd"),
    )


def make_collector(
    responses: list[httpx.Response],
    settings: FakeSettings | None = None,
    sleeps: list[float] | None = None,
) -> tuple[NvdCollector, FakeClient, list[float]]:
    sleep_calls = sleeps if sleeps is not None else []
    client = FakeClient(responses)
    collector = NvdCollector(
        settings=settings or FakeSettings(),
        client=client,  # type: ignore[arg-type]
        sleep=sleep_calls.append,
        now=lambda: datetime(2100, 1, 1, tzinfo=UTC),
    )
    return collector, client, sleep_calls


def test_successful_single_page_fetch() -> None:
    data = load_fixture("nvd_page_1.json")
    data["totalResults"] = 1
    collector, client, sleeps = make_collector([make_response(data)])

    raw_items = collector.fetch()

    assert len(raw_items) == 1
    assert raw_items[0].source == "nvd"
    assert raw_items[0].title == "CVE-2099-0001"
    assert raw_items[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"
    assert raw_items[0].raw_data == data["vulnerabilities"][0]
    assert client.calls[0]["timeout"] == 30
    assert sleeps == []


def test_multi_page_pagination_and_start_index_changes() -> None:
    collector, client, sleeps = make_collector(
        [
            make_response(load_fixture("nvd_page_1.json")),
            make_response(load_fixture("nvd_page_2.json")),
        ]
    )

    raw_items = collector.fetch()

    assert len(raw_items) == 2
    assert [call["params"]["startIndex"] for call in client.calls] == [0, 1]
    assert sleeps == [0.01]


def test_api_key_header_when_configured() -> None:
    settings = FakeSettings(nvd_api_key="secret")
    collector, client, _ = make_collector(
        [make_response({**load_fixture("nvd_page_1.json"), "totalResults": 1})],
        settings=settings,
    )

    collector.fetch()

    assert client.calls[0]["headers"]["apiKey"] == "secret"


def test_no_api_key_header_when_absent() -> None:
    collector, client, _ = make_collector(
        [make_response({**load_fixture("nvd_page_1.json"), "totalResults": 1})]
    )

    collector.fetch()

    assert "apiKey" not in client.calls[0]["headers"]


def test_malformed_vulnerabilities_field_raises_value_error() -> None:
    collector, _, _ = make_collector(
        [make_response({"totalResults": 1, "vulnerabilities": {}})]
    )

    with pytest.raises(ValueError):
        collector.fetch()


def test_malformed_total_results_raises_value_error() -> None:
    collector, _, _ = make_collector(
        [make_response({"totalResults": -1, "vulnerabilities": []})]
    )

    with pytest.raises(ValueError):
        collector.fetch()


def test_http_errors_propagate() -> None:
    collector, _, _ = make_collector([make_response({}, status_code=500)])

    with pytest.raises(httpx.HTTPStatusError):
        collector.fetch()


def test_normalize_maps_cve_description_dates_and_cvss_v4_priority() -> None:
    data = load_fixture("nvd_page_1.json")
    data["totalResults"] = 1
    collector, _, _ = make_collector([make_response(data)])
    vulnerability = collector.normalize(collector.fetch())[0]

    assert vulnerability.cve_id == "CVE-2099-0001"
    assert vulnerability.title == "Short English NVD description."
    assert vulnerability.description == "Short English NVD description."
    assert vulnerability.published_at == datetime(2099, 1, 1, tzinfo=UTC)
    assert vulnerability.updated_at == datetime(2099, 1, 2, 3, 4, 5, tzinfo=UTC)
    assert vulnerability.cvss_score == 9.9
    assert vulnerability.severity == "CRITICAL"


def test_cvss_v31_fallback() -> None:
    data = load_fixture("nvd_page_2.json")
    data["totalResults"] = 1
    collector, _, _ = make_collector([make_response(data)])
    vulnerability = collector.normalize(collector.fetch())[0]

    assert vulnerability.cvss_score == 8.1
    assert vulnerability.severity == "HIGH"


def test_cvss_v2_fallback_and_malformed_metrics_do_not_crash() -> None:
    data = {
        "totalResults": 1,
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2099-0003",
                    "published": "invalid",
                    "lastModified": "invalid",
                    "descriptions": [{"lang": "en", "value": "V2 description"}],
                    "metrics": {
                        "cvssMetricV40": [{"bad": "metric"}],
                        "cvssMetricV2": [
                            {"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}
                        ],
                    },
                }
            }
        ],
    }
    collector, _, _ = make_collector([make_response(data)])
    vulnerability = collector.normalize(collector.fetch())[0]

    assert vulnerability.published_at is None
    assert vulnerability.updated_at is None
    assert vulnerability.cvss_score == 5.0
    assert vulnerability.severity == "MEDIUM"


def test_invalid_date_returns_none() -> None:
    assert _parse_nvd_datetime("not-a-date") is None
    assert _parse_nvd_datetime("") is None
    assert _parse_nvd_datetime(None) is None
