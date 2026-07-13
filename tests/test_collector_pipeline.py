from datetime import UTC, datetime

from collectors.base import BaseCollector, NormalizedVulnerability, RawAdvisory
from pipeline.collector_pipeline import CollectorPipeline


class FakeCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__(name="fake")

    def fetch(self) -> list[RawAdvisory]:
        return [
            RawAdvisory(
                source=self.name,
                title="Fake advisory",
                url="https://example.com/fake",
                published_at=datetime.now(UTC),
                raw_data={},
            )
        ]

    def normalize(
        self,
        raw_items: list[RawAdvisory],
    ) -> list[NormalizedVulnerability]:
        return [
            NormalizedVulnerability(
                source=raw.source,
                source_url=raw.url,
                cve_id=None,
                title=raw.title,
                description=None,
                vendor=None,
                product=None,
                severity=None,
                cvss_score=4.0,
                published_at=raw.published_at,
                updated_at=None,
            )
            for raw in raw_items
        ]


def test_collector_pipeline_counts(monkeypatch) -> None:
    def fake_save(vulnerabilities: list[NormalizedVulnerability]) -> int:
        return len(vulnerabilities)

    monkeypatch.setattr("skills.storage.save_vulnerabilities", fake_save)

    result = CollectorPipeline(FakeCollector()).run()

    assert result.collector_name == "fake"
    assert result.fetched_count == 1
    assert result.normalized_count == 1
    assert result.valid_count == 1
    assert result.rejected_count == 0
    assert result.inserted_count == 1
