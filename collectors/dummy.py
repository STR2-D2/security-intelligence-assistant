from datetime import datetime

from collectors.base import BaseCollector, NormalizedVulnerability, RawAdvisory


class DummyCollector(BaseCollector):
    def __init__(self) -> None:
        super().__init__(name="dummy")

    def fetch(self) -> list[RawAdvisory]:
        return [
            RawAdvisory(
                source=self.name,
                title="Dummy vulnerability advisory",
                url="https://example.com/advisories/dummy",
                published_at=datetime.utcnow(),
                raw_data={"severity": "low"},
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
                description="Dummy advisory for collector pipeline validation.",
                vendor="Dummy Vendor",
                product="Dummy Product",
                severity=raw.raw_data.get("severity"),
                cvss_score=None,
                published_at=raw.published_at,
                updated_at=None,
            )
            for raw in raw_items
        ]

