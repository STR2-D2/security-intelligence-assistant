from dataclasses import dataclass

from collectors.base import BaseCollector
from skills import storage
from skills.validator import validate_vulnerabilities


@dataclass(frozen=True)
class PipelineResult:
    collector_name: str
    fetched_count: int
    normalized_count: int
    valid_count: int
    rejected_count: int
    inserted_count: int


class CollectorPipeline:
    def __init__(self, collector: BaseCollector) -> None:
        self.collector = collector

    def run(self) -> PipelineResult:
        raw_items = self.collector.fetch()
        vulnerabilities = self.collector.normalize(raw_items)
        valid_items, rejected_items = validate_vulnerabilities(vulnerabilities)
        inserted_count = storage.save_vulnerabilities(valid_items)

        return PipelineResult(
            collector_name=self.collector.name,
            fetched_count=len(raw_items),
            normalized_count=len(vulnerabilities),
            valid_count=len(valid_items),
            rejected_count=len(rejected_items),
            inserted_count=inserted_count,
        )
