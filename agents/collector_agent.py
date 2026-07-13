from loguru import logger

from agents.base import BaseAgent
from collectors.base import BaseCollector
from collectors.cisa_kev import CisaKevCollector
from pipeline.collector_pipeline import CollectorPipeline


class CollectorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="collector")
        self.collectors: list[BaseCollector] = [CisaKevCollector()]
        logger.info("CollectorAgent initialized")
        logger.info(f"CollectorAgent collector count: {len(self.collectors)}")

    def run(self) -> None:
        logger.info("CollectorAgent run started")
        total_fetched = 0
        total_normalized = 0
        total_rejected = 0
        total_inserted = 0
        total_updated = 0
        total_unchanged = 0

        for collector in self.collectors:
            try:
                result = CollectorPipeline(collector).run()
            except Exception as exc:
                logger.exception(f"{collector.name} pipeline failed: {exc}")
                continue

            total_fetched += result.fetched_count
            total_normalized += result.normalized_count
            total_rejected += result.rejected_count
            total_inserted += result.inserted_count
            total_updated += result.updated_count
            total_unchanged += result.unchanged_count

            logger.info(
                f"{result.collector_name} pipeline result: "
                f"fetched={result.fetched_count}, "
                f"normalized={result.normalized_count}, "
                f"valid={result.valid_count}, "
                f"rejected={result.rejected_count}, "
                f"inserted={result.inserted_count}, "
                f"updated={result.updated_count}, "
                f"unchanged={result.unchanged_count}"
            )

        logger.info(
            "CollectorAgent totals: "
            f"fetched={total_fetched}, "
            f"normalized={total_normalized}, "
            f"rejected={total_rejected}, "
            f"inserted={total_inserted}, "
            f"updated={total_updated}, "
            f"unchanged={total_unchanged}"
        )
        logger.info("CollectorAgent run completed")
