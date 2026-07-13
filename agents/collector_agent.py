from loguru import logger

from agents.base import BaseAgent
from collectors.base import BaseCollector
from collectors.dummy import DummyCollector
from pipeline.collector_pipeline import CollectorPipeline


class CollectorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="collector")
        self.collectors: list[BaseCollector] = [DummyCollector()]
        logger.info("CollectorAgent initialized")
        logger.info(f"CollectorAgent collector count: {len(self.collectors)}")

    def run(self) -> None:
        logger.info("CollectorAgent run started")
        total_fetched = 0
        total_normalized = 0
        total_rejected = 0
        total_inserted = 0

        for collector in self.collectors:
            result = CollectorPipeline(collector).run()
            total_fetched += result.fetched_count
            total_normalized += result.normalized_count
            total_rejected += result.rejected_count
            total_inserted += result.inserted_count

            logger.info(
                f"{result.collector_name} pipeline result: "
                f"fetched={result.fetched_count}, "
                f"normalized={result.normalized_count}, "
                f"valid={result.valid_count}, "
                f"rejected={result.rejected_count}, "
                f"inserted={result.inserted_count}"
            )

        logger.info(
            "CollectorAgent totals: "
            f"fetched={total_fetched}, "
            f"normalized={total_normalized}, "
            f"rejected={total_rejected}, "
            f"inserted={total_inserted}"
        )
        logger.info("CollectorAgent run completed")
