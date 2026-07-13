from loguru import logger

from agents.base import BaseAgent
from collectors.base import BaseCollector
from collectors.dummy import DummyCollector
from skills.storage import save_vulnerabilities


class CollectorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="collector")
        self.collectors: list[BaseCollector] = [DummyCollector()]
        logger.info("CollectorAgent initialized")
        logger.info(f"CollectorAgent collector count: {len(self.collectors)}")

    def run(self) -> None:
        logger.info("CollectorAgent run started")
        total_inserted = 0
        for collector in self.collectors:
            raw_items = collector.fetch()
            logger.info(f"{collector.name} fetched {len(raw_items)} raw advisories")
            vulnerabilities = collector.normalize(raw_items)
            logger.info(
                f"{collector.name} normalized {len(vulnerabilities)} vulnerabilities"
            )
            inserted_count = save_vulnerabilities(vulnerabilities)
            total_inserted += inserted_count
            logger.info(f"{collector.name} inserted {inserted_count} vulnerabilities")
        logger.info(f"CollectorAgent total inserted: {total_inserted}")
        logger.info("CollectorAgent run completed")
