from loguru import logger

from agents.base import BaseAgent
from collectors.base import BaseCollector
from collectors.dummy import DummyCollector


class CollectorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="collector")
        self.collectors: list[BaseCollector] = [DummyCollector()]
        logger.info("CollectorAgent initialized")
        logger.info(f"CollectorAgent collector count: {len(self.collectors)}")

    def run(self) -> None:
        logger.info("CollectorAgent run started")
        for collector in self.collectors:
            raw_items = collector.fetch()
            logger.info(f"{collector.name} fetched {len(raw_items)} raw advisories")
            vulnerabilities = collector.normalize(raw_items)
            logger.info(
                f"{collector.name} normalized {len(vulnerabilities)} vulnerabilities"
            )
        logger.info("CollectorAgent run completed")
