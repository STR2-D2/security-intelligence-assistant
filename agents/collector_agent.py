from loguru import logger

from agents.base import BaseAgent


class CollectorAgent(BaseAgent):
    def __init__(self) -> None:
        super().__init__(name="collector")
        logger.info("CollectorAgent initialized")

    def run(self) -> None:
        logger.info("CollectorAgent run started")
        logger.info("CollectorAgent run completed")
