from loguru import logger

from agents.collector_agent import CollectorAgent
from app.config import settings
from app.logging import setup_logging


def main() -> None:
    setup_logging(settings.log_level)
    logger.info(f"{settings.app_name} started")
    collector = CollectorAgent()
    collector.run()


if __name__ == "__main__":
    main()
