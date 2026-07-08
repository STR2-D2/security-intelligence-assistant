from loguru import logger

from agents.collector_agent import CollectorAgent
from app.config import settings
from app.logging import setup_logging
from database.init_db import init_db


def main() -> None:
    setup_logging(settings.log_level)
    logger.info(f"{settings.app_name} started")
    init_db()
    logger.info("Database initialized")
    collector = CollectorAgent()
    collector.run()


if __name__ == "__main__":
    main()
