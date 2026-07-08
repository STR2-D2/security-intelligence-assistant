import sys

from loguru import logger


def setup_logging(log_level: str) -> None:
    logger.remove()
    logger.add(sys.stderr, level=log_level)
    logger.add(
        "logs/app.log",
        level=log_level,
        rotation="10 MB",
        retention="7 days",
    )
