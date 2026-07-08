from database.models import Base
from database.session import engine


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
