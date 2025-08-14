import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# Local default = SQLite file. In production, set env var DATABASE_URL to your Postgres URL.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///codestan.db")

engine = create_engine(DATABASE_URL, echo=False, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

class Base(DeclarativeBase):
    pass
