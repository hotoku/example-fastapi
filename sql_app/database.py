from enum import auto
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import attribute_mapped_collection, sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# SessionLocalとBaseは、動的に作られたclass
SessionLocal = sessionmaker(autoflush=False, bind=engine)
Base = declarative_base()
