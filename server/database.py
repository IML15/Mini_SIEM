from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./minisiem.db"

engine_db = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine_db)
Base = declarative_base()


class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    rule_id = Column(String, index=True)
    rule_name = Column(String)
    severity = Column(String)
    entity = Column(String, index=True)
    count = Column(Integer)
    description = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Crear tablas automáticamente al iniciar
def init_db():
    Base.metadata.create_all(bind=engine_db)