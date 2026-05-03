from sqlalchemy import Column, String, JSON, DateTime
from datetime import datetime
try:
    from backend.config import Base
except ImportError:
    from .config import Base

class Event(Base):
    __tablename__ = "events"

    id = Column(String, primary_key=True)
    event_type = Column(String)
    raw_payload = Column(JSON)
    repo = Column(String)
    branch = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    files = Column(JSON)   

    def __str__(self):
        return f"<Event(id={self.id}, event_type={self.event_type}, repo={self.repo}, branch={self.branch})>"

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    event_id = Column(String)
    repo = Column(String)
    file_path = Column(String)
    rule_name = Column(String)
    severity = Column(String)
    match = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
