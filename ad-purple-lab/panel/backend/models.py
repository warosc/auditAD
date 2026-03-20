from sqlalchemy import Column, Integer, String, DateTime, Text, Float, Boolean
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime


class Base(DeclarativeBase):
    pass


class AuditRun(Base):
    __tablename__ = "audit_runs"

    id = Column(Integer, primary_key=True, index=True)
    audit_type = Column(String(50), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="running")
    exit_code = Column(Integer, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    output_summary = Column(Text, nullable=True)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    filepath = Column(String(500), nullable=False)
    size_bytes = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    report_type = Column(String(50), nullable=True)


class Setting(Base):
    """Key-value store for all panel-configurable settings."""
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, default="")
    updated_at = Column(DateTime, default=datetime.utcnow)


class ScheduledJob(Base):
    """Scheduled audit jobs — polled every minute by background task."""
    __tablename__ = "scheduled_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_type = Column(String(50), nullable=False)   # safe-audit, bloodhound, ldap-check…
    label = Column(String(100), nullable=True)
    interval_minutes = Column(Integer, nullable=False)
    enabled = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
