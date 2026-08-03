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


class AuditBaseline(Base):
    """Saved CSV or live audit snapshots for comparison."""
    __tablename__ = "audit_baselines"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    source = Column(String(20), default="csv")  # "csv" or "live_audit"
    audit_type = Column(String(50), nullable=True)  # "safe-audit", "ldap-check", etc
    created_at = Column(DateTime, default=datetime.utcnow)
    imported_at = Column(DateTime, nullable=True)
    parsed_data = Column(Text, nullable=True)  # JSON serialized result
    file_count = Column(Integer, default=0)
    summary = Column(Text, default="")  # Quick stats: "users: 150, computers: 45, groups: 20"
    tags = Column(String(255), default="")  # Comma-separated tags
    is_locked = Column(Boolean, default=False)  # Prevent accidental deletion


class AuditComparison(Base):
    """Comparison results between two audit baselines."""
    __tablename__ = "audit_comparisons"

    id = Column(Integer, primary_key=True, index=True)
    baseline1_id = Column(Integer, nullable=False)  # FK to AuditBaseline
    baseline2_id = Column(Integer, nullable=False)  # FK to AuditBaseline
    baseline1_name = Column(String(100), nullable=False)
    baseline2_name = Column(String(100), nullable=False)
    comparison_type = Column(String(30), default="baseline_vs_baseline")  # "baseline_vs_baseline", "live_vs_baseline"
    created_at = Column(DateTime, default=datetime.utcnow)
    delta_summary = Column(Text, nullable=True)  # JSON with cached diff summary
    user_action = Column(String(100), default="manual")  # Who/what triggered comparison
    stats_users_added = Column(Integer, default=0)
    stats_users_removed = Column(Integer, default=0)
    stats_users_modified = Column(Integer, default=0)
    stats_computers_added = Column(Integer, default=0)
    stats_computers_removed = Column(Integer, default=0)
    stats_groups_modified = Column(Integer, default=0)
