"""
scheduler_service.py — Simple asyncio-based audit scheduler.

Stores jobs in SQLite. A background task (started in main.py lifespan)
calls tick() every 60 seconds to dispatch overdue jobs.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from database import AsyncSessionLocal
from models import ScheduledJob

AUDIT_LABELS = {
    "safe-audit":  "Auditoría completa",
    "bloodhound":  "BloodHound collect",
    "ldap-check":  "LDAP enumeration",
    "dns-check":   "DNS check",
}


class SchedulerService:
    # ── CRUD ──────────────────────────────────────────────────────────

    async def list_jobs(self) -> list[dict[str, Any]]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScheduledJob).order_by(ScheduledJob.id)
            )
            jobs = result.scalars().all()
            return [self._serialize(j) for j in jobs]

    async def add_job(self, audit_type: str, interval_minutes: int, label: str = "") -> dict:
        if audit_type not in AUDIT_LABELS:
            raise ValueError(f"Unknown audit type: {audit_type}")
        if interval_minutes < 1:
            raise ValueError("interval_minutes must be >= 1")

        next_run = datetime.utcnow() + timedelta(minutes=interval_minutes)
        job = ScheduledJob(
            audit_type=audit_type,
            label=label or AUDIT_LABELS[audit_type],
            interval_minutes=interval_minutes,
            enabled=True,
            next_run=next_run,
        )
        async with AsyncSessionLocal() as session:
            session.add(job)
            await session.commit()
            await session.refresh(job)
            return self._serialize(job)

    async def toggle_job(self, job_id: int, enabled: bool) -> dict:
        async with AsyncSessionLocal() as session:
            job = await session.get(ScheduledJob, job_id)
            if not job:
                raise ValueError(f"Job {job_id} not found")
            job.enabled = enabled
            await session.commit()
            await session.refresh(job)
            return self._serialize(job)

    async def delete_job(self, job_id: int) -> None:
        async with AsyncSessionLocal() as session:
            job = await session.get(ScheduledJob, job_id)
            if job:
                await session.delete(job)
                await session.commit()

    # ── Background tick ───────────────────────────────────────────────

    async def tick(self, audit_svc) -> list[str]:
        """Called every 60 s. Runs overdue enabled jobs. Returns list of triggered types."""
        triggered: list[str] = []
        now = datetime.utcnow()

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(ScheduledJob).where(ScheduledJob.enabled == True)
            )
            jobs = result.scalars().all()

            for job in jobs:
                if job.next_run and job.next_run <= now:
                    # Fire and forget — do not await so tick returns quickly
                    asyncio.create_task(
                        _run_job(audit_svc, job.audit_type)
                    )
                    triggered.append(job.audit_type)
                    job.last_run = now
                    job.next_run = now + timedelta(minutes=job.interval_minutes)

            if triggered:
                await session.commit()

        return triggered

    # ── Helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _serialize(job: ScheduledJob) -> dict[str, Any]:
        return {
            "id":               job.id,
            "audit_type":       job.audit_type,
            "label":            job.label or AUDIT_LABELS.get(job.audit_type, job.audit_type),
            "interval_minutes": job.interval_minutes,
            "enabled":          job.enabled,
            "last_run":         job.last_run.isoformat() if job.last_run else None,
            "next_run":         job.next_run.isoformat() if job.next_run else None,
            "created_at":       job.created_at.isoformat() if job.created_at else None,
        }


async def _run_job(audit_svc, audit_type: str) -> None:
    """Consume the SSE generator fully (background execution, output discarded)."""
    try:
        async for _ in audit_svc.stream_script(audit_type):
            pass
    except Exception:
        pass
