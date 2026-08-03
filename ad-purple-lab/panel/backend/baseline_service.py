"""
baseline_service.py — Manages saved audit baselines (CSV snapshots, live audits).
Stores analyzed results for later comparison and tracking.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal
from models import AuditBaseline


class BaselineService:
    """Manages saved audit baselines for comparison."""

    async def save_baseline(
        self,
        name: str,
        parsed_data: dict[str, Any],
        source: str = "csv",
        audit_type: str | None = None,
        tags: str = "",
    ) -> dict[str, Any]:
        """
        Save analyzed CSV or audit results as a reusable baseline.

        Args:
            name: Human-friendly baseline name (e.g., "AD Snapshot 2024-08-03")
            parsed_data: Full result dict from CsvImportService.analyze() or ResultsService.get_latest()
            source: "csv" or "live_audit"
            audit_type: "safe-audit", "ldap-check", etc.
            tags: Comma-separated tags for organization

        Returns:
            Dictionary with { id, name, source, created_at, summary }
        """
        async with AsyncSessionLocal() as db:
            # Generate summary from parsed_data
            stats = parsed_data.get("stats", {})
            summary = f"users: {stats.get('total_users', 0)}, computers: {stats.get('total_computers', 0)}, groups: {stats.get('total_groups', 0)}"

            # Serialize parsed_data to JSON
            parsed_json = json.dumps(parsed_data, default=str)

            baseline = AuditBaseline(
                name=name,
                source=source,
                audit_type=audit_type,
                imported_at=datetime.now(timezone.utc),
                parsed_data=parsed_json,
                file_count=len(parsed_data.get("files_detected", [])),
                summary=summary,
                tags=tags,
                is_locked=False,
            )

            db.add(baseline)
            await db.commit()
            await db.refresh(baseline)

            return {
                "id": baseline.id,
                "name": baseline.name,
                "source": baseline.source,
                "created_at": baseline.created_at.isoformat(),
                "summary": baseline.summary,
                "tags": baseline.tags,
            }

    async def list_baselines(self, limit: int = 50) -> dict[str, Any]:
        """List all saved baselines ordered by creation date (newest first)."""
        async with AsyncSessionLocal() as db:
            stmt = select(AuditBaseline).order_by(desc(AuditBaseline.created_at)).limit(limit)
            result = await db.execute(stmt)
            baselines = result.scalars().all()

            return {
                "baselines": [
                    {
                        "id": b.id,
                        "name": b.name,
                        "source": b.source,
                        "audit_type": b.audit_type,
                        "created_at": b.created_at.isoformat(),
                        "summary": b.summary,
                        "tags": b.tags,
                        "file_count": b.file_count,
                        "is_locked": b.is_locked,
                    }
                    for b in baselines
                ],
                "total": len(baselines),
            }

    async def get_baseline(self, baseline_id: int) -> dict[str, Any] | None:
        """Retrieve full baseline data by ID."""
        async with AsyncSessionLocal() as db:
            stmt = select(AuditBaseline).filter(AuditBaseline.id == baseline_id)
            result = await db.execute(stmt)
            baseline = result.scalar_one_or_none()

            if not baseline:
                return None

            # Parse JSON back to dict
            parsed_data = json.loads(baseline.parsed_data) if baseline.parsed_data else {}

            return {
                "id": baseline.id,
                "name": baseline.name,
                "source": baseline.source,
                "audit_type": baseline.audit_type,
                "created_at": baseline.created_at.isoformat(),
                "summary": baseline.summary,
                "tags": baseline.tags,
                **parsed_data,  # Include all parsed audit data (findings, users, computers, etc)
            }

    async def delete_baseline(self, baseline_id: int) -> dict[str, Any]:
        """Delete a baseline by ID (fails if locked)."""
        async with AsyncSessionLocal() as db:
            stmt = select(AuditBaseline).filter(AuditBaseline.id == baseline_id)
            result = await db.execute(stmt)
            baseline = result.scalar_one_or_none()

            if not baseline:
                return {"status": "error", "message": "Baseline not found"}

            if baseline.is_locked:
                return {"status": "error", "message": "Baseline is locked and cannot be deleted"}

            db.delete(baseline)
            await db.commit()

            return {"status": "deleted", "id": baseline_id, "name": baseline.name}

    async def update_baseline(
        self,
        baseline_id: int,
        name: str | None = None,
        tags: str | None = None,
        is_locked: bool | None = None,
    ) -> dict[str, Any]:
        """Update baseline metadata (not parsed data)."""
        async with AsyncSessionLocal() as db:
            stmt = select(AuditBaseline).filter(AuditBaseline.id == baseline_id)
            result = await db.execute(stmt)
            baseline = result.scalar_one_or_none()

            if not baseline:
                return {"status": "error", "message": "Baseline not found"}

            if name is not None:
                baseline.name = name
            if tags is not None:
                baseline.tags = tags
            if is_locked is not None:
                baseline.is_locked = is_locked

            await db.commit()
            await db.refresh(baseline)

            return {
                "status": "updated",
                "id": baseline.id,
                "name": baseline.name,
                "tags": baseline.tags,
                "is_locked": baseline.is_locked,
            }
