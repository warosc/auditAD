"""
audit_comparison_service.py — Compares two audit baselines and generates delta reports.
Shows what changed between two snapshots (users, computers, groups, policies).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from database import AsyncSessionLocal
from models import AuditComparison


class AuditComparisonService:
    """Compares two audit baselines and generates delta reports."""

    @staticmethod
    def _compare_users(users1: list[dict], users2: list[dict]) -> dict[str, Any]:
        """Compare user lists between two baselines."""
        sam_map1 = {u["sam"]: u for u in users1}
        sam_map2 = {u["sam"]: u for u in users2}

        new_users = [u for sam, u in sam_map2.items() if sam not in sam_map1]
        removed_users = [u for sam, u in sam_map1.items() if sam not in sam_map2]

        modified_users = []
        for sam, u2 in sam_map2.items():
            if sam in sam_map1:
                u1 = sam_map1[sam]
                changes = {}
                if u1.get("disabled") != u2.get("disabled"):
                    changes["disabled"] = [u1.get("disabled"), u2.get("disabled")]
                if u1.get("no_expire") != u2.get("no_expire"):
                    changes["no_expire"] = [u1.get("no_expire"), u2.get("no_expire")]
                if u1.get("no_preauth") != u2.get("no_preauth"):
                    changes["no_preauth"] = [u1.get("no_preauth"), u2.get("no_preauth")]
                if u1.get("pwd_not_req") != u2.get("pwd_not_req"):
                    changes["pwd_not_req"] = [u1.get("pwd_not_req"), u2.get("pwd_not_req")]
                if changes:
                    modified_users.append({"sam": sam, "changes": changes})

        return {
            "new": new_users,
            "removed": removed_users,
            "modified": modified_users,
            "counts": {
                "new": len(new_users),
                "removed": len(removed_users),
                "modified": len(modified_users),
            },
        }

    @staticmethod
    def _compare_computers(comps1: list[dict], comps2: list[dict]) -> dict[str, Any]:
        """Compare computer lists."""
        name_map1 = {c["name"]: c for c in comps1}
        name_map2 = {c["name"]: c for c in comps2}

        new_comps = [c for name, c in name_map2.items() if name not in name_map1]
        removed_comps = [c for name, c in name_map1.items() if name not in name_map2]

        modified_comps = []
        for name, c2 in name_map2.items():
            if name in name_map1:
                c1 = name_map1[name]
                changes = {}
                if c1.get("enabled") != c2.get("enabled"):
                    changes["enabled"] = [c1.get("enabled"), c2.get("enabled")]
                if c1.get("os") != c2.get("os"):
                    changes["os"] = [c1.get("os"), c2.get("os")]
                if changes:
                    modified_comps.append({"name": name, "changes": changes})

        return {
            "new": new_comps,
            "removed": removed_comps,
            "modified": modified_comps,
            "counts": {
                "new": len(new_comps),
                "removed": len(removed_comps),
                "modified": len(modified_comps),
            },
        }

    @staticmethod
    def _compare_groups(groups1: list[dict], groups2: list[dict]) -> dict[str, Any]:
        """Compare group lists."""
        name_map1 = {g["name"]: g for g in groups1}
        name_map2 = {g["name"]: g for g in groups2}

        new_groups = [g for name, g in name_map2.items() if name not in name_map1]
        removed_groups = [g for name, g in name_map1.items() if name not in name_map2]

        modified_groups = []
        for name, g2 in name_map2.items():
            if name in name_map1:
                g1 = name_map1[name]
                if g1.get("member_count") != g2.get("member_count"):
                    modified_groups.append({
                        "name": name,
                        "member_count_before": g1.get("member_count"),
                        "member_count_after": g2.get("member_count"),
                    })

        return {
            "new": new_groups,
            "removed": removed_groups,
            "modified": modified_groups,
            "counts": {
                "new": len(new_groups),
                "removed": len(removed_groups),
                "modified": len(modified_groups),
            },
        }

    @staticmethod
    def _compare_policies(policy1: dict, policy2: dict) -> dict[str, Any]:
        """Compare AD password policies."""
        changes = []
        all_keys = set(policy1.keys()) | set(policy2.keys())

        for key in all_keys:
            val1 = policy1.get(key)
            val2 = policy2.get(key)
            if val1 != val2:
                changes.append({
                    "key": key,
                    "before": val1,
                    "after": val2,
                })

        return {
            "changes": changes,
            "count": len(changes),
        }

    @staticmethod
    def _identify_security_deltas(comparison: dict[str, Any]) -> list[dict[str, Any]]:
        """Identify high-impact security changes."""
        deltas = []

        # Critical: Users disabled/enabled
        users_disabled = [u for u in comparison["users"]["removed"] if not u.get("disabled")]
        if users_disabled:
            deltas.append({
                "severity": "critical",
                "type": "users_removed",
                "count": len(users_disabled),
                "description": f"{len(users_disabled)} usuario(s) eliminado(s)",
                "examples": [u["sam"] for u in users_disabled[:3]],
            })

        # High: Privileged users modified
        priv_ous = {"Administradores", "Domain Admins", "Honeypots"}
        modified_priv = [
            u for u in comparison["users"]["modified"]
            if u.get("changes", {}).get("disabled")
        ]
        if modified_priv:
            deltas.append({
                "severity": "high",
                "type": "privileged_users_modified",
                "count": len(modified_priv),
                "description": f"{len(modified_priv)} usuario(s) privilegiado(s) modificado(s)",
                "examples": [u["sam"] for u in modified_priv[:3]],
            })

        # High: Computers removed
        if comparison["computers"]["removed"]:
            deltas.append({
                "severity": "high",
                "type": "computers_removed",
                "count": len(comparison["computers"]["removed"]),
                "description": f"{len(comparison['computers']['removed'])} equipo(s) eliminado(s)",
                "examples": [c["name"] for c in comparison["computers"]["removed"][:3]],
            })

        # Medium: Groups modified
        if comparison["groups"]["modified"]:
            deltas.append({
                "severity": "medium",
                "type": "groups_modified",
                "count": len(comparison["groups"]["modified"]),
                "description": f"{len(comparison['groups']['modified'])} grupo(s) modificado(s)",
            })

        # Info: Policy changes
        if comparison["policy"]["count"] > 0:
            deltas.append({
                "severity": "info",
                "type": "policy_changes",
                "count": comparison["policy"]["count"],
                "description": f"{comparison['policy']['count']} política(s) modificada(s)",
            })

        return deltas

    async def compare(self, baseline1_data: dict, baseline2_data: dict) -> dict[str, Any]:
        """
        Compare two baseline snapshots.

        Args:
            baseline1_data: First baseline (older snapshot)
            baseline2_data: Second baseline (newer snapshot)

        Returns:
            Comprehensive comparison report
        """
        users1 = baseline1_data.get("users", [])
        users2 = baseline2_data.get("users", [])

        comps1 = baseline1_data.get("computers", [])
        comps2 = baseline2_data.get("computers", [])

        groups1 = baseline1_data.get("groups", [])
        groups2 = baseline2_data.get("groups", [])

        policy1 = baseline1_data.get("policy", {})
        policy2 = baseline2_data.get("policy", {})

        comparison = {
            "users": self._compare_users(users1, users2),
            "computers": self._compare_computers(comps1, comps2),
            "groups": self._compare_groups(groups1, groups2),
            "policy": self._compare_policies(policy1, policy2),
        }

        security_deltas = self._identify_security_deltas(comparison)

        return {
            "baseline1": baseline1_data.get("timestamp", "unknown"),
            "baseline2": baseline2_data.get("timestamp", "unknown"),
            "comparison": comparison,
            "security_deltas": security_deltas,
            "summary": {
                "users_added": comparison["users"]["counts"]["new"],
                "users_removed": comparison["users"]["counts"]["removed"],
                "users_modified": comparison["users"]["counts"]["modified"],
                "computers_added": comparison["computers"]["counts"]["new"],
                "computers_removed": comparison["computers"]["counts"]["removed"],
                "groups_modified": comparison["groups"]["counts"]["modified"],
                "policy_changes": comparison["policy"]["count"],
            },
        }

    async def save_comparison(
        self,
        baseline1_id: int,
        baseline2_id: int,
        baseline1_name: str,
        baseline2_name: str,
        delta_data: dict[str, Any],
    ) -> dict[str, Any]:
        """Save comparison result to database."""
        async with AsyncSessionLocal() as db:
            summary = delta_data.get("summary", {})

            comparison = AuditComparison(
                baseline1_id=baseline1_id,
                baseline2_id=baseline2_id,
                baseline1_name=baseline1_name,
                baseline2_name=baseline2_name,
                comparison_type="baseline_vs_baseline",
                created_at=datetime.now(timezone.utc),
                delta_summary=json.dumps(delta_data, default=str),
                stats_users_added=summary.get("users_added", 0),
                stats_users_removed=summary.get("users_removed", 0),
                stats_users_modified=summary.get("users_modified", 0),
                stats_computers_added=summary.get("computers_added", 0),
                stats_computers_removed=summary.get("computers_removed", 0),
                stats_groups_modified=summary.get("groups_modified", 0),
            )

            db.add(comparison)
            await db.commit()
            await db.refresh(comparison)

            return {
                "id": comparison.id,
                "baseline1_id": comparison.baseline1_id,
                "baseline2_id": comparison.baseline2_id,
                "created_at": comparison.created_at.isoformat(),
            }

    async def get_comparison(self, comparison_id: int) -> dict[str, Any] | None:
        """Retrieve saved comparison by ID."""
        async with AsyncSessionLocal() as db:
            stmt = select(AuditComparison).filter(AuditComparison.id == comparison_id)
            result = await db.execute(stmt)
            comp = result.scalar_one_or_none()

            if not comp:
                return None

            delta_data = json.loads(comp.delta_summary) if comp.delta_summary else {}

            return {
                "id": comp.id,
                "baseline1_id": comp.baseline1_id,
                "baseline1_name": comp.baseline1_name,
                "baseline2_id": comp.baseline2_id,
                "baseline2_name": comp.baseline2_name,
                "created_at": comp.created_at.isoformat(),
                "stats": {
                    "users_added": comp.stats_users_added,
                    "users_removed": comp.stats_users_removed,
                    "users_modified": comp.stats_users_modified,
                    "computers_added": comp.stats_computers_added,
                    "computers_removed": comp.stats_computers_removed,
                    "groups_modified": comp.stats_groups_modified,
                },
                **delta_data,
            }

    async def list_comparisons(self, limit: int = 20) -> dict[str, Any]:
        """List recent comparisons."""
        async with AsyncSessionLocal() as db:
            stmt = select(AuditComparison).order_by(desc(AuditComparison.created_at)).limit(limit)
            result = await db.execute(stmt)
            comparisons = result.scalars().all()

            return {
                "comparisons": [
                    {
                        "id": c.id,
                        "baseline1_name": c.baseline1_name,
                        "baseline2_name": c.baseline2_name,
                        "created_at": c.created_at.isoformat(),
                        "summary": {
                            "users_added": c.stats_users_added,
                            "users_removed": c.stats_users_removed,
                            "computers_added": c.stats_computers_added,
                            "computers_removed": c.stats_computers_removed,
                        },
                    }
                    for c in comparisons
                ],
                "total": len(comparisons),
            }

    async def delete_comparison(self, comparison_id: int) -> dict[str, Any]:
        """Delete a comparison."""
        async with AsyncSessionLocal() as db:
            stmt = select(AuditComparison).filter(AuditComparison.id == comparison_id)
            result = await db.execute(stmt)
            comp = result.scalar_one_or_none()

            if not comp:
                return {"status": "error", "message": "Comparison not found"}

            db.delete(comp)
            await db.commit()

            return {"status": "deleted", "id": comparison_id}
