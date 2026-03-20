"""
health_service.py — Checks health of all lab services over HTTP
and retrieves Docker container states.
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx


ENDPOINTS: dict[str, str] = {
    "opensearch":            "http://opensearch:9200/_cluster/health",
    "grafana":               "http://grafana:3000/api/health",
    "neo4j":                 "http://neo4j:7474",
    "opensearch-dashboards": "http://opensearch-dashboards:5601/api/status",
}


async def _probe(name: str, url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
            body: dict[str, Any] = {"status": "up", "http_code": resp.status_code}

            if name == "opensearch":
                data = resp.json()
                body["cluster_status"] = data.get("status", "?")
                body["shards"] = {
                    "active": data.get("active_shards", 0),
                    "unassigned": data.get("unassigned_shards", 0),
                }
            elif name == "grafana":
                data = resp.json()
                body["database"] = data.get("database", "?")
            return body

    except httpx.ConnectError:
        return {"status": "down", "error": "connection refused"}
    except httpx.TimeoutException:
        return {"status": "down", "error": "timeout"}
    except Exception as exc:
        return {"status": "down", "error": str(exc)}


class HealthService:
    async def get_full_health(self) -> dict[str, Any]:
        tasks = {name: _probe(name, url) for name, url in ENDPOINTS.items()}
        results: dict[str, Any] = {}

        # Run all probes concurrently
        resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for name, result in zip(tasks.keys(), resolved):
            if isinstance(result, Exception):
                results[name] = {"status": "error", "error": str(result)}
            else:
                results[name] = result

        # Summary
        all_up = all(v.get("status") == "up" for v in results.values())
        results["_summary"] = {
            "all_up": all_up,
            "services_checked": len(ENDPOINTS),
            "services_up": sum(1 for v in results.values()
                               if isinstance(v, dict) and v.get("status") == "up"),
        }
        return results
