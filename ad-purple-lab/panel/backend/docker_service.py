"""
docker_service.py — Docker SDK wrapper for AD Purple Lab Panel.
Manages container status, restarts, log retrieval and script execution.
"""
from __future__ import annotations

import queue
import threading
from typing import Any

import docker
import docker.errors


# Containers that belong to this lab (checked in order).
LAB_CONTAINERS = [
    "kali-audit",
    "tomcat-ocsp-scanner",
    "neo4j",
    "opensearch",
    "opensearch-dashboards",
    "grafana",
    "zeek",
    "suricata",
    "wazuh-manager",
    "panel-api",
    "panel-ui",
]


class DockerService:
    def __init__(self) -> None:
        try:
            self.client: docker.DockerClient = docker.from_env()
            self._available = True
        except Exception as exc:
            self.client = None  # type: ignore[assignment]
            self._available = False
            self._init_error = str(exc)

    # ── Container listing ──────────────────────────────────────

    def list_containers(self) -> list[dict[str, Any]]:
        if not self._available:
            return [{"name": n, "status": "docker_unavailable"} for n in LAB_CONTAINERS]

        result = []
        for name in LAB_CONTAINERS:
            result.append(self._describe(name))
        return result

    def _describe(self, name: str) -> dict[str, Any]:
        try:
            c = self.client.containers.get(name)
            tags = c.image.tags
            return {
                "name": name,
                "id": c.short_id,
                "status": c.status,
                "image": tags[0] if tags else "unknown",
                "health": self._health(c),
            }
        except docker.errors.NotFound:
            return {
                "name": name,
                "id": "N/A",
                "status": "not_found",
                "image": "N/A",
                "health": "not_found",
            }
        except Exception as exc:
            return {
                "name": name,
                "id": "N/A",
                "status": "error",
                "image": "N/A",
                "health": str(exc),
            }

    @staticmethod
    def _health(container) -> str:
        try:
            hc = container.attrs.get("State", {}).get("Health")
            return hc["Status"] if hc else "no_healthcheck"
        except Exception:
            return "unknown"

    # ── Restart ────────────────────────────────────────────────

    def restart_container(self, name: str) -> dict[str, str]:
        try:
            c = self.client.containers.get(name)
            c.restart(timeout=30)
            return {"status": "ok", "message": f"{name} restarted successfully"}
        except docker.errors.NotFound:
            return {"status": "error", "message": f"Container '{name}' not found"}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    # ── Logs ───────────────────────────────────────────────────

    def get_logs(self, name: str, tail: int = 200) -> str:
        try:
            c = self.client.containers.get(name)
            raw = c.logs(tail=tail, timestamps=True)
            return raw.decode("utf-8", errors="replace")
        except docker.errors.NotFound:
            return f"[Container '{name}' not found]"
        except Exception as exc:
            return f"[Error reading logs: {exc}]"

    # ── Script execution (streaming via queue) ─────────────────

    def exec_stream(self, container_name: str, cmd: str, env: dict | None = None) -> queue.Queue:
        """
        Execute *cmd* in *container_name* and return a Queue.
        The queue yields bytes chunks; ``None`` signals completion.
        Errors are encoded as bytes with prefix ``b"ERROR: ..."``.
        """
        q: queue.Queue = queue.Queue()

        def _run() -> None:
            try:
                c = self.client.containers.get(container_name)
                result = c.exec_run(cmd, stream=True, demux=False, environment=env or {})
                for chunk in result.output:
                    if chunk:
                        q.put(chunk)
            except Exception as exc:
                q.put(f"ERROR: {exc}\n".encode())
            finally:
                q.put(None)

        threading.Thread(target=_run, daemon=True).start()
        return q

    # ── File download via container archive ────────────────────

    def get_file_stream(self, container_name: str, filepath: str):
        """
        Returns (bits_generator, stat_dict) for streaming a file out of a container.
        Uses docker.container.get_archive().
        """
        c = self.client.containers.get(container_name)
        bits, stat = c.get_archive(filepath)
        return bits, stat

    def find_file_in_container(self, container_name: str, filename: str) -> str:
        """Returns absolute path of *filename* inside the container, or ''."""
        try:
            c = self.client.containers.get(container_name)
            r = c.exec_run(f"find /workspace -maxdepth 3 -name '{filename}' 2>/dev/null | head -1")
            return r.output.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""
