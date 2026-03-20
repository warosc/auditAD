"""
audit_service.py — Executes audit scripts inside kali-audit via Docker exec.
Streams output as SSE (Server-Sent Events) text/event-stream.
Settings env vars are injected at exec time so they override container startup values.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator

from docker_service import DockerService

KALI_CONTAINER = "kali-audit"

SCRIPTS: dict[str, str] = {
    "safe-audit":   "bash /workspace/scripts/safe-audit.sh",
    "bloodhound":   "bash /workspace/scripts/bloodhound-collect.sh",
    "dns-check":    "bash /workspace/scripts/dns-check.sh",
    "ldap-check":   "bash /workspace/scripts/ldap-check.sh",
    "export":       "bash /workspace/scripts/export-logs.sh",
    "health":       "bash /workspace/scripts/lab-health.sh",
    "validate":     "bash /workspace/scripts/validate-env.sh",
    "asrep-roast":  "bash /workspace/scripts/asrep-roast.sh",
    "kerberoast":   "bash /workspace/scripts/kerberoast.sh",
}


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


class AuditService:
    def __init__(self, docker_svc: DockerService) -> None:
        self.docker = docker_svc
        # Injected by main.py after settings_service is initialized
        self._settings_svc = None

    def set_settings(self, svc) -> None:
        self._settings_svc = svc

    async def stream_script(self, script_key: str) -> AsyncGenerator[str, None]:
        """
        Async generator that yields SSE-formatted strings.
        Runs the specified script inside the kali-audit container.
        Live settings are injected as environment overrides to exec_run.
        """
        cmd = SCRIPTS.get(script_key)
        if not cmd:
            yield _sse({"error": f"Unknown script: {script_key}"})
            return

        # Get live settings to pass as env vars
        env_overrides: dict[str, str] = {}
        if self._settings_svc:
            try:
                env_overrides = await self._settings_svc.get_env_dict()
            except Exception:
                pass  # Fall back to container's own .env

        yield _sse({"line": f"[panel] Launching: {cmd}\n", "type": "info"})
        if env_overrides.get("DC_IP"):
            yield _sse({"line": f"[panel] Target DC: {env_overrides['DC_IP']} ({env_overrides.get('AD_DOMAIN', '')})\n", "type": "info"})

        q = self.docker.exec_stream(KALI_CONTAINER, cmd, env=env_overrides)
        loop = asyncio.get_event_loop()
        start_ts = time.monotonic()

        while True:
            try:
                item = await loop.run_in_executor(
                    None, lambda: q.get(timeout=600)
                )
            except Exception as exc:
                yield _sse({"error": f"Stream timeout or error: {exc}"})
                break

            if item is None:
                break

            text = item.decode("utf-8", errors="replace")
            yield _sse({"line": text})

        elapsed = round(time.monotonic() - start_ts, 1)
        yield _sse({"done": True, "elapsed": elapsed})
