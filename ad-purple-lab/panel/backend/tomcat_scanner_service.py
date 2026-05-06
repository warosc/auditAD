"""
tomcat_scanner_service.py — Streams Tomcat OCSP/TLS scanner output.

Executes scanner.py inside the dedicated `tomcat-ocsp-scanner` container
via docker exec, passing SCAN_TARGET and SCAN_PORTS as environment variables.
Yields SSE-formatted strings for consumption by the frontend.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import AsyncGenerator

from docker_service import DockerService

SCANNER_CONTAINER = "tomcat-ocsp-scanner"
SCANNER_CMD       = "python /app/scanner.py"


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


class TomcatScannerService:
    def __init__(self, docker_svc: DockerService) -> None:
        self.docker = docker_svc

    async def stream_scan(
        self,
        target: str,
        ports: list[int] | None = None,
    ) -> AsyncGenerator[str, None]:
        """
        Async generator — yields SSE strings.
        Runs the scanner in tomcat-ocsp-scanner with SCAN_TARGET / SCAN_PORTS env vars.
        """
        if not target or not target.strip():
            yield _sse({"error": "No target specified"})
            return

        target = target.strip()
        env: dict[str, str] = {"SCAN_TARGET": target}

        if ports:
            env["SCAN_PORTS"] = ",".join(str(p) for p in ports)

        ports_display = env.get("SCAN_PORTS", "443,8443,8080 (default)")
        yield _sse({"line": f"[panel] Tomcat OCSP scanner starting\n", "type": "info"})
        yield _sse({"line": f"[panel] Target  : {target}\n", "type": "info"})
        yield _sse({"line": f"[panel] Ports   : {ports_display}\n", "type": "info"})
        yield _sse({"line": f"[panel] Container: {SCANNER_CONTAINER}\n", "type": "info"})
        yield _sse({"line": f"[panel] Command : {SCANNER_CMD}\n\n", "type": "info"})

        q = self.docker.exec_stream(SCANNER_CONTAINER, SCANNER_CMD, env=env)
        loop      = asyncio.get_event_loop()
        start_ts  = time.monotonic()

        while True:
            try:
                item = await loop.run_in_executor(
                    None, lambda: q.get(timeout=120)
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
