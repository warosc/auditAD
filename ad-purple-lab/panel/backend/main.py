"""
main.py — FastAPI backend for AD Purple Lab SOC Panel.

Routes:
  GET/POST  /settings                 — lab settings (AD IP, rate limits, etc.)
  GET       /settings/schema          — setting definitions for frontend rendering
  GET       /settings/schedule        — list scheduled audit jobs
  POST      /settings/schedule        — add a scheduled job
  PATCH     /settings/schedule/{id}   — enable/disable a job
  DELETE    /settings/schedule/{id}   — remove a job
  GET       /containers               — list lab containers
  POST      /containers/{n}/restart   — restart container
  GET       /containers/{n}/logs      — tail container logs
  POST      /audit/{type}             — stream audit script (SSE)
  GET       /reports                  — list reports
  GET       /reports/history          — audit run history
  GET       /reports/download/{f}     — download report
  GET       /lab/health               — HTTP health probes
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from audit_service import AuditService
from database import init_db
from docker_service import DockerService
from health_service import HealthService
from report_service import ReportService
from results_service import ResultsService
from settings_service import SettingsService
from scheduler_service import SchedulerService, AUDIT_LABELS

# ── Services ───────────────────────────────────────────────────────────────

docker_svc    = DockerService()
audit_svc     = AuditService(docker_svc)
report_svc    = ReportService()
results_svc   = ResultsService()
health_svc    = HealthService()
settings_svc  = SettingsService()
scheduler_svc = SchedulerService()

audit_svc.set_settings(settings_svc)

# ── Background scheduler ───────────────────────────────────────────────────

async def _scheduler_loop():
    while True:
        await asyncio.sleep(60)
        try:
            await scheduler_svc.tick(audit_svc)
        except Exception:
            pass

# ── Lifespan ───────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    asyncio.create_task(_scheduler_loop())
    yield

# ── App ────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AD Purple Lab — Panel API",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

_SSE_HEADERS = {
    "Cache-Control":     "no-cache",
    "X-Accel-Buffering": "no",
    "Connection":        "keep-alive",
}

# ── Pydantic models ────────────────────────────────────────────────────────

class SettingsSaveBody(BaseModel):
    settings: dict[str, str]

class ScheduleAddBody(BaseModel):
    audit_type: str
    interval_minutes: int
    label: str = ""

class ScheduleToggleBody(BaseModel):
    enabled: bool

# ── Health ─────────────────────────────────────────────────────────────────

@app.get("/health")
async def api_health():
    return {"status": "ok", "service": "panel-api"}

# ── Settings ───────────────────────────────────────────────────────────────

@app.get("/settings")
async def get_settings():
    return {"settings": await settings_svc.get_all()}

@app.post("/settings")
async def save_settings(body: SettingsSaveBody):
    await settings_svc.save(body.settings)
    return {"status": "saved", "count": len(body.settings)}

@app.get("/settings/schema")
async def settings_schema():
    return {"definitions": settings_svc.get_definitions()}

# ── Scheduler ──────────────────────────────────────────────────────────────

@app.get("/settings/schedule")
async def list_schedule():
    return {"jobs": await scheduler_svc.list_jobs(), "audit_types": AUDIT_LABELS}

@app.post("/settings/schedule")
async def add_schedule(body: ScheduleAddBody):
    try:
        job = await scheduler_svc.add_job(body.audit_type, body.interval_minutes, body.label)
        return {"status": "created", "job": job}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.patch("/settings/schedule/{job_id}")
async def toggle_schedule(job_id: int, body: ScheduleToggleBody):
    try:
        job = await scheduler_svc.toggle_job(job_id, body.enabled)
        return {"status": "updated", "job": job}
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.delete("/settings/schedule/{job_id}")
async def delete_schedule(job_id: int):
    await scheduler_svc.delete_job(job_id)
    return {"status": "deleted"}

# ── Containers ─────────────────────────────────────────────────────────────

@app.get("/containers")
async def list_containers():
    return {"containers": docker_svc.list_containers()}

@app.post("/containers/{name}/restart")
async def restart_container(name: str):
    result = docker_svc.restart_container(name)
    if result.get("status") == "error":
        raise HTTPException(status_code=400, detail=result["message"])
    return result

@app.get("/containers/{name}/logs")
async def container_logs(name: str, tail: int = 200):
    return {"container": name, "logs": docker_svc.get_logs(name, tail=tail)}

# ── Audit SSE ──────────────────────────────────────────────────────────────

def _stream(key: str):
    return StreamingResponse(
        audit_svc.stream_script(key),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )

@app.post("/audit/run")
async def audit_run():        return _stream("safe-audit")
@app.post("/audit/bloodhound")
async def audit_bloodhound(): return _stream("bloodhound")
@app.post("/audit/dns")
async def audit_dns():        return _stream("dns-check")
@app.post("/audit/ldap")
async def audit_ldap():       return _stream("ldap-check")
@app.post("/audit/export")
async def audit_export():     return _stream("export")
@app.post("/audit/validate")
async def audit_validate():   return _stream("validate")
@app.post("/audit/asrep-roast")
async def audit_asrep():      return _stream("asrep-roast")
@app.post("/audit/kerberoast")
async def audit_kerberoast(): return _stream("kerberoast")

# ── Reports ────────────────────────────────────────────────────────────────

@app.get("/reports")
async def list_reports():
    return report_svc.list_reports()

@app.get("/reports/history")
async def report_history():
    return report_svc.audit_history()

@app.get("/reports/download/{filename:path}")
async def download_report(filename: str):
    local_path = report_svc.resolve_path(filename)
    if local_path:
        return FileResponse(
            path=local_path,
            filename=os.path.basename(filename),
            media_type="application/octet-stream",
        )
    safe_name = os.path.basename(filename)
    filepath = docker_svc.find_file_in_container("kali-audit", safe_name)
    if not filepath:
        raise HTTPException(status_code=404, detail=f"File not found: {safe_name}")
    try:
        bits, _ = docker_svc.get_file_stream("kali-audit", filepath)
        return StreamingResponse(
            (chunk for chunk in bits),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}"'},
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

# ── Results (parsed audit data) ────────────────────────────────────────────

@app.get("/audit/results/latest")
async def audit_results_latest():
    return results_svc.get_latest()

@app.get("/audit/results/attacks")
async def audit_results_attacks():
    return results_svc.get_attack_results()

# ── Lab health ─────────────────────────────────────────────────────────────

@app.get("/lab/health")
async def lab_health():
    return await health_svc.get_full_health()
