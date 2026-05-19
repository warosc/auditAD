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
import subprocess
import tempfile
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from pydantic import BaseModel

from audit_service import AuditService
from csv_import_service import CsvImportService
from neo4j_import_service import Neo4jImportService
from neo4j_query_service import Neo4jQueryService
from shares_import_service import SharesImportService
from ntfs_neo4j_service import NtfsNeo4jService
from database import init_db
from docker_service import DockerService
from health_service import HealthService
from report_service import ReportService
from results_service import ResultsService
from settings_service import SettingsService
from scheduler_service import SchedulerService, AUDIT_LABELS
from tomcat_scanner_service import TomcatScannerService

# ── Services ───────────────────────────────────────────────────────────────

docker_svc        = DockerService()
audit_svc         = AuditService(docker_svc)
report_svc        = ReportService()
results_svc       = ResultsService()
health_svc        = HealthService()
settings_svc      = SettingsService()
scheduler_svc     = SchedulerService()
csv_import_svc    = CsvImportService()
shares_import_svc = SharesImportService()
ntfs_neo4j_svc    = NtfsNeo4jService()
neo4j_import_svc  = Neo4jImportService()
neo4j_query_svc   = Neo4jQueryService()
tomcat_scan_svc   = TomcatScannerService(docker_svc)

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

class TomcatScanBody(BaseModel):
    target: str
    ports: list[int] = [443, 8443, 8080]

class Neo4jExecuteBody(BaseModel):
    query_id: str
    params: dict[str, str] = {}

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
@app.post("/audit/tomcat-ocsp-scan")
async def audit_tomcat_ocsp(): return _stream("tomcat-ocsp-scan")

# ── Tomcat OCSP Scanner (dedicated, target-aware) ──────────────────────────

@app.post("/scan/tomcat-ocsp")
async def scan_tomcat_ocsp(body: TomcatScanBody):
    if not body.target or not body.target.strip():
        raise HTTPException(status_code=400, detail="target is required")
    return StreamingResponse(
        tomcat_scan_svc.stream_scan(body.target, body.ports),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )

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

@app.get("/audit/results/pdf")
async def audit_results_pdf():
    """Generate a PDF report of the latest audit findings using pandoc + weasyprint."""
    result = results_svc.get_latest()
    if not result.get("available"):
        raise HTTPException(
            status_code=404,
            detail="No hay datos de auditoría. Ejecuta una auditoría primero.",
        )

    md_text = _build_audit_report_markdown(result)
    date    = datetime.now().strftime("%Y-%m-%d")

    with tempfile.TemporaryDirectory() as tmp:
        md_path  = Path(tmp) / "report.md"
        css_path = Path(tmp) / "style.css"
        pdf_path = Path(tmp) / "report.pdf"

        md_path.write_text(md_text, encoding="utf-8")
        css_path.write_text(_PDF_CSS, encoding="utf-8")

        proc = subprocess.run(
            [
                "pandoc", str(md_path),
                "-o", str(pdf_path),
                "--pdf-engine=weasyprint",
                f"--css={css_path}",
                "--standalone",
                "--metadata", f"title=Reporte de Hallazgos AD — {date}",
            ],
            capture_output=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Error generando PDF: {proc.stderr.decode(errors='replace')}",
            )

        pdf_bytes = pdf_path.read_bytes()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="HALLAZGOS_AD_{date}.pdf"'},
    )

# ── CSV offline import ─────────────────────────────────────────────────────

@app.get("/csv/result")
async def csv_get_cached_result():
    """Return the last CSV analysis result cached in memory (survives page navigation)."""
    result = csv_import_svc.get_last_result()
    if not result:
        raise HTTPException(status_code=404, detail="No hay análisis CSV en caché")
    return result

@app.post("/csv/analyze")
async def csv_analyze(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="Se requiere al menos un archivo CSV.")
    contents: dict[str, bytes] = {}
    for f in files:
        if not (f.filename or "").lower().endswith(".csv"):
            continue
        contents[f.filename] = await f.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Ningún archivo .csv válido recibido.")
    return csv_import_svc.analyze(contents)

# ── Neo4j integration ──────────────────────────────────────────────────────

@app.get("/csv/neo4j-status")
async def csv_neo4j_status():
    return neo4j_import_svc.status()

@app.post("/csv/neo4j-import")
async def csv_neo4j_import(purge: str = "csv"):
    """
    purge=csv  — delete only ADUser/ADComputer/ADGroup/ADOU nodes (default)
    purge=all  — delete everything in Neo4j (BloodHound data included)
    purge=none — append without deleting existing data
    """
    result = csv_import_svc.get_last_result()
    if not result:
        raise HTTPException(
            status_code=400,
            detail="No hay análisis CSV en memoria. Sube y analiza los archivos primero (/csv/analyze).",
        )
    purged = 0
    if purge == "all":
        purged = neo4j_import_svc.purge_all()
    elif purge == "csv":
        purged = neo4j_import_svc.purge_csv_labels()

    stats = neo4j_import_svc.import_data(result)
    return {
        "status":  "ok",
        "purged":  purged,
        "purge_mode": purge,
        "imported": stats,
    }

@app.delete("/csv/neo4j-purge")
async def csv_neo4j_purge(mode: str = "csv"):
    """
    mode=csv — delete only CSV-imported labels
    mode=all — delete everything
    """
    if mode == "all":
        count = neo4j_import_svc.purge_all()
    else:
        count = neo4j_import_svc.purge_csv_labels()
    return {"status": "ok", "deleted": count, "mode": mode}

# ── PDF helpers ───────────────────────────────────────────────────────────────

_PDF_CSS = """
body { font-family: "Liberation Sans", Arial, sans-serif; font-size: 10.5pt; color: #111; line-height: 1.45; margin: 2cm; }
h1 { color: #3b0070; border-bottom: 3px solid #3b0070; padding-bottom: 4px; font-size: 18pt; }
h2 { color: #5a009a; border-bottom: 1px solid #ccc; padding-bottom: 2px; font-size: 14pt; margin-top: 1.6em; }
h3 { color: #7700bb; font-size: 12pt; margin-top: 1.2em; }
h4 { color: #8800cc; font-size: 11pt; }
table { border-collapse: collapse; width: 100%; margin: 0.8em 0; font-size: 9.5pt; }
th { background: #3b0070; color: #fff; padding: 5px 7px; text-align: left; }
td { border: 1px solid #ccc; padding: 4px 7px; }
tr:nth-child(even) td { background: #f7f0ff; }
code { background: #f0f0f0; padding: 1px 4px; border-radius: 2px; font-size: 0.88em; font-family: monospace; }
blockquote { border-left: 3px solid #9b59b6; padding-left: 0.8em; color: #555; margin: 0.6em 0; }
strong { color: #222; }
hr { border: none; border-top: 1px solid #ccc; margin: 1.2em 0; }
"""

def _build_audit_report_markdown(result: dict) -> str:
    date = datetime.now().strftime("%Y-%m-%d %H:%M")
    sc   = result.get("severity_counts", {})
    st   = result.get("stats", {})
    pol  = result.get("policy", {})
    findings = result.get("findings", [])
    users    = result.get("users", [])
    ports    = result.get("ports", [])

    sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
    sev_name = {"critical": "Crítico", "high": "Alto", "medium": "Medio", "low": "Bajo", "info": "Info"}

    lines: list[str] = [
        "# Reporte de Hallazgos — Active Directory",
        "",
        f"**Generado:** {date}  |  **Dominio:** {pol.get('domain', 'N/A')}  |  **Clasificación:** CONFIDENCIAL",
        "",
        "---",
        "",
        "## Resumen Ejecutivo",
        "",
        "| Métrica | Valor |",
        "|---|---|",
        f"| Usuarios totales | {st.get('total_users', 0)} |",
        f"| Usuarios activos | {st.get('active_users', 0)} |",
        f"| Usuarios deshabilitados | {st.get('disabled_users', 0)} |",
        f"| Usuarios privilegiados | {st.get('privileged_users', 0)} |",
        f"| Equipos totales | {st.get('total_computers', 0)} |",
        f"| Controladores de dominio | {st.get('domain_controllers', 0)} |",
        f"| Grupos totales | {st.get('total_groups', 0)} |",
        f"| Puertos abiertos | {st.get('ports_open', 0)} |",
        "",
        "### Distribución de Severidad",
        "",
        "| Severidad | Hallazgos |",
        "|---|---|",
        f"| 🔴 Crítico | {sc.get('critical', 0)} |",
        f"| 🟠 Alto | {sc.get('high', 0)} |",
        f"| 🟡 Medio | {sc.get('medium', 0)} |",
        f"| 🟢 Bajo | {sc.get('low', 0)} |",
        f"| ⚪ Info | {sc.get('info', 0)} |",
        f"| **Total** | **{len(findings)}** |",
        "",
    ]

    # Política de dominio
    if pol:
        lines += [
            "## Política de Dominio",
            "",
            "| Parámetro | Valor |",
            "|---|---|",
            f"| Longitud mínima de contraseña | {pol.get('minPwdLength', '?')} |",
            f"| Máxima edad de contraseña | {pol.get('maxPwdAge', '?')} |",
            f"| Historial de contraseñas | {pol.get('pwdHistoryLength', '?')} |",
            f"| Complejidad (pwdProperties) | {pol.get('pwdProperties', '?')} |",
            f"| Umbral de bloqueo | {pol.get('lockoutThreshold', '?')} |",
            f"| Duración de bloqueo | {pol.get('lockoutDuration', '?')} |",
            f"| MachineAccountQuota | {pol.get('machineAccountQuota', '?')} |",
            f"| Nivel funcional | {pol.get('behaviorVersion', '?')} |",
            "",
        ]

    # Matriz de hallazgos
    lines += [
        "## Matriz de Hallazgos",
        "",
        "| ID | Sev. | Categoría | Título | MITRE |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        icon = sev_icon.get(f["severity"], "")
        name = sev_name.get(f["severity"], f["severity"])
        lines.append(
            f"| {f['id']} | {icon} {name} | {f['category']} | {f['title']} | `{f['mitre']}` |"
        )
    lines.append("")

    # Detalle de hallazgos
    lines += ["## Detalle de Hallazgos", ""]
    for f in findings:
        icon = sev_icon.get(f["severity"], "")
        name = sev_name.get(f["severity"], f["severity"])
        lines += [
            f"### {f['id']} — {f['title']}",
            "",
            f"**Severidad:** {icon} {name}  |  **Categoría:** {f['category']}  |  **MITRE:** `{f['mitre']}`",
            "",
            f.get("description", ""),
            "",
            f"> **Recomendación:** {f.get('recommendation', '')}",
            "",
            "---",
            "",
        ]

    # Cuentas de alto riesgo
    asrep = [u["sam"] for u in users if u.get("no_preauth") and not u.get("disabled")]
    kerb  = [u["sam"] for u in users if u.get("spn") and not u.get("disabled")]
    no_exp = [u["sam"] for u in users if u.get("no_expire") and not u.get("disabled")]

    if asrep or kerb:
        lines += ["## Cuentas de Alto Riesgo Kerberos", ""]
        if asrep:
            lines += [
                f"**AS-REP Roastable ({len(asrep)} cuentas):** {', '.join(asrep)}",
                "",
            ]
        if kerb:
            lines += [
                f"**Kerberoastable ({len(kerb)} cuentas):** {', '.join(kerb[:20])}"
                + (f" +{len(kerb)-20} más" if len(kerb) > 20 else ""),
                "",
            ]
        if no_exp:
            lines += [
                f"**Sin expiración de contraseña ({len(no_exp)}):** {', '.join(no_exp[:15])}"
                + (f" +{len(no_exp)-15} más" if len(no_exp) > 15 else ""),
                "",
            ]

    # Puertos abiertos
    open_ports = [p for p in ports if p.get("state") == "open"]
    if open_ports:
        lines += [
            "## Puertos Abiertos",
            "",
            "| Puerto | Servicio |",
            "|---|---|",
        ]
        for p in open_ports:
            lines.append(f"| {p['port']}/tcp | {p['service']} |")
        lines.append("")

    lines += [
        "---",
        f"*Reporte generado por AD Purple Lab — Auditoría LDAP ({date})*",
    ]
    return "\n".join(lines)


def _sev_label(s: str) -> str:
    return {"critical": "🔴 CRÍTICO", "high": "🟠 ALTO", "medium": "🟡 MEDIO",
            "low": "🟢 BAJO", "info": "⚪ INFO"}.get(s, s.upper())

def _build_report_markdown(result: dict) -> str:
    date  = datetime.now().strftime("%Y-%m-%d")
    sc    = result.get("severity_counts", {})
    st    = result.get("stats", {})
    lines: list[str] = [
        f"# Reporte de Riesgo y Cumplimiento — Active Directory",
        f"",
        f"**Fecha:** {date} | **Fuente:** {result.get('source','')} | **Clasificación:** CONFIDENCIAL",
        f"",
        f"## Resumen Ejecutivo",
        f"",
        f"| Métrica | Valor |",
        f"|---|---|",
        f"| Usuarios totales | {st.get('total_users', 0)} |",
        f"| Usuarios activos | {st.get('active_users', 0)} |",
        f"| Usuarios privilegiados | {st.get('privileged_users', 0)} |",
        f"| Equipos totales | {st.get('total_computers', 0)} |",
        f"| Controladores de dominio | {st.get('domain_controllers', 0)} |",
        f"| Grupos totales | {st.get('total_groups', 0)} |",
        f"| OUs totales | {st.get('total_ous', 0)} |",
        f"",
        f"### Distribución de Severidad",
        f"",
        f"| Severidad | Hallazgos |",
        f"|---|---|",
        f"| 🔴 Crítico | {sc.get('critical', 0)} |",
        f"| 🟠 Alto | {sc.get('high', 0)} |",
        f"| 🟡 Medio | {sc.get('medium', 0)} |",
        f"| 🟢 Bajo | {sc.get('low', 0)} |",
        f"| ⚪ Info | {sc.get('info', 0)} |",
        f"| **Total** | **{len(result.get('findings', []))}** |",
        f"",
        f"## Matriz de Hallazgos",
        f"",
        f"| ID | Severidad | Título | MITRE | Recomendación |",
        f"|---|---|---|---|---|",
    ]
    for f in result.get("findings", []):
        lines.append(
            f"| {f['id']} | {_sev_label(f['severity'])} | {f['title']} | `{f['mitre']}` | {f['recommendation']} |"
        )
    lines += ["", "### Detalle de Hallazgos", ""]
    for f in result.get("findings", []):
        lines += [
            f"#### {f['id']} — {f['title']}",
            f"**Severidad:** {_sev_label(f['severity'])} | **Categoría:** {f['category']} | **MITRE:** `{f['mitre']}`",
            "",
            f.get("description", ""),
            "",
            f"**Recomendación:** {f.get('recommendation', '')}",
            "",
        ]

    paths = result.get("attack_paths", [])
    if paths:
        lines += [
            "## Rutas de Ataque Sintetizadas",
            "",
            "| ID | Severidad | Título | MITRE | Cuentas Afectadas |",
            "|---|---|---|---|---|",
        ]
        for ap in paths:
            accs = ap.get("accounts", [])
            acc_str = ", ".join(accs[:3]) + (f" +{len(accs)-3}" if len(accs) > 3 else "")
            lines.append(
                f"| {ap['id']} | {_sev_label(ap['severity'])} | {ap['title']} | `{ap['mitre']}` | {acc_str} |"
            )
        lines += ["", "### Detalle de Rutas de Ataque", ""]
        for ap in paths:
            chain = " → ".join(ap.get("chain", []))
            accs  = ", ".join(ap.get("accounts", []))
            lines += [
                f"#### {ap['id']} — {ap['title']}",
                f"**Severidad:** {_sev_label(ap['severity'])} | **MITRE:** `{ap['mitre']}`",
                "",
                f"**Cadena:** {chain}",
                "",
                f"**Cuentas afectadas:** {accs}" if accs else "",
                "",
                f"**Impacto:** {ap.get('impact', '')}",
                "",
                f"**Remediación:** {ap.get('fix', '')}",
                "",
            ]

    top_risk = sorted(
        [u for u in result.get("users", []) if not u.get("disabled") and u.get("risk_score", 0) > 0],
        key=lambda u: u.get("risk_score", 0), reverse=True
    )[:20]
    if top_risk:
        lines += [
            "## Top Cuentas por Riesgo",
            "",
            "| Score | Usuario | OU | Factores de Riesgo |",
            "|---|---|---|---|",
        ]
        for u in top_risk:
            flags = ", ".join(filter(None, [
                "AS-REP"     if u.get("no_preauth") else "",
                "Kerberoast" if u.get("spn")        else "",
                "NoExpira"   if u.get("no_expire")  else "",
                "NoPwd"      if u.get("pwd_not_req") else "",
            ]))
            lines.append(
                f"| {u.get('risk_score', 0)} | {u.get('sam', '')} | {u.get('ou', '—')} | {flags or '—'} |"
            )
        lines.append("")

    lines += [
        "---",
        f"*Reporte generado por AD Purple Lab — Módulo de Análisis CSV ({date})*",
    ]
    return "\n".join(lines)


@app.get("/csv/report/pdf")
async def csv_report_pdf():
    """Generate a PDF Risk & Compliance report from the last CSV analysis using pandoc + weasyprint."""
    result = csv_import_svc.get_last_result()
    if not result:
        raise HTTPException(
            status_code=404,
            detail="No hay análisis CSV en memoria. Analiza los archivos primero (/csv/analyze).",
        )

    md_text = _build_report_markdown(result)
    date    = datetime.now().strftime("%Y-%m-%d")

    with tempfile.TemporaryDirectory() as tmp:
        md_path  = Path(tmp) / "report.md"
        css_path = Path(tmp) / "style.css"
        pdf_path = Path(tmp) / "report.pdf"

        md_path.write_text(md_text, encoding="utf-8")
        css_path.write_text(_PDF_CSS, encoding="utf-8")

        proc = subprocess.run(
            [
                "pandoc", str(md_path),
                "-o", str(pdf_path),
                "--pdf-engine=weasyprint",
                f"--css={css_path}",
                "--standalone",
                "--metadata", f"title=Reporte Risk & Compliance — AD {date}",
            ],
            capture_output=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail=f"Error generando PDF: {proc.stderr.decode(errors='replace')}",
            )

        pdf_bytes = pdf_path.read_bytes()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="REPORTE_RC_AD_{date}.pdf"'},
    )

# ── SMB Shares + NTFS Permissions Analysis ────────────────────────────────

@app.get("/shares/result")
async def shares_get_cached():
    """Return last cached shares analysis (survives page navigation)."""
    result = shares_import_svc.get_last_result()
    if not result:
        raise HTTPException(status_code=404, detail="No hay análisis de permisos en caché")
    return result

@app.post("/shares/analyze")
async def shares_analyze(files: list[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="Se requiere al menos un archivo CSV.")
    contents: dict[str, bytes] = {}
    for f in files:
        if not (f.filename or "").lower().endswith(".csv"):
            continue
        contents[f.filename or "unknown.csv"] = await f.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Ningún archivo .csv válido recibido.")
    return shares_import_svc.analyze(contents)

# ── NTFS → Neo4j import ────────────────────────────────────────────────────

@app.get("/ntfs/status")
async def ntfs_status():
    """Return count of Folder nodes and HAS_ACCESS rels in Neo4j."""
    return ntfs_neo4j_svc.status()

@app.post("/ntfs/import")
async def ntfs_import(file: UploadFile = File(...)):
    """
    Import a single NTFS ACL CSV into Neo4j.
    Accepts NTFS_Permissions.csv (Folder/Identity/Rights/Type/Inherited)
    or NTFS_User_Effective.csv (User/Folder/Rights/Type/Inherited[/Via]).
    """
    fname = (file.filename or "upload.csv").lower()
    if not fname.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Se requiere un archivo .csv")
    content = await file.read()
    result = ntfs_neo4j_svc.import_csv(file.filename or "upload.csv", content)
    if result.get("status") == "error":
        raise HTTPException(status_code=422, detail=result["message"])
    return result

@app.delete("/ntfs/purge")
async def ntfs_purge():
    """Remove all Folder nodes and HAS_ACCESS relationships from Neo4j."""
    return ntfs_neo4j_svc.purge()

# ── Neo4j Graph Query API ──────────────────────────────────────────────────

@app.get("/neo4j/queries")
async def neo4j_queries():
    """Return the full Cypher query catalog."""
    return {"queries": neo4j_query_svc.get_catalog()}

@app.get("/neo4j/stats")
async def neo4j_stats():
    """Quick AD stats for dashboard cards."""
    return neo4j_query_svc.get_stats()

@app.post("/neo4j/execute")
async def neo4j_execute(body: Neo4jExecuteBody):
    """Execute a predefined Cypher query with parameters."""
    if not body.query_id:
        raise HTTPException(status_code=400, detail="query_id is required")
    try:
        result = neo4j_query_svc.execute(body.query_id, body.params)
        return result
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

@app.get("/neo4j/log")
async def neo4j_log():
    """Return the last 100 executed queries (audit log)."""
    return {"log": neo4j_query_svc.get_log()}

# ── Lab health ─────────────────────────────────────────────────────────────

@app.get("/lab/health")
async def lab_health():
    return await health_svc.get_full_health()
