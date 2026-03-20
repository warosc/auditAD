# AD Purple Lab — SOC Admin Panel

Web-based Security Operations Center panel for the AD Purple Lab.

## Stack

| Component | Technology | Port |
|-----------|-----------|------|
| Frontend  | Next.js 14 + TypeScript + TailwindCSS | 3001 |
| Backend   | FastAPI (Python 3.11) + SQLite | 8080 |

## Quick Start

```bash
# From the repo root — build and start both services
make panel-build
make panel

# Or directly with compose
docker compose up -d panel-api panel-ui
```

Open **http://localhost:3001**

## Panel Sections

| Section | Path | Description |
|---------|------|-------------|
| Dashboard | `/` | Service status overview, quick metrics |
| Auditoría AD | `/audit` | Run audit scripts with live streaming output |
| Contenedores | `/containers` | View, restart containers, tail logs |
| Reportes | `/reports` | List, filter, download audit reports |
| Lab Health | `/health` | HTTP endpoint health checks for all services |

## API Endpoints

```
GET  /health                       — Panel API health
GET  /containers                   — List lab containers
POST /containers/{name}/restart    — Restart a container
GET  /containers/{name}/logs       — Last N log lines
POST /audit/run                    — Stream safe-audit.sh (SSE)
POST /audit/bloodhound             — Stream bloodhound-collect.sh (SSE)
POST /audit/ldap                   — Stream ldap-check.sh (SSE)
POST /audit/dns                    — Stream dns-check.sh (SSE)
POST /audit/validate               — Stream validate-env.sh (SSE)
POST /audit/export                 — Stream export-logs.sh (SSE)
GET  /reports                      — List report files
GET  /reports/history              — Audit summary history
GET  /reports/download/{filename}  — Download a report file
GET  /lab/health                   — HTTP health probes for all services
```

All audit endpoints return **Server-Sent Events** (SSE):

```
data: {"line": "output text\n"}
data: {"done": true, "elapsed": 12.4}
data: {"error": "message"}
```

## Development (without Docker)

**Backend:**
```bash
cd panel/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8080
```

**Frontend:**
```bash
cd panel/frontend
npm install
BACKEND_URL=http://localhost:8080 npm run dev
# Opens on http://localhost:3000
```

## Architecture Notes

- The panel-api container mounts `/var/run/docker.sock` read-only to manage lab containers via the Docker SDK.
- Audit scripts run inside `kali-audit` container via `docker exec`.
- Report files are shared via the `./reports` bind mount.
- Next.js rewrites proxy `/api/*` requests server-side to `http://panel-api:8080`, so the browser never needs direct access to the API port.
- SSE streaming uses `fetch()` + `ReadableStream` on the frontend (the `EventSource` API only supports GET).
