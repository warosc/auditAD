#!/usr/bin/env bash
# ============================================================
# health-summary.sh - Resumen de salud del stack
# Uso: bash scripts/health-summary.sh
# Se ejecuta en el host (requiere acceso a Docker).
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

ok()      { echo -e "${GREEN}[OK]${NC}    $*"; }
fail()    { echo -e "${RED}[DOWN]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
section() { echo -e "\n${BLUE}${BOLD}── $* ──${NC}"; }

cd "${PROJECT_DIR}"

echo "=================================================="
echo " AD Purple Lab - Health Summary"
echo " $(date)"
echo "=================================================="

# ── Estado de contenedores ────────────────────────────────────
section "Estado de contenedores"

if ! docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null; then
    warn "No se pudo obtener estado de docker compose."
    warn "¿Está el stack levantado? Ejecuta: make up"
fi

# ── Healthchecks individuales ─────────────────────────────────
section "Healthchecks"

CONTAINERS=(kali-audit neo4j opensearch opensearch-dashboards grafana zeek suricata)

for container in "${CONTAINERS[@]}"; do
    if ! docker inspect "${container}" &>/dev/null; then
        fail "${container}: contenedor no encontrado"
        continue
    fi

    status=$(docker inspect --format='{{.State.Status}}' "${container}" 2>/dev/null || echo "unknown")
    health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "${container}" 2>/dev/null || echo "unknown")

    if [[ "${status}" == "running" ]]; then
        if [[ "${health}" == "healthy" ]]; then
            ok "${container}: running (healthy)"
        elif [[ "${health}" == "no-healthcheck" ]]; then
            ok "${container}: running (sin healthcheck)"
        elif [[ "${health}" == "starting" ]]; then
            warn "${container}: running (healthcheck: starting...)"
        else
            warn "${container}: running (healthcheck: ${health})"
        fi
    else
        fail "${container}: ${status}"
    fi
done

# ── Puertos publicados ────────────────────────────────────────
section "Puertos accesibles"

declare -A SERVICE_PORTS=(
    ["Neo4j Browser"]="7474"
    ["Neo4j Bolt"]="7687"
    ["OpenSearch API"]="9200"
    ["OpenSearch Dashboards"]="5601"
    ["Grafana"]="3000"
)

for svc in "${!SERVICE_PORTS[@]}"; do
    port="${SERVICE_PORTS[$svc]}"
    if nc -zw2 127.0.0.1 "${port}" 2>/dev/null; then
        ok "${svc} → http://localhost:${port}"
    else
        warn "${svc} (puerto ${port}) → no alcanzable"
    fi
done

# ── Tamaño de logs ────────────────────────────────────────────
section "Tamaño de datos"

echo "  Logs:"
for logdir in "${PROJECT_DIR}/logs/zeek" "${PROJECT_DIR}/logs/suricata"; do
    if [[ -d "${logdir}" ]]; then
        size=$(du -sh "${logdir}" 2>/dev/null | awk '{print $1}')
        echo "    $(basename "${logdir}"): ${size}"
    else
        echo "    $(basename "${logdir}"): (vacío)"
    fi
done

echo "  Reportes:"
if [[ -d "${PROJECT_DIR}/reports" ]]; then
    size=$(du -sh "${PROJECT_DIR}/reports" 2>/dev/null | awk '{print $1}')
    count=$(find "${PROJECT_DIR}/reports" -type f 2>/dev/null | wc -l)
    echo "    reports/: ${size} (${count} archivos)"
else
    echo "    reports/: (vacío)"
fi

echo "  Volúmenes Docker:"
docker volume ls --filter "name=ad-purple-lab" --format "  {{.Name}}" 2>/dev/null || true

# ── Uso de recursos ───────────────────────────────────────────
section "Uso de recursos (contenedores activos)"

docker stats --no-stream --format \
    "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" \
    2>/dev/null | head -20 || warn "No se pudo obtener métricas de recursos"

echo ""
echo "=================================================="
echo "Para ver logs en tiempo real: make logs"
echo "Para exportar datos: make export"
echo "=================================================="
