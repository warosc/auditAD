#!/usr/bin/env bash
# ============================================================
# lab-health.sh - Dashboard de salud completo del lab
# Uso: bash scripts/lab-health.sh  (desde el host)
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

ok()      { printf "${GREEN}%-8s${NC} %s\n" "[OK]" "$*"; }
fail()    { printf "${RED}%-8s${NC} %s\n" "[DOWN]" "$*"; }
warn()    { printf "${YELLOW}%-8s${NC} %s\n" "[WARN]" "$*"; }
section() { echo -e "\n${BLUE}${BOLD}━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }
hr()      { echo "─────────────────────────────────────────────────────"; }

cd "${PROJECT_DIR}"

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║        AD Purple Lab — Health Dashboard           ║${NC}"
echo -e "${BOLD}║        $(date '+%Y-%m-%d %H:%M:%S')                   ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════╝${NC}"

# ── 1. Estado de contenedores ─────────────────────────────────
section "Contenedores Docker"

if ! docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Service}}" 2>/dev/null; then
    warn "Stack no iniciado. Ejecuta: make up"
fi

# ── 2. Healthchecks por servicio ──────────────────────────────
section "Estado de salud"

check_container() {
    local name="$1"
    local label="${2:-${name}}"

    if ! docker inspect "${name}" &>/dev/null; then
        fail "${label}: no existe (no iniciado)"
        return
    fi

    local status health
    status=$(docker inspect --format='{{.State.Status}}' "${name}" 2>/dev/null)
    health=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}sin-healthcheck{{end}}' "${name}" 2>/dev/null)

    case "${status}" in
        running)
            if [[ "${health}" == "healthy" ]]; then
                ok "${label}"
            elif [[ "${health}" == "sin-healthcheck" ]]; then
                ok "${label} (corriendo, sin healthcheck)"
            elif [[ "${health}" == "starting" ]]; then
                warn "${label}: healthcheck iniciando..."
            else
                warn "${label}: corriendo, healthcheck=${health}"
            fi
            ;;
        exited)
            fail "${label}: detenido (exited)"
            ;;
        *)
            warn "${label}: estado=${status}"
            ;;
    esac
}

check_container "kali-audit"        "Kali Audit"
check_container "neo4j"             "Neo4j"
check_container "opensearch"        "OpenSearch"
check_container "opensearch-dashboards" "OpenSearch Dashboards"
check_container "grafana"           "Grafana"
check_container "zeek"              "Zeek NSM"
check_container "suricata"          "Suricata IDS"
check_container "wazuh-manager"     "Wazuh Manager (opcional)"

# ── 3. Estado de endpoints HTTP ───────────────────────────────
section "Endpoints HTTP"

check_http() {
    local name="$1"
    local url="$2"
    local extra="${3:-}"

    if curl -sf --max-time 5 "${url}" -o /dev/null 2>/dev/null; then
        ok "${name} → ${url} ${extra}"
    else
        fail "${name} → ${url} (no responde)"
    fi
}

check_opensearch() {
    local url="http://localhost:9200"
    local response
    if response=$(curl -sf --max-time 5 "${url}/_cluster/health" 2>/dev/null); then
        local status
        status=$(echo "${response}" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")
        if [[ "${status}" == "green" ]]; then
            ok "OpenSearch cluster: ${url} (status=green)"
        elif [[ "${status}" == "yellow" ]]; then
            warn "OpenSearch cluster: ${url} (status=yellow — single-node, normal)"
        else
            fail "OpenSearch cluster: ${url} (status=${status})"
        fi
    else
        fail "OpenSearch: ${url} (no responde)"
    fi
}

check_http "Neo4j Browser" "http://localhost:7474"
check_opensearch
check_http "OpenSearch Dashboards" "http://localhost:5601/api/status"
check_http "Grafana" "http://localhost:3000/api/health"

# ── 4. Estado de Neo4j ────────────────────────────────────────
section "Neo4j — Estado de la base de datos"

if curl -sf --max-time 5 "http://localhost:7474" -o /dev/null 2>/dev/null; then
    neo4j_info=$(curl -sf --max-time 5 "http://localhost:7474/db/data/" \
        -H "Accept: application/json" 2>/dev/null \
        | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('neo4j_version','?'))" 2>/dev/null || echo "no disponible")
    ok "Neo4j versión: ${neo4j_info}"
    ok "Browser: http://localhost:7474"
    ok "Bolt:    bolt://localhost:7687"
else
    fail "Neo4j no responde en localhost:7474"
fi

# ── 5. Tamaño de logs ─────────────────────────────────────────
section "Tamaño de datos"

printf "\n  %-28s %s\n" "Directorio" "Tamaño"
hr

for dir in \
    "${PROJECT_DIR}/logs/zeek" \
    "${PROJECT_DIR}/logs/suricata" \
    "${PROJECT_DIR}/logs/wazuh" \
    "${PROJECT_DIR}/reports" \
    "${PROJECT_DIR}/data"; do

    if [[ -d "${dir}" ]]; then
        size=$(du -sh "${dir}" 2>/dev/null | awk '{print $1}')
        count=$(find "${dir}" -type f 2>/dev/null | wc -l)
        label=$(basename "${dir}")
        printf "  %-28s %s (%d archivos)\n" "${label}/" "${size}" "${count}"
    else
        label=$(basename "${dir}")
        printf "  %-28s %s\n" "${label}/" "(no existe)"
    fi
done

# ── 6. Volúmenes Docker ───────────────────────────────────────
section "Volúmenes Docker"

docker volume ls --format "  {{.Name}}\t{{.Driver}}" 2>/dev/null \
    | grep -E "neo4j|opensearch|grafana|zeek|suricata|wazuh|kali" \
    | sort || true

# ── 7. Uso de recursos ────────────────────────────────────────
section "Uso de recursos (contenedores activos)"

docker stats --no-stream \
    --format "  {{printf \"%-30s\" .Name}} CPU:{{.CPUPerc}}  RAM:{{.MemUsage}}" \
    2>/dev/null || warn "No se pudo obtener métricas de recursos"

# ── 8. Últimas alertas Suricata ───────────────────────────────
section "Últimas alertas Suricata (fast.log)"

FAST_LOG="${PROJECT_DIR}/logs/suricata/fast.log"
if [[ -f "${FAST_LOG}" ]]; then
    echo "  Últimas 5 alertas:"
    tail -5 "${FAST_LOG}" | sed 's/^/  /' || true
else
    warn "fast.log no encontrado en ${FAST_LOG}"
fi

# ── Resumen final ─────────────────────────────────────────────
echo ""
hr
echo ""
echo -e "  ${BOLD}Links útiles:${NC}"
echo "    Neo4j Browser:        http://localhost:7474"
echo "    OpenSearch Dashboards: http://localhost:5601"
echo "    Grafana:              http://localhost:3000"
echo "    OpenSearch API:       http://localhost:9200/_cluster/health"
echo ""
echo "  make logs        — ver logs en tiempo real"
echo "  make audit       — ejecutar auditoría segura"
echo "  make export      — exportar logs y reportes"
echo ""
