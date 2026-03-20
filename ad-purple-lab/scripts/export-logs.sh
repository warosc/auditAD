#!/usr/bin/env bash
# ============================================================
# export-logs.sh - Empaqueta logs y reportes en un tar.gz
# Uso: bash scripts/export-logs.sh
# Puede ejecutarse en el host o dentro del contenedor kali-audit.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
EXPORT_FILE="${PROJECT_DIR}/ad-purple-lab-export_${TIMESTAMP}.tar.gz"

GREEN='\033[0;32m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
info() { echo "[INFO] $*"; }

echo "=================================================="
echo " AD Purple Lab - Exportación de logs y reportes"
echo " Timestamp: ${TIMESTAMP}"
echo "=================================================="
echo ""

# Directorios a incluir en el export
INCLUDE_DIRS=()

for d in \
    "${PROJECT_DIR}/reports" \
    "${PROJECT_DIR}/logs/zeek" \
    "${PROJECT_DIR}/logs/suricata"; do
    if [[ -d "${d}" ]]; then
        INCLUDE_DIRS+=("${d}")
        info "Incluyendo: ${d}"
    else
        info "Omitiendo (no existe): ${d}"
    fi
done

if [[ ${#INCLUDE_DIRS[@]} -eq 0 ]]; then
    info "No hay directorios de datos para exportar."
    exit 0
fi

# Calcular tamaño antes de comprimir
TOTAL_SIZE=$(du -sh "${INCLUDE_DIRS[@]}" 2>/dev/null | tail -1 | awk '{print $1}' || echo "N/A")
info "Tamaño total estimado: ${TOTAL_SIZE}"
echo ""

info "Creando ${EXPORT_FILE}..."

tar -czf "${EXPORT_FILE}" \
    --ignore-failed-read \
    -C "${PROJECT_DIR}" \
    reports \
    logs 2>/dev/null || true

if [[ -f "${EXPORT_FILE}" ]]; then
    EXPORT_SIZE=$(du -sh "${EXPORT_FILE}" | awk '{print $1}')
    ok "Export creado: ${EXPORT_FILE} (${EXPORT_SIZE})"
else
    echo "Error: no se pudo crear ${EXPORT_FILE}"
    exit 1
fi

echo ""
info "Contenido del export:"
tar -tzf "${EXPORT_FILE}" | head -30
tar -tzf "${EXPORT_FILE}" | wc -l | xargs -I{} echo "  ... {} archivos en total"
