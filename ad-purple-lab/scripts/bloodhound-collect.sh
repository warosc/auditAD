#!/usr/bin/env bash
# ============================================================
# bloodhound-collect.sh - Colección de datos para BloodHound
# Uso: bash scripts/bloodhound-collect.sh
# Se ejecuta dentro del contenedor kali-audit.
# Requiere: bloodhound-python instalado en virtualenv
#
# IMPORTANTE: Colección en modo solo-lectura.
# bloodhound-python hace únicamente consultas LDAP/DNS.
# No modifica objetos del directorio.
# ============================================================
set -euo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
VENV="${VENV:-/opt/adaudit-venv}"
REPORT_DIR="${WORKSPACE}/reports/bloodhound"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${REPORT_DIR}/${TIMESTAMP}"

mkdir -p "${OUTPUT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo "[INFO] $*"; }

# ── Cargar variables ──────────────────────────────────────────
# Solo carga ad_env.sh si el panel NO inyectó DC_IP (ejecución manual)
if [[ -z "${DC_IP:-}" && -f "${WORKSPACE}/ad_env.sh" ]]; then
    # shellcheck disable=SC1090
    source "${WORKSPACE}/ad_env.sh"
fi

: "${AD_DOMAIN:?AD_DOMAIN no configurado}"
: "${DC_IP:?DC_IP no configurado}"
: "${AD_USERNAME:?AD_USERNAME no configurado}"
: "${AD_PASSWORD:?AD_PASSWORD no configurado}"
: "${DNS_SERVER:?DNS_SERVER no configurado}"

# Verificar que ENABLE_BLOODHOUND está activo
if [[ "${ENABLE_BLOODHOUND:-true}" != "true" ]]; then
    warn "ENABLE_BLOODHOUND=false. Colección de BloodHound omitida."
    exit 0
fi

echo "=================================================="
echo " BloodHound Collection - $(date)"
echo " Dominio  : ${AD_DOMAIN}"
echo " DC IP    : ${DC_IP}"
echo " Usuario  : ${AD_USERNAME}"
echo " Output   : ${OUTPUT_DIR}"
echo "=================================================="
echo ""

# ── Activar virtualenv ────────────────────────────────────────
# shellcheck disable=SC1090
source "${VENV}/bin/activate"

# ── Verificar bloodhound-python ───────────────────────────────
if ! command -v bloodhound-python &>/dev/null; then
    fail "bloodhound-python no encontrado en virtualenv ${VENV}"
    exit 1
fi

info "Versión: $(bloodhound-python --version 2>&1 | head -1)"
echo ""

# ── Ejecutar colección ────────────────────────────────────────
# Métodos seguros de colección (solo lectura LDAP):
#   DCOnly  - Solo consultas LDAP al DC (más rápido, menos ruido)
#   Default - Incluye también consultas SMB a endpoints
#
# Para lab autorizado se usa DCOnly por defecto (menos impacto en la red).
# Cambiar a "Default" o "All" si se requiere colección más completa.

COLLECTION_METHOD="DCOnly"
BH_THREADS="${BLOODHOUND_THREADS:-5}"
BH_TIMEOUT="${BLOODHOUND_TIMEOUT:-30}"

info "Iniciando colección con método: ${COLLECTION_METHOD}"
info "  threads=${BH_THREADS}  timeout=${BH_TIMEOUT}s"
info "Esto puede tomar varios minutos dependiendo del tamaño del dominio."
echo ""

# bloodhound-python writes output to the current directory
cd "${OUTPUT_DIR}"

bloodhound-python \
    -d "${AD_DOMAIN}" \
    -u "${AD_USERNAME}" \
    -p "${AD_PASSWORD}" \
    -dc "${AD_FQDN:-${DC_IP}}" \
    --dns-tcp \
    -ns "${DNS_SERVER}" \
    -c "${COLLECTION_METHOD}" \
    --zip \
    -w "${BH_THREADS}" \
    2>&1 | tee "${OUTPUT_DIR}/bloodhound_run_${TIMESTAMP}.log"

BHEXIT=${PIPESTATUS[0]}

if [[ ${BHEXIT} -eq 0 ]]; then
    echo ""
    ok "Colección completada exitosamente."
    echo ""
    info "Archivos generados:"
    ls -lh "${OUTPUT_DIR}/"
    echo ""
    info "Para importar en BloodHound:"
    info "  1. Abre BloodHound (conectado a Neo4j en localhost:7474)"
    info "  2. Upload Data → selecciona los archivos .zip o .json en ${OUTPUT_DIR}"
    info "  3. Espera la importación y usa las queries predefinidas"
    echo ""
    info "Para importar directamente vía API de Neo4j, usa BloodHound CE o"
    info "la interfaz web de Neo4j en http://localhost:7474"
else
    fail "bloodhound-python terminó con código de error ${BHEXIT}"
    fail "Revisa el log: ${OUTPUT_DIR}/bloodhound_run_${TIMESTAMP}.log"
    exit ${BHEXIT}
fi

echo "Reporte guardado en: ${OUTPUT_DIR}"
