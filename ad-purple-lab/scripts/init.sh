#!/usr/bin/env bash
# ============================================================
# init.sh - Inicialización del proyecto AD Purple Lab
# Uso: bash scripts/init.sh  (desde el directorio raíz del proyecto)
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
info() { echo "[INFO] $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

echo "=================================================="
echo " AD Purple Lab - Inicialización"
echo "=================================================="
echo ""

cd "${PROJECT_DIR}"

# ── Verificar Docker y Docker Compose ────────────────────────
info "Verificando dependencias..."

if ! command -v docker &>/dev/null; then
    fail "Docker no encontrado. Instala Docker Desktop o Docker Engine."
    exit 1
fi
ok "Docker $(docker --version | awk '{print $3}' | tr -d ',')"

if ! docker compose version &>/dev/null; then
    fail "docker compose v2 no disponible. Actualiza Docker Desktop."
    exit 1
fi
ok "Docker Compose $(docker compose version --short)"

# ── Crear .env desde .env.example si no existe ───────────────
echo ""
info "Verificando archivo .env..."

if [[ ! -f "${PROJECT_DIR}/.env" ]]; then
    if [[ -f "${PROJECT_DIR}/.env.example" ]]; then
        cp "${PROJECT_DIR}/.env.example" "${PROJECT_DIR}/.env"
        ok ".env creado desde .env.example"
        warn "IMPORTANTE: Edita .env con los datos de tu laboratorio antes de continuar."
        warn "  DC_IP, AD_DOMAIN, AD_USERNAME, AD_PASSWORD deben apuntar a tu DC real."
    else
        fail ".env.example no encontrado en ${PROJECT_DIR}"
        exit 1
    fi
else
    ok ".env ya existe"
fi

# ── Crear directorios de datos persistentes ──────────────────
echo ""
info "Creando directorios de datos..."

DIRS=(
    "reports/ldap"
    "reports/bloodhound"
    "reports/nmap"
    "reports/dns"
    "logs/zeek"
    "logs/suricata"
    "data"
)

for d in "${DIRS[@]}"; do
    mkdir -p "${PROJECT_DIR}/${d}"
    ok "  ${d}/"
done

# ── Permisos de scripts ───────────────────────────────────────
echo ""
info "Configurando permisos de scripts..."

find "${PROJECT_DIR}/scripts" -name "*.sh" -exec chmod +x {} \;
ok "Scripts en scripts/ → chmod +x"

if [[ -f "${PROJECT_DIR}/kali/entrypoint.sh" ]]; then
    chmod +x "${PROJECT_DIR}/kali/entrypoint.sh"
    ok "kali/entrypoint.sh → chmod +x"
fi

if [[ -f "${PROJECT_DIR}/zeek/entrypoint-zeek.sh" ]]; then
    chmod +x "${PROJECT_DIR}/zeek/entrypoint-zeek.sh"
    ok "zeek/entrypoint-zeek.sh → chmod +x"
fi

# ── Verificar vm.max_map_count para OpenSearch ────────────────
echo ""
info "Verificando configuración del kernel para OpenSearch..."

if [[ "$(uname -s)" == "Linux" ]]; then
    current_map=$(cat /proc/sys/vm/max_map_count 2>/dev/null || echo "0")
    if [[ "${current_map}" -lt 262144 ]]; then
        warn "vm.max_map_count=${current_map} (OpenSearch requiere 262144)"
        warn "Ejecuta como root: sysctl -w vm.max_map_count=262144"
        warn "Para persistir: echo 'vm.max_map_count=262144' >> /etc/sysctl.conf"
    else
        ok "vm.max_map_count=${current_map} (OK para OpenSearch)"
    fi
else
    info "Sistema no-Linux detectado. Docker Desktop ajusta vm.max_map_count automáticamente."
    ok "vm.max_map_count: gestionado por Docker Desktop"
fi

# ── Validar docker compose config ────────────────────────────
echo ""
info "Validando docker-compose.yml..."

if docker compose config --quiet 2>&1; then
    ok "docker compose config: válido"
else
    fail "docker-compose.yml tiene errores de sintaxis. Revisa el archivo."
    exit 1
fi

# ── Próximos pasos ────────────────────────────────────────────
echo ""
echo "=================================================="
echo -e "${GREEN} Inicialización completada.${NC}"
echo "=================================================="
echo ""
echo "Próximos pasos:"
echo ""
echo "  1. Edita .env con los datos de tu DC:"
echo "       nano .env"
echo ""
echo "  2. Levanta los servicios:"
echo "       make up"
echo "       # o: docker compose up -d"
echo ""
echo "  3. Verifica que todo está corriendo:"
echo "       make ps"
echo "       make health"
echo ""
echo "  4. Abre shell en Kali para auditoría:"
echo "       make shell"
echo ""
echo "  5. Ejecuta auditoría completa:"
echo "       make audit"
echo "       # o desde el shell Kali:"
echo "       bash /workspace/scripts/safe-audit.sh"
echo ""
echo "  UIs disponibles (después de 'make up'):"
echo "    Neo4j:               http://localhost:7474"
echo "    OpenSearch Dashboards: http://localhost:5601"
echo "    Grafana:             http://localhost:3000"
echo ""
