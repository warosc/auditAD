#!/usr/bin/env bash
# ============================================================
# ldap-check.sh - Verificación y enumeración LDAP autenticada
# Uso: bash scripts/ldap-check.sh
# Se ejecuta dentro del contenedor kali-audit.
# Requiere: ldap-utils instalado (ldapsearch)
# ============================================================
set -euo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
REPORT_DIR="${WORKSPACE}/reports/ldap"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${REPORT_DIR}/ldap_check_${TIMESTAMP}.txt"

mkdir -p "${REPORT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $*" | tee -a "${REPORT_FILE}"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" | tee -a "${REPORT_FILE}"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "${REPORT_FILE}"; }
info() { echo "[INFO] $*" | tee -a "${REPORT_FILE}"; }

# ── Cargar variables ──────────────────────────────────────────
# Solo carga ad_env.sh si el panel NO inyectó DC_IP (ejecución manual)
if [[ -z "${DC_IP:-}" && -f "${WORKSPACE}/ad_env.sh" ]]; then
    # shellcheck disable=SC1090
    source "${WORKSPACE}/ad_env.sh"
fi

: "${DC_IP:?DC_IP no configurado}"
: "${AD_USERNAME:?AD_USERNAME no configurado}"
: "${AD_PASSWORD:?AD_PASSWORD no configurado}"
: "${LDAP_BASE_DN:?LDAP_BASE_DN no configurado}"
# Derivar AD_USER_DN si no fue inyectado (UPN: user@domain)
AD_USER_DN="${AD_USER_DN:-${AD_USERNAME}@${AD_DOMAIN:-}}"
: "${AD_USER_DN:?AD_USER_DN no configurado (y AD_DOMAIN tampoco)}"

LDAP_PORT="${LDAP_PORT:-389}"

echo "=================================================="
echo " LDAP Check - $(date)"
echo " DC        : ${DC_IP}:${LDAP_PORT}"
echo " Usuario   : ${AD_USERNAME}"
echo " Base DN   : ${LDAP_BASE_DN}"
echo "==================================================" | tee "${REPORT_FILE}"

# Helper: ejecutar ldapsearch y guardar resultado
run_ldap() {
    local desc="$1"
    local filter="$2"
    local attrs="$3"
    local outfile="${REPORT_DIR}/${4}"

    info "Consulta: ${desc}"
    if ldapsearch \
        -x \
        -H "ldap://${DC_IP}:${LDAP_PORT}" \
        -D "${AD_USER_DN}" \
        -w "${AD_PASSWORD}" \
        -b "${LDAP_BASE_DN}" \
        "${filter}" \
        ${attrs} \
        > "${outfile}" 2>&1; then
        local count
        count=$(grep -c "^dn:" "${outfile}" || true)
        ok "${desc} → ${count} objeto(s) encontrado(s) → ${outfile}"
    else
        fail "${desc} → Falló. Ver ${outfile}"
    fi
}

# ── Test 1: Bind autenticado (RootDSE) ───────────────────────
echo "" | tee -a "${REPORT_FILE}"
info "Test 1: Bind LDAP autenticado"

ROOTDSE_FILE="${REPORT_DIR}/rootdse_${TIMESTAMP}.txt"
if ldapsearch \
    -x \
    -H "ldap://${DC_IP}:${LDAP_PORT}" \
    -D "${AD_USER_DN}" \
    -w "${AD_PASSWORD}" \
    -s base \
    -b "" \
    "objectclass=*" \
    > "${ROOTDSE_FILE}" 2>&1; then
    ok "Bind autenticado exitoso → ${ROOTDSE_FILE}"
    # Extraer información clave del RootDSE
    for attr in defaultNamingContext dnsHostName forestFunctionality domainFunctionality; do
        val=$(grep "^${attr}:" "${ROOTDSE_FILE}" | head -1 | cut -d' ' -f2- || true)
        [[ -n "${val}" ]] && info "  ${attr}: ${val}"
    done
else
    fail "Bind LDAP fallido. Verificar credenciales y conectividad."
    cat "${ROOTDSE_FILE}" | tee -a "${REPORT_FILE}"
    exit 1
fi

# ── Test 2: Enumerar Domain Admins ───────────────────────────
echo "" | tee -a "${REPORT_FILE}"
run_ldap \
    "Domain Admins" \
    "(&(objectClass=group)(cn=Domain Admins))" \
    "cn member sAMAccountName description" \
    "domain_admins_${TIMESTAMP}.txt"

# ── Test 3: Enumerar cuentas de usuario activas ──────────────
echo "" | tee -a "${REPORT_FILE}"
run_ldap \
    "Usuarios activos (máx 200)" \
    "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
    "sAMAccountName displayName mail userAccountControl memberOf" \
    "users_active_${TIMESTAMP}.txt"

# ── Test 4: Enumerar cuentas de computadora ──────────────────
echo "" | tee -a "${REPORT_FILE}"
run_ldap \
    "Cuentas de computadora" \
    "(objectClass=computer)" \
    "cn dNSHostName operatingSystem operatingSystemVersion lastLogon" \
    "computers_${TIMESTAMP}.txt"

# ── Test 5: Enumerar grupos de seguridad ─────────────────────
echo "" | tee -a "${REPORT_FILE}"
run_ldap \
    "Grupos de seguridad" \
    "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))" \
    "cn sAMAccountName description member" \
    "security_groups_${TIMESTAMP}.txt"

# ── Test 6: Políticas de contraseña ─────────────────────────
echo "" | tee -a "${REPORT_FILE}"
run_ldap \
    "Política de contraseñas del dominio" \
    "(objectClass=domainDNS)" \
    "minPwdLength maxPwdAge lockoutThreshold lockoutDuration" \
    "password_policy_${TIMESTAMP}.txt"

# ── Test 7: GPOs ──────────────────────────────────────────────
echo "" | tee -a "${REPORT_FILE}"
run_ldap \
    "Group Policy Objects (GPOs)" \
    "(objectClass=groupPolicyContainer)" \
    "cn displayName gPCFileSysPath" \
    "gpos_${TIMESTAMP}.txt"

echo "" | tee -a "${REPORT_FILE}"
echo "=================================================="
echo "Todos los reportes LDAP en: ${REPORT_DIR}"
ls -lh "${REPORT_DIR}/"*"${TIMESTAMP}"*.txt 2>/dev/null || true
