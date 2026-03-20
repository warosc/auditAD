#!/usr/bin/env bash
# ============================================================
# safe-audit.sh - Auditoría completa y segura de Active Directory
# Uso: bash scripts/safe-audit.sh
# Se ejecuta dentro del contenedor kali-audit.
#
# Ejecuta en orden:
#   1. Validación de variables de entorno
#   2. Verificación DNS
#   3. Pruebas de conectividad TCP a puertos clave AD
#   4. Verificación LDAP autenticada
#   5. ldapdomaindump
#   6. BloodHound collection
#   7. Resumen final de archivos generados
# ============================================================
set -euo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
VENV="${VENV:-/opt/adaudit-venv}"
SCRIPTS_DIR="${WORKSPACE}/scripts"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
SUMMARY_FILE="${WORKSPACE}/reports/audit_summary_${TIMESTAMP}.txt"

mkdir -p "${WORKSPACE}/reports"

# ── Colores ───────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

ok()      { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "${SUMMARY_FILE}"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*" | tee -a "${SUMMARY_FILE}"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "${SUMMARY_FILE}"; }
info()    { echo -e "[INFO]  $*" | tee -a "${SUMMARY_FILE}"; }
section() { echo -e "\n${BLUE}${BOLD}══ $* ══${NC}" | tee -a "${SUMMARY_FILE}"; }
sep()     { echo "──────────────────────────────────────────────────" | tee -a "${SUMMARY_FILE}"; }

AUDIT_ERRORS=0
AUDIT_WARNINGS=0

# ── Rate limiting ─────────────────────────────────────────────
# Pausa entre operaciones que consultan el DC para no sobrecargarlo.
# Configurable en .env con LDAP_DELAY (default: 0.2 seg).
LDAP_DELAY="${LDAP_DELAY:-0.2}"
PORTSCAN_RATE="${PORTSCAN_RATE:-20}"

rate_sleep() {
    # Pausa controlada entre consultas LDAP/AD
    sleep "${LDAP_DELAY}"
}

# ── Cargar variables ──────────────────────────────────────────
# Solo carga ad_env.sh si el panel NO inyectó DC_IP (ejecución manual)
if [[ -z "${DC_IP:-}" && -f "${WORKSPACE}/ad_env.sh" ]]; then
    # shellcheck disable=SC1090
    source "${WORKSPACE}/ad_env.sh"
fi

# ── Banner de inicio ──────────────────────────────────────────
cat <<EOF | tee "${SUMMARY_FILE}"
══════════════════════════════════════════════════════════
 AD Purple Lab - Auditoría Segura
 Fecha  : $(date)
 Host   : $(hostname)
 Dominio: ${AD_DOMAIN:-<no configurado>}
 DC IP  : ${DC_IP:-<no configurado>}
 Usuario: ${AD_USERNAME:-<no configurado>}
 Modo   : SOLO LECTURA | SAFE_MODE=${SAFE_MODE:-true}
══════════════════════════════════════════════════════════
EOF

# ── Paso 1: Validar entorno ───────────────────────────────────
section "Paso 1: Validación de variables de entorno"

if bash "${SCRIPTS_DIR}/validate-env.sh" >> "${SUMMARY_FILE}" 2>&1; then
    ok "Variables de entorno validadas"
else
    fail "Validación de entorno fallida. Abortando auditoría."
    exit 1
fi

# ── Paso 2: Verificación DNS ──────────────────────────────────
section "Paso 2: Verificación DNS"

if bash "${SCRIPTS_DIR}/dns-check.sh"; then
    ok "Verificación DNS completada"
else
    fail "Verificación DNS fallida"
    AUDIT_ERRORS=$((AUDIT_ERRORS + 1))
    warn "Continuando con advertencia..."
fi

# ── Paso 3: Verificación de puertos clave AD ─────────────────
section "Paso 3: Verificación de conectividad TCP a puertos AD"
sep

declare -A AD_PORTS=(
    [53]="DNS"
    [88]="Kerberos"
    [135]="RPC Endpoint Mapper"
    [389]="LDAP"
    [445]="SMB"
    [636]="LDAPS"
    [3268]="Global Catalog LDAP"
    [3269]="Global Catalog LDAPS"
    [5985]="WinRM HTTP"
)

PORT_REPORT="${WORKSPACE}/reports/port_check_${TIMESTAMP}.txt"

if [[ "${ENABLE_PORT_CHECKS:-true}" == "true" ]]; then
    # Usar nmap con rate limiting para no saturar el DC.
    # -T2: timing "polite" (espera entre probes)
    # --max-retries 2: no reintentar excesivamente
    # --min-rate ${PORTSCAN_RATE}: paquetes/seg controlados
    info "Usando nmap con rate limit: ${PORTSCAN_RATE} pkt/s, timing T2"

    NMAP_OUT="${WORKSPACE}/reports/nmap/nmap_ports_${TIMESTAMP}.txt"
    mkdir -p "${WORKSPACE}/reports/nmap"

    if command -v nmap &>/dev/null; then
        nmap -sT \
            -p 53,88,135,389,445,636,3268,3269,5985 \
            --min-rate "${PORTSCAN_RATE}" \
            --max-retries 2 \
            -T2 \
            -oN "${NMAP_OUT}" \
            "${DC_IP}" 2>&1 | tee -a "${SUMMARY_FILE}" || true

        ok "Nmap port scan completado → ${NMAP_OUT}"

        # Extraer resultados al formato de PORT_RESULTS
        PORT_RESULTS=""
        while IFS= read -r line; do
            if [[ "${line}" =~ ^([0-9]+)/tcp[[:space:]]+open ]]; then
                port="${BASH_REMATCH[1]}"
                svc="${AD_PORTS[$port]:-unknown}"
                ok "Puerto ${port}/TCP (${svc}) → ABIERTO"
                PORT_RESULTS+="OPEN:${port}:${svc}\n"
            elif [[ "${line}" =~ ^([0-9]+)/tcp[[:space:]]+closed ]]; then
                port="${BASH_REMATCH[1]}"
                svc="${AD_PORTS[$port]:-unknown}"
                warn "Puerto ${port}/TCP (${svc}) → CERRADO"
                PORT_RESULTS+="CLOSED:${port}:${svc}\n"
                if [[ "${port}" -eq 389 || "${port}" -eq 88 ]]; then
                    fail "Puerto crítico ${port} (${svc}) no alcanzable."
                    AUDIT_ERRORS=$((AUDIT_ERRORS + 1))
                fi
            fi
        done < "${NMAP_OUT}"
    else
        # Fallback a nc si nmap no está disponible
        warn "nmap no encontrado, usando nc (sin rate limit)"
        PORT_RESULTS=""
        for port in 53 88 135 389 445 636 3268 3269 5985; do
            svc="${AD_PORTS[$port]}"
            if nc -zw3 "${DC_IP}" "${port}" 2>/dev/null; then
                ok "Puerto ${port}/TCP (${svc}) → ABIERTO"
                PORT_RESULTS+="OPEN:${port}:${svc}\n"
            else
                warn "Puerto ${port}/TCP (${svc}) → CERRADO"
                PORT_RESULTS+="CLOSED:${port}:${svc}\n"
                if [[ "${port}" -eq 389 || "${port}" -eq 88 ]]; then
                    fail "Puerto crítico ${port} (${svc}) no alcanzable."
                    AUDIT_ERRORS=$((AUDIT_ERRORS + 1))
                fi
            fi
            rate_sleep
        done
    fi

    printf "%b" "${PORT_RESULTS}" > "${PORT_REPORT}"
    info "Resultado de puertos guardado en reports/port_check_${TIMESTAMP}.txt"
else
    warn "ENABLE_PORT_CHECKS=false. Verificación de puertos omitida."
fi

# ── Paso 4: Verificación LDAP ─────────────────────────────────
section "Paso 4: Verificación LDAP autenticada"

info "Rate limit LDAP: ${LDAP_DELAY}s entre consultas"

if bash "${SCRIPTS_DIR}/ldap-check.sh"; then
    ok "Verificación LDAP completada"
else
    fail "Verificación LDAP fallida"
    AUDIT_ERRORS=$((AUDIT_ERRORS + 1))
fi

# Pausa controlada entre módulos para no saturar el DC
rate_sleep

# ── Paso 5: ldapdomaindump ────────────────────────────────────
section "Paso 5: ldapdomaindump"

LDAPDUMP_DIR="${WORKSPACE}/reports/ldapdomaindump_${TIMESTAMP}"
mkdir -p "${LDAPDUMP_DIR}"

if [[ "${ENABLE_LDAP_DUMP:-true}" == "true" ]]; then
    info "Iniciando ldapdomaindump → ${LDAPDUMP_DIR}"

    # shellcheck disable=SC1090
    source "${VENV}/bin/activate"

    # ldapdomaindump requiere DOMAIN\username (no acepta UPN ni DN)
    LDAP_DUMP_NETBIOS="${AD_DOMAIN%%.*}"
    LDAP_DUMP_NETBIOS="${LDAP_DUMP_NETBIOS^^}"
    _BS="\\"; LDAP_DUMP_USER="${LDAP_DUMP_NETBIOS}${_BS}${AD_USERNAME}"

    if ldapdomaindump \
        --user "${LDAP_DUMP_USER}" \
        --password "${AD_PASSWORD}" \
        --outdir "${LDAPDUMP_DIR}" \
        --no-html \
        "ldap://${DC_IP}:${LDAP_PORT:-389}" \
        2>&1 | tee -a "${SUMMARY_FILE}"; then
        ok "ldapdomaindump completado → ${LDAPDUMP_DIR}"
    else
        fail "ldapdomaindump fallido"
        AUDIT_ERRORS=$((AUDIT_ERRORS + 1))
    fi
    # Pausa tras ldapdomaindump
    rate_sleep
else
    warn "ENABLE_LDAP_DUMP=false. ldapdomaindump omitido."
fi

# ── Paso 6: BloodHound collection ────────────────────────────
section "Paso 6: BloodHound collection"

if [[ "${ENABLE_BLOODHOUND:-true}" == "true" ]]; then
    info "BloodHound: threads=${BLOODHOUND_THREADS:-5}, timeout=${BLOODHOUND_TIMEOUT:-30}s"
    if bash "${SCRIPTS_DIR}/bloodhound-collect.sh"; then
        ok "BloodHound collection completada"
    else
        fail "BloodHound collection fallida"
        AUDIT_ERRORS=$((AUDIT_ERRORS + 1))
    fi
else
    warn "ENABLE_BLOODHOUND=false. Colección BloodHound omitida."
fi

# ── Paso 7: Resumen final ─────────────────────────────────────
section "Paso 7: Resumen de archivos generados"

echo "" | tee -a "${SUMMARY_FILE}"
info "Archivos en ${WORKSPACE}/reports:"
find "${WORKSPACE}/reports" -type f -newer "${WORKSPACE}/reports" -ls 2>/dev/null \
    | awk '{print "  " $11 " (" $7 " bytes)"}' \
    | tee -a "${SUMMARY_FILE}" || true

echo "" | tee -a "${SUMMARY_FILE}"
sep
echo "" | tee -a "${SUMMARY_FILE}"

if [[ ${AUDIT_ERRORS} -eq 0 ]]; then
    ok "Auditoría completada. Errores: ${AUDIT_ERRORS} | Advertencias: ${AUDIT_WARNINGS}"
else
    fail "Auditoría completada con ${AUDIT_ERRORS} error(es). Revisa el log."
fi

echo "" | tee -a "${SUMMARY_FILE}"
info "Resumen guardado en: ${SUMMARY_FILE}"
info "Para ver reportes: ls -la ${WORKSPACE}/reports/"
