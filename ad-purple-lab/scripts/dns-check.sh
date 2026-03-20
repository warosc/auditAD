#!/usr/bin/env bash
# ============================================================
# dns-check.sh - Verificación DNS del Domain Controller
# Uso: bash scripts/dns-check.sh
# Se ejecuta dentro del contenedor kali-audit.
# ============================================================
set -euo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
REPORT_DIR="${WORKSPACE}/reports/dns"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${REPORT_DIR}/dns_check_${TIMESTAMP}.txt"

mkdir -p "${REPORT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}  $*" | tee -a "${REPORT_FILE}"; }
fail() { echo -e "${RED}[FAIL]${NC} $*" | tee -a "${REPORT_FILE}"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" | tee -a "${REPORT_FILE}"; }
info() { echo -e "[INFO] $*" | tee -a "${REPORT_FILE}"; }

# ── Cargar variables ──────────────────────────────────────────
# Solo carga archivos de env si el panel NO inyectó DC_IP (ejecución manual)
if [[ -z "${DC_IP:-}" ]]; then
    if [[ -f "${WORKSPACE}/ad_env.sh" ]]; then
        # shellcheck disable=SC1090
        source "${WORKSPACE}/ad_env.sh"
    elif [[ -f "/.env" ]]; then
        # shellcheck disable=SC1090
        source "/.env"
    fi
fi

: "${AD_FQDN:?Variable AD_FQDN no configurada}"
: "${DC_IP:?Variable DC_IP no configurada}"
: "${DNS_SERVER:?Variable DNS_SERVER no configurada}"
: "${AD_DOMAIN:?Variable AD_DOMAIN no configurada}"

echo "=================================================="
echo " DNS Check - $(date)"
echo " DC FQDN   : ${AD_FQDN}"
echo " DC IP     : ${DC_IP}"
echo " DNS Server: ${DNS_SERVER}"
echo "==================================================" | tee "${REPORT_FILE}"

# ── Test 1: Resolución directa del FQDN ──────────────────────
echo "" | tee -a "${REPORT_FILE}"
info "Test 1: Resolución DNS del FQDN del DC"

if resolved_ip=$(nslookup "${AD_FQDN}" "${DNS_SERVER}" 2>/dev/null \
        | grep -A1 "Name:" | grep "Address" | awk '{print $2}'); then
    if [[ "${resolved_ip}" == "${DC_IP}" ]]; then
        ok "${AD_FQDN} resuelve a ${resolved_ip} (coincide con DC_IP)"
    elif [[ -n "${resolved_ip}" ]]; then
        warn "${AD_FQDN} resuelve a ${resolved_ip} (DC_IP configurado: ${DC_IP})"
    fi
else
    fail "No se pudo resolver ${AD_FQDN} via ${DNS_SERVER}"
fi

# ── Test 2: Resolución inversa del DC IP ─────────────────────
echo "" | tee -a "${REPORT_FILE}"
info "Test 2: Resolución inversa (PTR) de ${DC_IP}"

if ptr=$(nslookup "${DC_IP}" "${DNS_SERVER}" 2>/dev/null \
        | grep "name =" | awk '{print $NF}'); then
    if [[ -n "${ptr}" ]]; then
        ok "PTR de ${DC_IP} → ${ptr}"
    else
        warn "Sin registro PTR para ${DC_IP}"
    fi
else
    fail "Resolución inversa fallida para ${DC_IP}"
fi

# ── Test 3: SRV Records de Active Directory ──────────────────
echo "" | tee -a "${REPORT_FILE}"
info "Test 3: SRV Records de Active Directory"

AD_SRV_RECORDS=(
    "_ldap._tcp.${AD_DOMAIN}"
    "_kerberos._tcp.${AD_DOMAIN}"
    "_kerberos._udp.${AD_DOMAIN}"
    "_ldap._tcp.dc._msdcs.${AD_DOMAIN}"
    "_kerberos._tcp.dc._msdcs.${AD_DOMAIN}"
    "_gc._tcp.${AD_DOMAIN}"
)

for srv in "${AD_SRV_RECORDS[@]}"; do
    if dig @"${DNS_SERVER}" SRV "${srv}" +short 2>/dev/null | grep -q "."; then
        ok "SRV ${srv} → OK"
    else
        warn "SRV ${srv} → sin respuesta"
    fi
done

# ── Test 4: Registro A del dominio ────────────────────────────
echo "" | tee -a "${REPORT_FILE}"
info "Test 4: Registro A del dominio ${AD_DOMAIN}"

if dig @"${DNS_SERVER}" A "${AD_DOMAIN}" +short 2>/dev/null | grep -qE "^[0-9]"; then
    domain_ip=$(dig @"${DNS_SERVER}" A "${AD_DOMAIN}" +short | head -1)
    ok "${AD_DOMAIN} resuelve a ${domain_ip}"
else
    warn "Sin registro A directo para ${AD_DOMAIN}"
fi

# ── Test 5: Conectividad al servidor DNS ─────────────────────
echo "" | tee -a "${REPORT_FILE}"
info "Test 5: Conectividad TCP/UDP al servidor DNS (${DNS_SERVER}:53)"

if nc -zw3 "${DNS_SERVER}" 53 2>/dev/null; then
    ok "Puerto TCP 53 alcanzable en ${DNS_SERVER}"
else
    fail "Puerto TCP 53 NO alcanzable en ${DNS_SERVER}"
fi

echo "" | tee -a "${REPORT_FILE}"
echo "Reporte guardado en: ${REPORT_FILE}"
