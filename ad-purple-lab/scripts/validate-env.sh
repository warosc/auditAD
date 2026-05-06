#!/usr/bin/env bash
# ============================================================
# validate-env.sh - Valida variables y conectividad al AD
# Las variables llegan inyectadas por el panel (exec_run).
# Como fallback carga ad_env.sh si DC_IP no está definido.
# ============================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
fail() { echo -e "${RED}[FAIL]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
info() { echo -e "${BLUE}[INFO]${NC}  $*"; }

ERRORS=0

echo "=================================================="
echo " AD Purple Lab - Validación de entorno"
echo " $(date)"
echo "=================================================="
echo ""

# ── Fuente de variables ───────────────────────────────────────
if [[ -n "${DC_IP:-}" ]]; then
    info "Variables inyectadas desde el panel de configuración."
else
    WORKSPACE="${WORKSPACE:-/workspace}"
    if [[ -f "${WORKSPACE}/ad_env.sh" ]]; then
        info "Cargando variables desde ${WORKSPACE}/ad_env.sh (ejecución manual)"
        # shellcheck disable=SC1090
        source "${WORKSPACE}/ad_env.sh"
    else
        fail "No hay variables de entorno inyectadas ni ad_env.sh disponible."
        fail "Configura las credenciales en el panel: Settings → Active Directory"
        exit 1
    fi
fi

# ── Validación de variables ───────────────────────────────────
echo "── Variables críticas de Active Directory ─────────────────"

check_var() {
    local name="$1"
    local critical="${2:-true}"
    local val="${!name:-}"
    if [[ -n "$val" ]]; then
        if [[ "$name" == *PASSWORD* || "$name" == *AUTH* || "$name" == *SECRET* ]]; then
            ok "${name} = [OCULTO]"
        else
            ok "${name} = ${val}"
        fi
    else
        if [[ "$critical" == "true" ]]; then
            fail "${name} no configurado — ir a Settings → Active Directory"
            ERRORS=$((ERRORS + 1))
        else
            warn "${name} no configurado (opcional)"
        fi
    fi
}

check_var "DC_IP"          "true"
check_var "AD_DOMAIN"      "true"
check_var "AD_FQDN"        "true"
check_var "AD_USERNAME"    "true"
check_var "AD_PASSWORD"    "true"
check_var "LDAP_BASE_DN"   "true"

echo ""
echo "── Variables de red ───────────────────────────────────────"
check_var "DNS_SERVER"     "true"
check_var "TARGET_SUBNET"  "false"

echo ""
echo "── Variables de control ───────────────────────────────────"
check_var "SAFE_MODE"          "false"
check_var "ENABLE_LDAP_DUMP"   "false"
check_var "ENABLE_BLOODHOUND"  "false"

# ── Validaciones de formato ───────────────────────────────────
echo ""
echo "── Validaciones de formato ────────────────────────────────"

if [[ -n "${DC_IP:-}" ]]; then
    if [[ "${DC_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        ok "DC_IP '${DC_IP}' tiene formato IPv4 válido"
    else
        fail "DC_IP '${DC_IP}' no es una IPv4 válida"
        ERRORS=$((ERRORS + 1))
    fi
fi

if [[ "${SAFE_MODE:-true}" != "true" ]]; then
    warn "SAFE_MODE='${SAFE_MODE}' — no es 'true'. Algunas acciones podrían modificar el AD."
else
    ok "SAFE_MODE=true — modo de solo lectura activo"
fi

if [[ -n "${LDAP_BASE_DN:-}" ]]; then
    if [[ "${LDAP_BASE_DN}" =~ ^DC= ]]; then
        ok "LDAP_BASE_DN '${LDAP_BASE_DN}' tiene formato válido"
    else
        fail "LDAP_BASE_DN '${LDAP_BASE_DN}' no tiene el formato DC=... esperado"
        ERRORS=$((ERRORS + 1))
    fi
fi

# ── Conectividad de red al DC ─────────────────────────────────
if [[ ${ERRORS} -eq 0 && -n "${DC_IP:-}" ]]; then
    echo ""
    echo "── Conectividad al DC ${DC_IP} ────────────────────────────"

    check_port() {
        local port="$1"
        local label="$2"
        if nc -zv -w3 "${DC_IP}" "${port}" 2>/dev/null; then
            ok "Puerto ${port}/tcp (${label}) abierto"
        else
            warn "Puerto ${port}/tcp (${label}) no alcanzable (DC apagado o firewall)"
        fi
    }

    check_port 53  "DNS"
    check_port 88  "Kerberos"
    check_port 135 "RPC"
    check_port 389 "LDAP"
    check_port 445 "SMB"
    check_port 636 "LDAPS"

    # Resolución DNS del DC
    echo ""
    info "Resolución DNS de ${AD_FQDN:-$DC_IP}:"
    if command -v dig &>/dev/null; then
        dig +short "${AD_FQDN:-${DC_IP}}" @"${DNS_SERVER:-${DC_IP}}" 2>/dev/null | head -3 || warn "Sin respuesta DNS"
    else
        nslookup "${AD_FQDN:-${DC_IP}}" "${DNS_SERVER:-${DC_IP}}" 2>/dev/null | grep "Address:" | tail -1 || warn "Sin respuesta DNS"
    fi

    # LDAP bind anónimo (sólo para verificar conectividad, no credenciales)
    echo ""
    info "Verificando conectividad LDAP..."
    VENV="${VENV:-/opt/adaudit-venv}"
    if [[ -f "${VENV}/bin/activate" ]]; then
        source "${VENV}/bin/activate"
        python3 - <<PYEOF 2>/dev/null && ok "LDAP bind anónimo exitoso (DC responde en ${DC_IP}:389)" || warn "LDAP no responde o requiere autenticación para bind"
import socket, struct, sys
try:
    s = socket.create_connection(("${DC_IP}", 389), timeout=5)
    # LDAP bind request anónima (versión 3, sin credenciales)
    msg = bytes.fromhex('300c020101600702010304008000')
    s.send(msg)
    resp = s.recv(128)
    s.close()
    sys.exit(0 if len(resp) > 0 else 1)
except Exception as e:
    sys.exit(1)
PYEOF
    fi

    # ── Política de bloqueo de cuentas ──────────────────────────────────────
    # Un lockoutThreshold bajo + auditorías programadas con credenciales
    # incorrectas puede bloquear la cuenta de auditoría.
    if [[ -n "${AD_USERNAME:-}" && -n "${AD_PASSWORD:-}" && -n "${LDAP_BASE_DN:-}" ]]; then
        echo ""
        echo "── Política de bloqueo de cuentas del dominio ─────────────────"
        info "Consultando lockoutThreshold y minPwdLength vía LDAP..."

        LOCKOUT_RAW=$(ldapsearch -x \
            -H "ldap://${DC_IP}:${LDAP_PORT:-389}" \
            -D "${AD_USERNAME}@${AD_DOMAIN}" \
            -w "${AD_PASSWORD}" \
            -b "${LDAP_BASE_DN}" \
            "(objectClass=domainDNS)" \
            lockoutThreshold minPwdLength 2>/dev/null || echo "")

        if [[ -z "${LOCKOUT_RAW}" ]]; then
            warn "No se pudo consultar la política de dominio. Si las credenciales son incorrectas"
            warn "  y hay auditorías programadas, existe riesgo de lockout de la cuenta de auditoría."
        else
            LOCKOUT_THRESHOLD=$(echo "${LOCKOUT_RAW}" | grep "^lockoutThreshold:" | awk '{print $2}' || echo "")
            MIN_PWD_LEN=$(echo "${LOCKOUT_RAW}" | grep "^minPwdLength:" | awk '{print $2}' || echo "")

            if [[ -z "${LOCKOUT_THRESHOLD}" ]]; then
                warn "lockoutThreshold: no devuelto (requiere permisos de lectura sobre el objeto de dominio)"
            elif [[ "${LOCKOUT_THRESHOLD}" -eq 0 ]]; then
                ok "lockoutThreshold = 0 — sin bloqueo de cuentas (entorno de laboratorio confirmado)"
            elif [[ "${LOCKOUT_THRESHOLD}" -lt 10 ]]; then
                fail "lockoutThreshold = ${LOCKOUT_THRESHOLD} — RIESGO ALTO de lockout de la cuenta de auditoría."
                fail "  Con auditorías programadas y credenciales incorrectas se alcanzará el límite."
                fail "  Verifica AD_PASSWORD en Settings antes de activar el scheduler."
                ERRORS=$((ERRORS + 1))
            else
                ok "lockoutThreshold = ${LOCKOUT_THRESHOLD} — margen suficiente para auditorías"
            fi

            if [[ -n "${MIN_PWD_LEN}" ]]; then
                [[ "${MIN_PWD_LEN}" -lt 12 ]] \
                    && warn "minPwdLength = ${MIN_PWD_LEN} — política débil (recomendado ≥14)" \
                    || ok  "minPwdLength = ${MIN_PWD_LEN} — política aceptable"
            fi
        fi
    fi
fi

# ── Herramientas disponibles ──────────────────────────────────
echo ""
echo "── Herramientas en kali-audit ─────────────────────────────"
VENV="${VENV:-/opt/adaudit-venv}"
[[ -f "${VENV}/bin/activate" ]] && source "${VENV}/bin/activate" 2>/dev/null || true

for tool in bloodhound-python ldapdomaindump nmap dig nc python3; do
    if command -v "$tool" &>/dev/null; then
        ver=$("$tool" --version 2>&1 | head -1 | cut -c1-60 || echo "ok")
        ok "${tool}: ${ver}"
    else
        warn "${tool}: no encontrado"
    fi
done

# ── Resultado final ────────────────────────────────────────────
echo ""
echo "=================================================="
if [[ ${ERRORS} -eq 0 ]]; then
    echo -e "${GREEN}[PASS] Entorno validado correctamente. Listo para auditar.${NC}"
    echo ""
    echo "  Siguiente paso recomendado:"
    echo "    → Auditoría AD → 2. DNS Check"
    exit 0
else
    echo -e "${RED}[FAIL] ${ERRORS} error(es) encontrados.${NC}"
    echo "  Corrige en: Panel → Settings → Active Directory"
    exit 1
fi
