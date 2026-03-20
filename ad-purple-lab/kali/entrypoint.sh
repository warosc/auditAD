#!/usr/bin/env bash
set -euo pipefail

WORKSPACE="${WORKSPACE:-/workspace}"
VENV="${VENV:-/opt/adaudit-venv}"
AD_ENV_FILE="${WORKSPACE}/ad_env.sh"

# ── Banner ────────────────────────────────────────────────────
cat <<'EOF'
 ____  ____  ____  __  __  ____  __    ____  __      __    __   ____
(  _ \(  _ \(  _ \(  )(  )(  _ \(  )  (  __)  )    /__\  (  ) (  _ \
 )___/ )   / ) __/ )(__)(  )___/ )(__  ) _) )(__   /(__)\  )(   ) _ <
(__)  (__\_)(__)  (____)(__)(__)  (____)(____)(____)(__)(__)(__) (____/

AD Purple Lab - Auditoría Segura de Active Directory
Modo: SOLO LECTURA | Entorno autorizado requerido
EOF

echo ""
echo "[*] Inicializando workspace en ${WORKSPACE}..."

# ── Crear directorios si no existen ──────────────────────────
mkdir -p \
    "${WORKSPACE}/reports/ldap" \
    "${WORKSPACE}/reports/bloodhound" \
    "${WORKSPACE}/reports/nmap" \
    "${WORKSPACE}/reports/dns" \
    "${WORKSPACE}/logs" \
    "${WORKSPACE}/data" \
    "${WORKSPACE}/scripts"

# ── Generar ad_env.sh con exports del entorno ─────────────────
# Este archivo se puede hacer 'source' dentro del contenedor
# para tener las variables disponibles en scripts manuales.
cat > "${AD_ENV_FILE}" <<ENVEOF
#!/usr/bin/env bash
# Generado automáticamente por entrypoint.sh
# Source este archivo para cargar variables de AD en tu shell:
#   source ${AD_ENV_FILE}

export AD_DOMAIN="${AD_DOMAIN:-}"
export AD_FQDN="${AD_FQDN:-}"
export DC_IP="${DC_IP:-}"
export LDAP_PORT="${LDAP_PORT:-389}"
export LDAPS_PORT="${LDAPS_PORT:-636}"
export KERBEROS_REALM="${KERBEROS_REALM:-}"
export AD_USERNAME="${AD_USERNAME:-}"
export AD_PASSWORD="${AD_PASSWORD:-}"
export AD_USER_DN="${AD_USER_DN:-}"
export LDAP_BASE_DN="${LDAP_BASE_DN:-}"
export DNS_SERVER="${DNS_SERVER:-}"
export TARGET_SUBNET="${TARGET_SUBNET:-}"
export SAFE_MODE="${SAFE_MODE:-true}"
export ENABLE_LDAP_DUMP="${ENABLE_LDAP_DUMP:-true}"
export ENABLE_BLOODHOUND="${ENABLE_BLOODHOUND:-true}"
export ENABLE_PORT_CHECKS="${ENABLE_PORT_CHECKS:-true}"

# Activar virtualenv
export VIRTUAL_ENV="${VENV}"
export PATH="${VENV}/bin:\${PATH}"

echo "[+] Variables de AD cargadas."
echo "    DC_IP=\${DC_IP}  DOMAIN=\${AD_DOMAIN}  USER=\${AD_USERNAME}"
ENVEOF

chmod 600 "${AD_ENV_FILE}"
echo "[+] Archivo ad_env.sh generado en ${AD_ENV_FILE}"

# ── Activar virtualenv en .bashrc para sesiones interactivas ──
if ! grep -q "source ${VENV}/bin/activate" /root/.bashrc 2>/dev/null; then
    echo "source ${VENV}/bin/activate" >> /root/.bashrc
    echo "source ${AD_ENV_FILE}" >> /root/.bashrc
    echo 'export PS1="\[\033[1;31m\][ad-purple-lab]\[\033[0m\] \w # "' >> /root/.bashrc
fi

# ── Verificar herramientas disponibles ────────────────────────
echo ""
echo "[*] Verificando herramientas instaladas:"
check_tool() {
    local tool="$1"
    local path
    if path=$(command -v "${tool}" 2>/dev/null); then
        echo "    [OK] ${tool} → ${path}"
    else
        echo "    [--] ${tool} no encontrado en PATH"
    fi
}

check_tool ldapsearch
check_tool ldapdomaindump
check_tool bloodhound-python
check_tool nmap
check_tool smbclient
check_tool nslookup
check_tool dig
check_tool jq

# ── Mostrar estado de configuración ──────────────────────────
echo ""
echo "[*] Configuración de laboratorio:"
echo "    AD_DOMAIN  = ${AD_DOMAIN:-<no configurado>}"
echo "    DC_IP      = ${DC_IP:-<no configurado>}"
echo "    AD_USERNAME= ${AD_USERNAME:-<no configurado>}"
echo "    SAFE_MODE  = ${SAFE_MODE:-true}"
echo ""

if [[ -z "${AD_DOMAIN:-}" || -z "${DC_IP:-}" ]]; then
    echo "[!] ADVERTENCIA: AD_DOMAIN o DC_IP no configurados."
    echo "    Edita .env y reinicia el contenedor para configurar el objetivo."
    echo ""
fi

echo "[*] Scripts disponibles en /workspace/scripts/"
echo "[*] Reportes en /workspace/reports/"
echo "[*] Ejecuta: source /workspace/ad_env.sh  para cargar variables"
echo "[*] Ejecuta: bash /workspace/scripts/safe-audit.sh  para auditoría completa"
echo ""
echo "[+] Shell listo."

# ── Mantener contenedor activo con bash interactivo ──────────
exec /bin/bash
