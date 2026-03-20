#!/usr/bin/env bash
set -euo pipefail

ZEEK_HOME="${ZEEK_HOME:-/opt/zeek}"
IFACE="${CAPTURE_INTERFACE:-eth0}"
LOG_DIR="${ZEEK_HOME}/logs/current"

echo "[zeek] Iniciando Zeek NSM en interfaz: ${IFACE}"
echo "[zeek] Logs en: ${LOG_DIR}"

mkdir -p "${LOG_DIR}"
cd "${LOG_DIR}"

# Zeek escribe logs en el directorio de trabajo actual.
# En modo bridge Docker, captura solo tráfico del contenedor zeek.
# Para captura completa del host, usar network_mode: host en compose.
exec "${ZEEK_HOME}/bin/zeek" \
    -i "${IFACE}" \
    "${ZEEK_HOME}/share/zeek/site/local.zeek" \
    -C
