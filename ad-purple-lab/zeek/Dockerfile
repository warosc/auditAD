FROM ubuntu:22.04

# ============================================================
# Zeek NSM - Imagen propia
# Razón: El proyecto Zeek no mantiene una imagen oficial en
# Docker Hub. Se instala desde el repositorio oficial de Zeek
# en OBS (OpenSUSE Build Service) para Ubuntu 22.04.
# ============================================================

LABEL maintainer="AD Purple Lab"
LABEL description="Zeek Network Security Monitor"

ENV DEBIAN_FRONTEND=noninteractive
ENV ZEEK_HOME=/opt/zeek
ENV PATH="${ZEEK_HOME}/bin:${PATH}"

# ── Proxy corporativo: deshabilitar verificación SSL ──────────
RUN printf 'Acquire::https::Verify-Peer "false";\nAcquire::https::Verify-Host "false";\nAcquire { Check-Valid-Until "false"; };\n' \
    > /etc/apt/apt.conf.d/99no-check-cert

# ── Instalar dependencias base ────────────────────────────────
RUN apt-get update -o Acquire::AllowInsecureRepositories=true && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg2 \
        ca-certificates \
        libpcap0.8 \
        libssl3 \
        libmaxminddb0 \
        python3 \
        python3-git \
        python3-semantic-version \
    && rm -rf /var/lib/apt/lists/*

# ── Agregar repositorio oficial de Zeek ──────────────────────
RUN echo 'deb [trusted=yes] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
        > /etc/apt/sources.list.d/security:zeek.list \
    && curl -fsSLk \
        https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key \
        | gpg --dearmor \
        | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null \
    && apt-get update -o Acquire::AllowInsecureRepositories=true \
    && apt-get install -y --no-install-recommends --allow-unauthenticated zeek \
    && rm -rf /var/lib/apt/lists/*

# ── Crear directorios de logs ─────────────────────────────────
RUN mkdir -p \
    /opt/zeek/logs/current \
    /opt/zeek/logs/archive \
    /var/log/zeek

# ── Copiar entrypoint ─────────────────────────────────────────
COPY entrypoint-zeek.sh /entrypoint-zeek.sh
RUN chmod +x /entrypoint-zeek.sh

WORKDIR /opt/zeek

ENTRYPOINT ["/entrypoint-zeek.sh"]
