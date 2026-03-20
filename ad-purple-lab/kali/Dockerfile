FROM kalilinux/kali-rolling:latest

LABEL maintainer="AD Purple Lab"
LABEL description="Kali Linux - Auditoría segura de Active Directory"

ENV DEBIAN_FRONTEND=noninteractive
ENV WORKSPACE=/workspace
ENV VENV=/opt/adaudit-venv
ENV PATH="${VENV}/bin:${PATH}"

# ── Proxy corporativo: deshabilitar verificación SSL en apt ───
RUN printf 'Acquire::https::Verify-Peer "false";\nAcquire::https::Verify-Host "false";\nAcquire { Check-Valid-Until "false"; };\n' \
    > /etc/apt/apt.conf.d/99no-check-cert

# ── Actualización base + herramientas del sistema ────────────
RUN apt-get update -o Acquire::AllowInsecureRepositories=true && \
    apt-get install -y --no-install-recommends --allow-unauthenticated \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    ldap-utils \
    smbclient \
    krb5-user \
    dnsutils \
    curl \
    wget \
    git \
    jq \
    vim \
    nano \
    netcat-traditional \
    iputils-ping \
    nmap \
    unzip \
    libssl-dev \
    libkrb5-dev \
    libldap2-dev \
    libsasl2-dev \
    build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Crear entorno virtual Python ─────────────────────────────
RUN python3 -m venv ${VENV}

# ── Instalar dependencias Python en el venv ──────────────────
COPY requirements.txt /tmp/requirements.txt
RUN ${VENV}/bin/pip install --upgrade pip setuptools wheel --trusted-host pypi.org --trusted-host files.pythonhosted.org \
    && ${VENV}/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
        --trusted-host pypi.org --trusted-host files.pythonhosted.org \
    && rm /tmp/requirements.txt

# ── Crear estructura de trabajo ──────────────────────────────
RUN mkdir -p \
    ${WORKSPACE}/reports/ldap \
    ${WORKSPACE}/reports/bloodhound \
    ${WORKSPACE}/reports/nmap \
    ${WORKSPACE}/reports/dns \
    ${WORKSPACE}/logs \
    ${WORKSPACE}/data \
    ${WORKSPACE}/scripts

# ── Copiar entrypoint ────────────────────────────────────────
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR ${WORKSPACE}

ENTRYPOINT ["/entrypoint.sh"]
