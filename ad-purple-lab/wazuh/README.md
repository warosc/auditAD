# Wazuh - Detección desde Active Directory

Este módulo agrega Wazuh Manager al stack de AD Purple Lab para recibir eventos
de seguridad directamente desde el Domain Controller.

---

## Arquitectura

```
Domain Controller (Windows)
  └── Wazuh Agent (instalado manualmente)
        │  eventos Security/System/DNS
        │  puerto 1514/tcp
        ▼
  wazuh-manager (contenedor)
        │  /var/ossec/logs/alerts/alerts.json
        │
        ▼
  OpenSearch ← Filebeat con módulo Wazuh
        │
        ▼
  Grafana / OpenSearch Dashboards
```

---

## Decisión técnica

Este proyecto usa OpenSearch 2.12.0 (ya existente en el stack principal).
**No se despliega wazuh-indexer** para evitar duplicar la base de datos.

La integración con OpenSearch se realiza mediante **Filebeat** con el módulo
`wazuh`, que lee `alerts.json` y lo indexa en OpenSearch.

**Limitación**: El contenedor `wazuh-manager` de por sí no envía datos
automáticamente a OpenSearch. Necesitas Filebeat como sidecar o servicio
adicional. Ver sección "Configurar Filebeat".

---

## Levantar Wazuh Manager

```bash
# Opción A: Override manual
docker compose \
    -f docker-compose.yml \
    -f wazuh/docker-compose.override.yml \
    up -d wazuh-manager

# Opción B: Usando make
make wazuh

# Verificar estado
docker logs wazuh-manager
```

---

## Instalar Wazuh Agent en el Domain Controller (Windows)

### Paso 1: Descargar el instalador

En el Domain Controller, abre PowerShell como Administrador:

```powershell
# Descargar Wazuh Agent 4.7.3 para Windows
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi" `
    -OutFile "C:\Temp\wazuh-agent.msi"
```

### Paso 2: Instalar y apuntar al Manager

Reemplaza `WAZUH_MANAGER_IP` con la IP del host donde corre Docker:

```powershell
# Instalar en modo silencioso apuntando al manager
msiexec /i "C:\Temp\wazuh-agent.msi" /q `
    WAZUH_MANAGER="192.168.1.100" `
    WAZUH_MANAGER_PORT="1514" `
    WAZUH_AGENT_NAME="DC01-corp-local" `
    WAZUH_REGISTRATION_SERVER="192.168.1.100" `
    WAZUH_REGISTRATION_PORT="1515"
```

### Paso 3: Iniciar el servicio del agente

```powershell
NET START WazuhSvc

# Verificar estado
Get-Service WazuhSvc
```

### Paso 4: Verificar conexión en el manager

```bash
# Listar agentes conectados:
docker exec wazuh-manager /var/ossec/bin/agent_control -lc
```

### Paso 5: Verificar que llegan eventos

```bash
# Ver alertas en tiempo real:
docker exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json

# Ver logs del manager:
docker exec wazuh-manager tail -f /var/ossec/logs/ossec.log
```

---

## Eventos de Windows que se recolectan

| Event ID | Descripción | Relevancia |
|---|---|---|
| 4624 | Logon exitoso | Seguimiento de accesos |
| 4625 | Logon fallido | Detección de ataques de contraseña |
| 4634 | Logoff | Sesiones completadas |
| 4648 | Logon con credenciales explícitas | Pass-the-Hash sospechoso |
| 4672 | Privilegios especiales asignados | Escalada de privilegios |
| 4688 | Proceso creado | Ejecución de comandos |
| 4698 | Tarea programada creada | Persistencia |
| 4720 | Cuenta de usuario creada | Creación de backdoor |
| 4722 | Cuenta habilitada | Reactivación de cuentas |
| 4723 | Intento de cambio de contraseña | Modificación de credenciales |
| 4726 | Cuenta eliminada | Borrado de evidencia |
| 4728/4732/4756 | Miembro agregado a grupo | Escalada de privilegios |
| 4768 | Kerberos AS-REQ (TGT request) | Solicitud de TGT |
| 4769 | Kerberos TGS-REQ | Solicitud de service ticket |
| 4771 | Kerberos pre-auth fallida | Posible AS-REP Roasting |
| 4776 | Validación de credenciales NTLM | Autenticación NTLM |

---

## Configurar Filebeat para ingestar en OpenSearch

### Requisitos

- Filebeat 7.17.x (compatible con OpenSearch 2.x vía API Elasticsearch v7)
- **No uses Filebeat 8.x**: usa APIs Elasticsearch v8 que OpenSearch no soporta completamente

### Agregar Filebeat al compose

Agrega este servicio a `wazuh/docker-compose.override.yml`:

```yaml
filebeat-wazuh:
  image: docker.elastic.co/beats/filebeat:7.17.18
  container_name: filebeat-wazuh
  user: root
  volumes:
    - ../logs/wazuh:/var/ossec/logs/alerts:ro
    - ./config/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
  networks:
    - purple_net
  depends_on:
    - wazuh-manager
  restart: unless-stopped
```

### Configuración de Filebeat (`wazuh/config/filebeat.yml`)

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
    json.add_error_key: true
    json.message_key: full_log

output.elasticsearch:
  hosts: ["http://opensearch:9200"]
  index: "wazuh-alerts-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "wazuh"
setup.template.pattern: "wazuh-alerts-*"
```

---

## Limitaciones reales

1. **wazuh-manager standalone no indexa automáticamente**: Las alertas van a `/var/ossec/logs/alerts/alerts.json`. Necesitas Filebeat o similar para enviarlas a OpenSearch.

2. **Wazuh Agent requiere conectividad de red al puerto 1514**: Si el DC está en una red diferente a la del host Docker, necesitas configurar las reglas de firewall correspondientes.

3. **TLS**: La configuración de este lab deshabilita TLS para simplificar. En entornos reales, habilitar TLS entre agente y manager.

4. **Sin respuestas activas**: `active-response` está deshabilitado por diseño. Este es un laboratorio de detección, no de respuesta automatizada.
