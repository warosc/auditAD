# AD Purple Lab

Laboratorio dockerizado de auditoría segura de Active Directory y monitoreo defensivo.

**Uso exclusivo en entornos de laboratorio autorizados.**
Este proyecto no contiene herramientas ofensivas. Todas las operaciones son de solo lectura sobre el directorio.

---

## Propósito

AD Purple Lab es un entorno reproducible para:

- Auditar la exposición de un Active Directory desde la perspectiva de un analista autorizado
- Visualizar relaciones entre objetos AD con BloodHound y Neo4j
- Capturar y analizar tráfico de red con Zeek y Suricata en un contexto de laboratorio
- Correlacionar alertas y logs en OpenSearch y Grafana
- Documentar hallazgos de forma estructurada

**No incluye**: bruteforce, relay attacks, exploits, movimiento lateral, evasión de detección ni ninguna capacidad ofensiva activa.

---

## Arquitectura Purple Team

```
┌──────────────────────────────────────────────────────────────────┐
│                         Docker Host                              │
│                                                                  │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │  kali-audit  │   │    neo4j     │   │     opensearch       │ │
│  │  Kali Linux  │──▶│  port 7474   │   │     port 9200        │ │
│  │  ldap/bh/nmap│   │  port 7687   │   └──────────────────────┘ │
│  └──────────────┘   │  BloodHound  │   ┌──────────────────────┐ │
│         │           └──────────────┘   │  opensearch-dashbrd  │ │
│         │ auditoría LDAP                │     port 5601        │ │
│         │                              └──────────────────────┘ │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │    zeek      │   │  suricata    │   │       grafana        │ │
│  │  NSM/ad_log  │   │  IDS alerts  │   │     port 3000        │ │
│  │  (bridge*)   │   │  eve.json    │   │  dashboards JSON     │ │
│  └──────────────┘   └──────────────┘   └──────────────────────┘ │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  wazuh-manager (opcional, ver wazuh/)                    │   │
│  │  port 1514 (agentes)  port 1515 (enroll)  port 55000 API │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         purple_net (172.20.0.0/24)               │
└──────────────────────────────────────────────────────────────────┘
                               │
                               │ red externa del host
                               │
              ┌────────────────▼────────────────┐
              │      Domain Controller          │
              │      DC_IP=192.168.1.10         │
              │                                 │
              │  ┌─────────────────────────┐    │
              │  │  Wazuh Agent (Windows)  │────┼──▶ wazuh-manager:1514
              │  │  eventos Security/System│    │
              │  │  4624/4625/4672/4768... │    │
              │  └─────────────────────────┘    │
              └─────────────────────────────────┘
```

### Decisiones técnicas

| Componente | Elección | Razón |
|---|---|---|
| Log backend | OpenSearch 2.12 | Licencia Apache 2.0, sin restricciones comerciales, API compatible con Grafana y Kibana |
| Neo4j | 5.18-community | Edición gratuita, estable para BloodHound classic |
| Zeek | Dockerfile propio (Ubuntu 22.04) | Sin imagen oficial mantenida en Docker Hub; se instala desde repo oficial zeek.org |
| Suricata | `jasonish/suricata:7-latest` | Imagen comunitaria activamente mantenida; no existe imagen oficial del proyecto Suricata |
| Grafana | 10.3.3 | Plugin `grafana-opensearch-datasource` instalado automáticamente; dashboards JSON provisionados |
| Wazuh | `wazuh/wazuh-manager:4.7.3` + overlay | Standalone manager reutilizando OpenSearch existente; sin wazuh-indexer duplicado |
| Captura de tráfico | Bridge mode (limitado) | Ver sección "Limitaciones reales" |
| Rate limiting | nmap -T2 + sleep LDAP_DELAY | Evita sobrecargar el DC con ráfagas de consultas |

---

## Prerequisitos

| Requisito | Versión mínima | Notas |
|---|---|---|
| Docker Engine o Docker Desktop | 24.x o superior | `docker --version` |
| Docker Compose v2 | 2.20+ | `docker compose version` |
| RAM libre | 6 GB mínimo | OpenSearch + Neo4j son los más exigentes |
| Disco | 10 GB libre | Para imágenes, logs y reportes |
| Sistema operativo | Linux, macOS, Windows 11 (WSL2) | |

### En Linux: configurar `vm.max_map_count` para OpenSearch

```bash
sudo sysctl -w vm.max_map_count=262144
# Para persistir al reinicio:
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

En **Docker Desktop** (macOS/Windows) esto se configura automáticamente.

---

## Instalación

```bash
git clone <url-del-repo> ad-purple-lab
cd ad-purple-lab
make init
```

`make init` hace lo siguiente:
- Verifica Docker y Docker Compose
- Crea `.env` desde `.env.example` si no existe
- Crea directorios de datos: `reports/`, `logs/`, `data/`
- Configura permisos de scripts
- Valida `docker-compose.yml` con `docker compose config`

---

## Configuración del entorno (`.env`)

Edita `.env` con los datos de **tu** laboratorio:

```bash
nano .env
```

Variables críticas:

```env
# Datos del Domain Controller de tu laboratorio
AD_DOMAIN=corp.local
AD_FQDN=dc01.corp.local
DC_IP=192.168.1.10           # IP real de tu DC

# Cuenta de auditoría (solo lectura, creada en tu DC)
AD_USERNAME=audit.user
AD_PASSWORD=TuPasswordAqui
AD_USER_DN=CN=audit.user,CN=Users,DC=corp,DC=local
LDAP_BASE_DN=DC=corp,DC=local

# Servidor DNS (generalmente el mismo DC)
DNS_SERVER=192.168.1.10

# Credencial de Neo4j (cambia la por defecto)
NEO4J_AUTH=neo4j/TuPasswordNeo4j
```

### Cuenta de auditoría recomendada en Active Directory

Crea una cuenta de **solo lectura** en tu DC antes de usar este lab:

```powershell
# En el Domain Controller (PowerShell como admin)
New-ADUser -Name "audit.user" -SamAccountName "audit.user" `
    -UserPrincipalName "audit.user@corp.local" `
    -AccountPassword (ConvertTo-SecureString "ChangeMe123!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true

# Agregar a Domain Users (acceso de lectura básico)
# NO agregar a Domain Admins
Add-ADGroupMember -Identity "Domain Users" -Members "audit.user"
```

---

## Levantado de servicios

```bash
# Primera vez: construye imágenes y levanta
make build
make up

# Verificar estado
make ps
make health
```

### Tiempos de arranque esperados

| Servicio | Tiempo aproximado |
|---|---|
| kali-audit | 2-5 min (primera vez, descarga imagen y compila pip) |
| neo4j | 30-60 seg |
| opensearch | 60-90 seg |
| opensearch-dashboards | 90-120 seg |
| grafana | 20-30 seg |
| zeek | 30-60 seg (primera vez, compila desde paquetes) |
| suricata | 20-30 seg |

```bash
# Esperar a que todos estén healthy:
watch -n5 'docker compose ps'
```

---

## Interfaces web

| Servicio | URL | Usuario / Contraseña |
|---|---|---|
| Neo4j Browser | http://localhost:7474 | `neo4j` / valor de `NEO4J_AUTH` en `.env` |
| OpenSearch Dashboards | http://localhost:5601 | Sin autenticación (lab) |
| Grafana | http://localhost:3000 | `admin` / `admin` |
| OpenSearch API | http://localhost:9200 | Sin autenticación (lab) |

---

## Ejecución de auditoría segura

### Opción 1: Auditoría completa automática

```bash
make audit
```

Ejecuta en secuencia: validación → DNS → puertos → LDAP → ldapdomaindump → BloodHound.

### Opción 2: Shell interactivo en Kali

```bash
make shell
# Dentro del contenedor:
source /workspace/ad_env.sh
bash /workspace/scripts/safe-audit.sh
```

### Opción 3: Pasos individuales

```bash
make validate      # Validar variables .env
make dns-check     # Solo verificación DNS
make ldap-check    # Solo verificación LDAP
make bloodhound    # Solo colección BloodHound
```

### Comandos de prueba rápida

```bash
# Verificar conectividad al DC desde kali-audit:
docker exec kali-audit ping -c3 ${DC_IP}

# Verificar LDAP manualmente:
docker exec kali-audit ldapsearch \
    -x -H ldap://${DC_IP} \
    -D "CN=audit.user,CN=Users,DC=corp,DC=local" \
    -w "TuPassword" \
    -b "DC=corp,DC=local" \
    "(objectClass=domainDNS)" \
    dc

# Verificar que Neo4j responde:
curl -s http://localhost:7474

# Verificar OpenSearch:
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
```

---

## Ubicación de reportes

Todos los reportes se generan en `./reports/` (montado en `/workspace/reports/` dentro del contenedor):

```
reports/
├── audit_summary_YYYYMMDD_HHMMSS.txt     # Resumen de auditoría completa
├── dns/
│   └── dns_check_YYYYMMDD_HHMMSS.txt     # Resultados DNS
├── ldap/
│   ├── rootdse_*.txt                     # RootDSE del DC
│   ├── users_active_*.txt                # Usuarios activos
│   ├── domain_admins_*.txt               # Miembros de Domain Admins
│   ├── computers_*.txt                   # Equipos del dominio
│   ├── security_groups_*.txt             # Grupos de seguridad
│   ├── password_policy_*.txt             # Política de contraseñas
│   └── gpos_*.txt                        # GPOs del dominio
├── bloodhound/
│   └── YYYYMMDD_HHMMSS/
│       ├── *.zip                         # Importar en BloodHound
│       └── bloodhound_run_*.log          # Log de ejecución
├── ldapdomaindump_YYYYMMDD_HHMMSS/
│   ├── domain_users.json
│   ├── domain_groups.json
│   ├── domain_computers.json
│   └── domain_policy.json
└── port_check_*.txt                      # Estado de puertos AD
```

### Importar BloodHound en Neo4j

1. Abre http://localhost:7474 en el navegador
2. Conecta con usuario/contraseña de `NEO4J_AUTH`
3. Descarga BloodHound desde: https://github.com/BloodHoundAD/BloodHound/releases
4. Configura BloodHound para conectar a `bolt://localhost:7687`
5. Usa "Upload Data" y selecciona el `.zip` generado en `reports/bloodhound/`

---

## Detección desde Active Directory (Wazuh)

Wazuh Manager permite recibir eventos de seguridad de Windows directamente
desde el Domain Controller, sin depender de captura de tráfico.

### Levantar Wazuh Manager

```bash
make wazuh
# o:
docker compose -f docker-compose.yml \
               -f wazuh/docker-compose.override.yml up -d wazuh-manager
```

### Instalar Wazuh Agent en el Domain Controller

En el DC Windows (PowerShell como Administrador):

```powershell
# 1. Descargar installer
Invoke-WebRequest `
    -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi" `
    -OutFile "C:\Temp\wazuh-agent.msi"

# 2. Instalar apuntando al host Docker (reemplaza con tu IP)
msiexec /i "C:\Temp\wazuh-agent.msi" /q `
    WAZUH_MANAGER="192.168.1.100" `
    WAZUH_MANAGER_PORT="1514" `
    WAZUH_AGENT_NAME="DC01-corp-local"

# 3. Iniciar servicio
NET START WazuhSvc
```

### Verificar eventos recibidos

```bash
# Ver alertas en tiempo real
docker exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json

# Listar agentes conectados
make wazuh-status
```

### Eventos de Windows monitoreados

| Event ID | Descripción |
|---|---|
| 4624 | Logon exitoso |
| 4625 | Logon fallido |
| 4648 | Logon con credenciales explícitas |
| 4672 | Privilegios especiales asignados |
| 4688 | Proceso creado |
| 4720/4726 | Cuenta creada/eliminada |
| 4728/4732/4756 | Cambios en grupos |
| 4768 | Kerberos AS-REQ (solicitud TGT) |
| 4769 | Kerberos TGS-REQ (service ticket) |
| 4771 | Kerberos pre-auth fallida |
| 4776 | Validación NTLM |

Ver `wazuh/README.md` para configuración completa y Filebeat.

---

## Interpretación de eventos de seguridad

### Eventos Kerberos críticos

| Patrón | Posible indicador |
|---|---|
| Muchos 4768 desde una IP | Enumeración de usuarios (AS-REP Roasting) |
| 4771 repetidos | Intentos fallidos de autenticación Kerberos |
| 4769 para `krbtgt` | Posible Golden Ticket |
| 4769 para muchos servicios | Kerberoasting |

### Eventos LDAP (Zeek ad_activity.log)

| event_type | Descripción |
|---|---|
| `ANONYMOUS_BIND` | Intento de bind sin credenciales |
| `SEARCH_REQUEST` | Consulta LDAP con filtro específico |
| `BIND_REQUEST` | Intento de autenticación LDAP |

### Alertas Suricata

Los SIDs 9000001-9000050 son de `local.rules` (alertas AD estándar).
Los SIDs 1000001-1000099 son de `custom.rules` (alertas de tráfico por volumen).

---

## Rate Limiting de auditoría

Para no sobrecargar el Domain Controller, configura en `.env`:

```env
LDAP_DELAY=0.2        # segundos de pausa entre consultas LDAP
PORTSCAN_RATE=20      # paquetes/seg para nmap
BLOODHOUND_THREADS=5  # hilos de BloodHound
BLOODHOUND_TIMEOUT=30 # timeout por operación BloodHound
```

El script `safe-audit.sh` aplica estas variables automáticamente:
- nmap usa `-T2 --max-retries 2 --min-rate ${PORTSCAN_RATE}`
- `sleep ${LDAP_DELAY}` entre módulos de auditoría
- BloodHound usa `--workers` y `--timeout`

---

## Dashboards Grafana

Cuatro dashboards JSON están provisionados automáticamente en
`grafana/provisioning/dashboards/`:

| Dashboard | UID | Datos |
|---|---|---|
| Suricata — Alertas IDS | `purplelab-suricata` | índice `suricata-*` |
| Kerberos — Actividad AD | `purplelab-kerberos` | índice `zeek-*` |
| LDAP — Consultas al Directorio | `purplelab-ldap` | índice `zeek-*` |
| Zeek — Conexiones de Red | `purplelab-zeek` | índice `zeek-*` |

**Nota**: Los dashboards requieren que los logs de Zeek/Suricata estén
indexados en OpenSearch. Ver sección "Ingestión de logs en OpenSearch".

```bash
# Abrir Grafana en el navegador:
make dashboards
# o navegar a: http://localhost:3000  (admin/admin)
```

---

## Docker Secrets (opcional)

Por defecto las credenciales van en `.env`. Para mayor seguridad:

```bash
# Crear secretos
echo -n "MiPassword" > secrets/ad_password.txt
chmod 600 secrets/ad_password.txt

# Activar en docker-compose.yml:
# Descomenta el bloque "secrets:" al final de "volumes:"
# y agrega secrets: - ad_password al servicio kali-audit
```

Ver `secrets/README.md` para instrucciones completas.

---

## Captura de tráfico en Docker

### Limitación real (importante leer)

**En modo bridge** (configuración por defecto):
- Zeek y Suricata solo ven el tráfico que entra/sale de su propio contenedor
- No ven el tráfico entre `kali-audit` y el DC externo
- Útil para: analizar pcaps copiados a `./data/`, monitoreo de tráfico interno del lab

**Para captura real del tráfico del host** (tráfico de auditoría hacia el DC):

Edita `docker-compose.yml` en los servicios `zeek` y `suricata`:

```yaml
# Reemplazar:
networks:
  - purple_net

# Con:
network_mode: host
```

Y en `.env`:
```env
CAPTURE_INTERFACE=ens33   # o eth0, enp3s0, según tu interfaz real
```

**Nota**: `network_mode: host` solo funciona en Linux. En macOS/Windows con Docker Desktop, la interfaz del host no es accesible directamente desde contenedores.

### Análisis de pcaps (alternativa portable)

```bash
# Copiar un pcap al directorio de datos:
cp captura.pcap ./data/

# Analizar con Zeek:
docker exec zeek zeek -r /workspace/data/captura.pcap \
    /opt/zeek/share/zeek/site/local.zeek

# Analizar con Suricata:
docker exec suricata suricata \
    -r /workspace/data/captura.pcap \
    -c /etc/suricata/suricata.yaml \
    -l /var/log/suricata-out
```

---

## Ingestión de logs en OpenSearch

Los logs de Zeek y Suricata se generan en formato JSON pero **no se ingestán automáticamente** en OpenSearch sin un agente de recolección (Filebeat, Logstash, Vector). Esta integración requiere pasos adicionales:

### Opción A: Filebeat (recomendado para producción del lab)

```bash
# Agregar al docker-compose.yml un servicio filebeat con módulos zeek y suricata
# Ver documentación: https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-zeek.html
```

### Opción B: Ingesta manual para pruebas

```bash
# Ingesta de un archivo eve.json de Suricata en OpenSearch:
curl -X POST "http://localhost:9200/suricata-$(date +%Y.%m.%d)/_bulk" \
    -H 'Content-Type: application/x-ndjson' \
    --data-binary @<(cat ./logs/suricata/eve.json | \
        jq -c '. | {"index":{}}, .' | head -200)
```

---

## Consumo aproximado de recursos

| Servicio | RAM mínima | RAM recomendada |
|---|---|---|
| kali-audit | 512 MB | 1 GB |
| neo4j | 512 MB | 1.5 GB |
| opensearch | 1 GB | 2 GB |
| opensearch-dashboards | 256 MB | 512 MB |
| grafana | 128 MB | 256 MB |
| zeek | 128 MB | 256 MB |
| suricata | 128 MB | 512 MB |
| **Total** | **~2.7 GB** | **~6 GB** |

---

## Limitaciones reales

1. **Active Directory no incluido**: Este lab se conecta a un DC externo. No hay un AD simulado dentro del compose.

2. **Captura de tráfico en Docker bridge**: Zeek y Suricata en modo bridge no capturan el tráfico entre contenedores y el DC. Ver sección anterior.

3. **Ingestión automática de logs**: Los logs JSON de Zeek/Suricata no se envían automáticamente a OpenSearch. Se requiere Filebeat o configuración adicional.

4. **BloodHound CE vs Classic**: Este lab usa Neo4j para BloodHound Classic. BloodHound CE (Community Edition) tiene su propia API y stack independiente; no es compatible directamente con este compose.

5. **macOS/Windows - network_mode: host**: No disponible en Docker Desktop. La captura de tráfico real desde el host requiere Linux.

6. **APOC para Neo4j**: No está instalado por defecto. BloodHound Classic no lo requiere para queries básicas, pero algunas queries avanzadas sí.

---

## Troubleshooting

### OpenSearch no arranca

```bash
# Verificar logs:
docker compose logs opensearch

# Problema más común en Linux: vm.max_map_count insuficiente
sudo sysctl -w vm.max_map_count=262144
docker compose restart opensearch
```

### kali-audit no conecta al DC

```bash
# Verificar que el DC es alcanzable desde el host:
ping <DC_IP>

# Verificar desde el contenedor:
docker exec kali-audit ping -c3 <DC_IP>

# Si falla: verificar que el DC_IP en .env es correcto
# y que la red del host puede alcanzar ese IP
```

### Neo4j no arranca con error de autenticación

```bash
# El formato de NEO4J_AUTH debe ser: usuario/contraseña
# Sin comillas, sin espacios
NEO4J_AUTH=neo4j/MiPassword123

# Si cambiaste la contraseña y Neo4j ya tiene datos:
docker compose down
docker volume rm ad-purple-lab_neo4j_data
docker compose up -d neo4j
```

### bloodhound-python falla con "Could not find DC"

```bash
# Verificar que DNS_SERVER apunta al DC:
docker exec kali-audit nslookup corp.local <DNS_SERVER>

# Verificar que el puerto 389 es alcanzable:
docker exec kali-audit nc -zv <DC_IP> 389

# Asegurarse de que AD_FQDN resuelve correctamente
```

### Grafana no muestra datos

1. OpenSearch debe estar healthy: `curl http://localhost:9200/_cluster/health`
2. El plugin `grafana-opensearch-datasource` tarda ~2 min en instalarse al primer arranque
3. Si no hay datos: los logs de Zeek/Suricata deben ingestarse primero (ver sección de ingestión)

---

## Consideraciones de seguridad

- **Usa este lab solo en entornos que controlas y para los que tienes autorización explícita.**
- Nunca uses credenciales de producción en `.env`. Crea una cuenta de auditoría dedicada.
- El `.env` con credenciales reales no debe commitearse. Está en `.gitignore`.
- OpenSearch y Neo4j corren sin TLS en este lab. No expongas los puertos 9200, 7474, 7687 en redes no confiables.
- La contraseña de Neo4j en `.env.example` es de ejemplo. Cámbiala antes de levantar el stack.
- Los reportes de BloodHound/LDAP contienen información sensible del AD. Gestiona `./reports/` con cuidado.

---

## Exportar y limpiar

```bash
# Exportar todos los logs y reportes:
make export
# Genera: ad-purple-lab-export_YYYYMMDD_HHMMSS.tar.gz

# Detener sin perder datos:
make down

# Detener y eliminar TODOS los datos (irreversible):
make clean
```
