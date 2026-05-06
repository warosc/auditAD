# AD Purple Lab — SOC Panel v2

Laboratorio dockerizado de auditoría y Purple Team para **Active Directory**. Incluye un panel SOC web completo con enumeración defensiva, módulos de ataque Kerberos (AS-REP Roasting y Kerberoasting), análisis de hallazgos con mapeo MITRE ATT&CK y monitoreo con OpenSearch, Grafana, Zeek y Suricata.

> **Uso exclusivo en entornos de laboratorio autorizados.** SAFE\_MODE=true — no realiza modificaciones en el AD.

---

## ¿Qué hace?

| Módulo | Descripción |
|---|---|
| **Panel SOC Web** | Interfaz Next.js 14 en `localhost:3002` para operar todo el lab |
| **Validar Entorno** | Verifica conectividad al DC, credenciales LDAP, puertos y herramientas |
| **DNS Check** | Registros SOA/NS/MX/SRV, resolución del DC, intento de zone transfer AXFR |
| **LDAP Enumeration** | ldapdomaindump: usuarios, grupos, GPOs, equipos, política de contraseñas |
| **BloodHound Collection** | bloodhound-python DCOnly: ACLs, sessions, trusts, GPOs → ZIP para Neo4j |
| **AS-REP Roasting** | T1558.004: identifica cuentas sin pre-auth Kerberos, solicita hashes, crackea offline |
| **Kerberoasting** | T1558.003: enumera cuentas con SPN, solicita TGS tickets, crackea hashes RC4 offline |
| **Resultados** | Vista estructurada de hallazgos con severidad, MITRE ATT&CK y recomendaciones |
| **Monitoreo** | OpenSearch + Grafana + Zeek + Suricata para detección defensiva |

---

## Capturas

```
Panel SOC → /results
┌────────────────────────────────────────────────────────┐
│ Resultados de Auditoría                                │
│ 113 usuarios · 11 equipos · 53 grupos                 │
│ Nivel de riesgo: CRÍTICO (1 crítico · 3 altos)        │
├────────────────────────────────────────────────────────┤
│ CRÍTICO  POL-001  Sin bloqueo de cuentas (lockout=0)  │
│ ALTO     USR-003  1 cuenta AS-REP Roastable           │
│ ALTO     USR-004  2 cuentas Kerberoastables (SPN)     │
│ ALTO     POL-002  Contraseña mínima 7 caracteres      │
│ MEDIO    POL-004  MachineAccountQuota=10              │
└────────────────────────────────────────────────────────┘
```

---

## Arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│                         Docker Host                              │
│                                                                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐    │
│  │  panel-ui   │   │  panel-api  │   │     kali-audit      │    │
│  │ Next.js 14  │──▶│  FastAPI    │──▶│  Kali Linux         │    │
│  │ :3002       │   │  :8080      │   │  ldap/bh/nmap/      │    │
│  └─────────────┘   └─────────────┘   │  impacket/crack.py  │    │
│                                      └─────────────────────┘    │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐    │
│  │    neo4j    │   │ opensearch  │   │       grafana       │    │
│  │ :7474/:7687 │   │  :9200      │   │       :3000         │    │
│  │ BloodHound  │   │ :5601 dash  │   │   dashboards JSON   │    │
│  └─────────────┘   └─────────────┘   └─────────────────────┘    │
│  ┌─────────────┐   ┌─────────────┐                              │
│  │    zeek     │   │  suricata   │                              │
│  │ NSM/AD log  │   │  IDS alerts │                              │
│  └─────────────┘   └─────────────┘                              │
│                    purple_net (172.20.0.0/24)                    │
└──────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────▼──────────────┐
              │      Domain Controller       │
              │    DC_IP=<tu-ip-del-DC>      │
              └──────────────────────────────┘
```

---

## Prerequisitos

| Requisito | Mínimo | Verificar |
|---|---|---|
| Docker Engine o Docker Desktop | 24.x | `docker --version` |
| Docker Compose v2 | 2.20+ | `docker compose version` |
| RAM libre | 6 GB | Panel + OpenSearch + Neo4j |
| Disco | 10 GB | Imágenes, logs, reportes |
| OS | Linux / macOS / Windows 11 WSL2 | |

### En Linux: `vm.max_map_count` para OpenSearch

```bash
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

En Docker Desktop (macOS/Windows) se configura automáticamente.

---

## Instalación rápida

```bash
# 1. Clonar
git clone https://github.com/warosc/auditAD.git
cd auditAD/ad-purple-lab

# 2. Inicializar (crea .env, directorios, permisos)
make init

# 3. Editar credenciales del DC
nano .env

# 4. Construir y levantar todo
make build
make up

# 5. Verificar que todos los contenedores están healthy
docker compose ps
```

El panel SOC estará disponible en **http://localhost:3002**

---

## Configuración (`.env`)

Edita `.env` con los datos de tu laboratorio:

```env
# Domain Controller
AD_DOMAIN=corp.local
AD_FQDN=dc01.corp.local
DC_IP=192.168.1.10

# Cuenta de auditoría (solo lectura)
AD_USERNAME=audit.user
AD_PASSWORD=TuPasswordAqui
LDAP_BASE_DN=DC=corp,DC=local

# DNS (generalmente el mismo DC)
DNS_SERVER=192.168.1.10

# Neo4j
NEO4J_AUTH=neo4j/TuPasswordNeo4j

# Rate limiting (para no sobrecargar el DC)
LDAP_DELAY=0.2
PORTSCAN_RATE=20
BLOODHOUND_THREADS=5
```

### Crear cuenta de auditoría en el DC (PowerShell)

```powershell
New-ADUser -Name "audit.user" -SamAccountName "audit.user" `
    -AccountPassword (ConvertTo-SecureString "ChangeMe123!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $true

# Solo Domain Users — NO Domain Admins
Add-ADGroupMember -Identity "Domain Users" -Members "audit.user"
```

---

## Interfaces web

| Servicio | URL | Credenciales |
|---|---|---|
| **Panel SOC** | http://localhost:3002 | Sin auth (lab) |
| Neo4j Browser | http://localhost:7474 | `neo4j` / valor de `NEO4J_AUTH` |
| OpenSearch Dashboards | http://localhost:5601 | Sin auth (lab) |
| Grafana | http://localhost:3000 | `admin` / `admin` |

---

## Uso del Panel SOC

### 1. Configurar Settings

Navega a **Configuración** → ingresa DC IP, dominio, credenciales y guarda.

### 2. Ejecutar auditoría en orden

Desde **Auditoría AD**, ejecuta en secuencia:

1. **Validar Entorno** — siempre primero, verifica que todo esté listo
2. **DNS Check** — enumeración de registros DNS del dominio
3. **LDAP Enumeration** — vuelca usuarios, grupos, GPOs via ldapdomaindump
4. **BloodHound Collection** — grafo de relaciones ACL/trusts para Neo4j
5. **AS-REP Roasting** — detecta cuentas sin pre-auth Kerberos, captura y crackea hashes
6. **Kerberoasting** — detecta cuentas con SPN, captura y crackea hashes RC4
7. **Safe Audit Completo** — orquestador que ejecuta pasos 1-4 en secuencia

El output se muestra en tiempo real vía SSE (Server-Sent Events).

### 3. Ver Resultados

Navega a **Resultados** para ver:

- **Hallazgos** — Findings automáticos con severidad y recomendaciones
- **Ataques** — Hashes capturados y contraseñas crackeadas (cuando el DC está activo)
- **Usuarios** — Tabla con flags de riesgo: AS-REP Roastable, Kerberoastable, Sin Expiración
- **Computadoras / Grupos / Política / Puertos**

---

## Módulos de ataque Purple Team

### AS-REP Roasting (T1558.004)

Ataca cuentas con `DONT_REQ_PREAUTH` habilitado. **No requiere contraseña**.

```bash
# Ejecutable manual desde kali-audit:
docker exec kali-audit bash /workspace/scripts/asrep-roast.sh
```

Flujo:
1. LDAP query → cuentas con `userAccountControl:DONT_REQ_PREAUTH`
2. `GetNPUsers.py` → solicita AS-REP hashes en formato hashcat
3. `crack-kerberos.py` → crackeo offline RC4-HMAC con wordlist incorporada
4. Guía de remediación (Event ID 4768, PowerShell fix, gMSA)

### Kerberoasting (T1558.003)

Ataca cuentas de servicio con SPN registrado. **Requiere credenciales válidas**.

```bash
docker exec kali-audit bash /workspace/scripts/kerberoast.sh
```

Flujo:
1. LDAP query → cuentas con `servicePrincipalName=*`
2. `GetUserSPNs.py` → solicita TGS tickets RC4-HMAC
3. `crack-kerberos.py` → crackeo offline
4. Guía de remediación (gMSA, Event ID 4769, longitud 25+)

### Cracker offline (sin hashcat/john)

`scripts/crack-kerberos.py` — implementación Python pura de RC4-HMAC:
- Soporta `$krb5asrep$23$` y `$krb5tgs$23$` (formato hashcat)
- Wordlist incorporada con ~60 contraseñas comunes de AD
- No requiere herramientas del sistema

---

## Hallazgos automáticos (ResultsService)

El backend parsea los JSON de ldapdomaindump y genera findings automáticamente:

| ID | Severidad | Descripción |
|---|---|---|
| POL-001 | CRÍTICO | Account Lockout Threshold = 0 |
| POL-002 | ALTO | Contraseña mínima < 8 caracteres |
| USR-003 | ALTO | Cuentas AS-REP Roastables |
| USR-004 | ALTO | Cuentas Kerberoastables (con SPN) |
| POL-004 | MEDIO | ms-DS-MachineAccountQuota > 0 |
| USR-001 | MEDIO | Cuentas con contraseña sin expiración |
| USR-005 | INFO | Cuentas honeypot detectadas |
| GRP-001 | INFO | Grupos privilegiados identificados |

---

## API Backend (FastAPI)

| Método | Endpoint | Descripción |
|---|---|---|
| GET | `/settings` | Obtener settings del lab |
| POST | `/settings` | Guardar settings |
| GET | `/settings/schedule` | Listar jobs programados |
| POST | `/audit/validate` | Validar entorno (SSE) |
| POST | `/audit/dns` | DNS check (SSE) |
| POST | `/audit/ldap` | LDAP enumeration (SSE) |
| POST | `/audit/bloodhound` | BloodHound collection (SSE) |
| POST | `/audit/asrep-roast` | AS-REP Roasting (SSE) |
| POST | `/audit/kerberoast` | Kerberoasting (SSE) |
| GET | `/audit/results/latest` | Resultados parseados del último audit |
| GET | `/audit/results/attacks` | Resultados de ataques Kerberos |
| GET | `/reports` | Listar reportes generados |
| GET | `/lab/health` | Health check de servicios |

Swagger UI: http://localhost:8080/docs

---

## Comandos make

```bash
make init        # Inicializar entorno (primera vez)
make build       # Construir imágenes Docker
make up          # Levantar todos los servicios
make down        # Detener servicios (conserva datos)
make ps          # Estado de contenedores
make health      # Health check del lab
make logs        # Ver logs en tiempo real
make shell       # Shell interactivo en kali-audit
make audit       # Ejecutar safe-audit.sh completo
make validate    # Solo validar entorno
make dns-check   # Solo DNS check
make ldap-check  # Solo LDAP enumeration
make bloodhound  # Solo BloodHound collection
make export      # Exportar logs y reportes (.tar.gz)
make clean       # Detener y eliminar TODOS los datos
make dashboards  # Abrir Grafana en el navegador
```

---

## Reportes generados

```
reports/
├── audit_summary_YYYYMMDD_HHMMSS.txt
├── dns/dns_check_*.txt
├── ldap/
│   ├── users_active_*.txt
│   ├── domain_admins_*.txt
│   ├── password_policy_*.txt
│   └── gpos_*.txt
├── bloodhound/YYYYMMDD/
│   └── *.zip  ← importar en BloodHound
├── ldapdomaindump_YYYYMMDD_HHMMSS/
│   ├── domain_users.json
│   ├── domain_groups.json
│   ├── domain_computers.json
│   └── domain_policy.json
├── asrep_hashes_*.txt        ← hashes AS-REP capturados
├── asrep_cracked_*.txt       ← contraseñas crackeadas
├── kerberoast_hashes_*.txt   ← hashes TGS capturados
└── kerberoast_cracked_*.txt  ← contraseñas crackeadas
```

---

## Tomcat OCSP Scanner

Módulo integrado al lab como servicio Docker. Detecta versiones vulnerables de Tomcat, uso de OCSP stapling y malas configuraciones TLS.

```bash
cd tomcat-ocsp-scanner
docker build -t tomcat-ocsp-scanner .
# El servicio también se levanta con docker compose desde el lab
```

Salida:
- `reports/tomcat-ocsp/report.csv`
- `reports/tomcat-ocsp/report.json`

*Desde el panel, se puede ejecutar el escáner en la sección de Auditoría AD con el botón "Scanner Tomcat OCSP".*

---

## Troubleshooting

### OpenSearch no arranca (Linux)

```bash
sudo sysctl -w vm.max_map_count=262144
docker compose restart opensearch
```

### kali-audit no conecta al DC

```bash
# Desde el host:
ping <DC_IP>
# Desde el contenedor:
docker exec kali-audit ping -c3 <DC_IP>
docker exec kali-audit nc -zv <DC_IP> 389
```

### bloodhound-python falla con "Could not find DC"

```bash
# AD_FQDN debe resolver — verificar DNS:
docker exec kali-audit nslookup <AD_FQDN> <DNS_SERVER>
```

### Neo4j error de autenticación

```bash
# Formato correcto en .env: usuario/contraseña (sin comillas)
NEO4J_AUTH=neo4j/MiPassword123

# Resetear volumen si ya tenía datos:
docker compose down && docker volume rm ad-purple-lab_neo4j_data
docker compose up -d neo4j
```

### Panel SOC muestra "Sin datos"

Los resultados se leen de `reports/ldapdomaindump_*`. Ejecuta **LDAP Enumeration** primero.

### Impacket ImportError en Python 3.13+

```bash
docker exec kali-audit bash -c "source /opt/venv/bin/activate && pip install setuptools"
```

---

## Monitoreo defensivo

### Wazuh Agent en el DC (opcional)

```powershell
# En el DC Windows:
msiexec /i wazuh-agent-4.7.3-1.msi /q `
    WAZUH_MANAGER="<HOST_IP>" WAZUH_AGENT_NAME="DC01"
NET START WazuhSvc
```

```bash
# Levantar Wazuh Manager:
make wazuh
docker exec wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json
```

### Eventos Windows monitoreados

| Event ID | Descripción |
|---|---|
| 4768 | Kerberos AS-REQ (TGT request) — AS-REP Roasting |
| 4769 | Kerberos TGS-REQ (service ticket) — Kerberoasting |
| 4771 | Kerberos pre-auth fallida |
| 4625 | Logon fallido |
| 4624 / 4672 | Logon exitoso / privilegios especiales |

---

## Limitaciones

1. **DC no incluido** — el lab se conecta a un DC externo. Necesitas tu propia VM con Windows Server + AD DS.
2. **Captura de tráfico en bridge** — Zeek/Suricata solo ven tráfico interno del compose, no el tráfico hacia el DC externo. En Linux usa `network_mode: host`.
3. **BloodHound Classic** — compatible con Neo4j 5.x. BloodHound CE tiene su propio stack.
4. **macOS/Windows** — `network_mode: host` no disponible en Docker Desktop.

---

## Seguridad

- Usa solo en entornos que controlas con **autorización explícita**.
- Nunca uses credenciales de producción en `.env`.
- El `.env` con credenciales está en `.gitignore` — no se sube al repo.
- No expongas los puertos 9200, 7474, 7687 en redes no confiables.
- Los reportes contienen información sensible del AD — gestiona `./reports/` con cuidado.

---

## Stack tecnológico

| Componente | Tecnología |
|---|---|
| Panel frontend | Next.js 14, TypeScript, Tailwind CSS |
| Panel backend | FastAPI (Python), SQLite, SSE streaming |
| Auditoría | Kali Linux, ldapdomaindump, bloodhound-python, impacket |
| Cracking offline | Python (pycryptodome, hashlib) — RC4-HMAC sin hashcat/john |
| Grafos AD | Neo4j 5 Community + BloodHound Classic |
| Logs/SIEM | OpenSearch 2.12 + Dashboards |
| Dashboards | Grafana 10 |
| NSM | Zeek 6, Suricata 7 |
| HIDS (opcional) | Wazuh Manager 4.7 |
