##! Configuración local de Zeek para AD Purple Lab
##! Activa protocolos relevantes para auditoría de Active Directory.

# Cargar framework base de Zeek
@load base/frameworks/notice
@load base/frameworks/logging
@load base/frameworks/sumstats

# ── Protocolos relevantes para AD ────────────────────────────
@load base/protocols/dns       # DNS queries/responses
@load base/protocols/krb       # Kerberos (port 88)
@load base/protocols/ldap      # LDAP (port 389/636)
@load base/protocols/smb       # SMB/CIFS (port 445)
@load base/protocols/dce-rpc   # DCE/RPC (port 135)
@load base/protocols/ntlm      # NTLM autenticación

# ── Detección básica ──────────────────────────────────────────
# Note: extend-email, detect-external-names, log-cmds are zkg packages not installed here
# @load policy/frameworks/notice/extend-email
# @load policy/protocols/dns/detect-external-names
# @load policy/protocols/smb/log-cmds

# ── Script personalizado de monitoreo AD ─────────────────────
# Escribe logs a: ad_activity.log
# Detecta: LDAP queries/binds, Kerberos AS-REQ/TGS-REQ/errors,
#          SMB sessions, NTLM negotiate/authenticate
@load custom/ad-monitor

# ── Configuración de logs ─────────────────────────────────────
# Rotar logs cada hora
redef Log::default_rotation_interval = 1 hr;

# Comprimir logs rotados
redef Log::default_rotation_postprocessor_cmd = "gzip";

# ── Puertos de Active Directory ───────────────────────────────
# Asegurar que Zeek detecte LDAP en puertos estándar (636/tcp y 3269/tcp son variantes TLS)
redef LDAP::ports_tcp += { 636/tcp, 3269/tcp };
# KRB: 88/tcp y 88/udp ya registrados por defecto en base/protocols/krb
