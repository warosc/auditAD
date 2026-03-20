##! ad-monitor.zeek - Monitoreo de actividad Active Directory
##! Escribe logs a: logs/zeek/ad_activity.log
##! Genera notices para actividad inusual en el laboratorio.

module ADMonitor;

export {

    # ── Log stream personalizado ──────────────────────────────
    redef enum Log::ID += { LOG };

    type Info: record {
        ## Timestamp del evento
        ts:         time   &log;
        ## IP origen
        src_ip:     addr   &log;
        ## IP destino
        dst_ip:     addr   &log;
        ## Puerto destino
        dst_port:   port   &log;
        ## Protocolo (ldap, kerberos, smb, ntlm)
        proto:      string &log;
        ## Tipo de evento
        event_type: string &log;
        ## Detalle adicional
        detail:     string &log &optional;
    };

    # ── Tipos de notice ───────────────────────────────────────
    redef enum Notice::Type += {
        ## Bind LDAP anónimo detectado
        LDAP_Anonymous_Bind,
        ## Solicitud de TGT Kerberos
        KRB_TGT_Request,
        ## Fallo de autenticación Kerberos
        KRB_Auth_Failed,
        ## Sesión SMB iniciada
        SMB_Session_Start,
        ## Autenticación NTLM detectada
        NTLM_Auth_Detected,
    };
}

# ── Inicializar el stream de logs ─────────────────────────────
event zeek_init() &priority=5
{
    Log::create_stream(ADMonitor::LOG,
        [$columns=ADMonitor::Info,
         $path="ad_activity"]);
}

# ── Función helper para registrar evento ─────────────────────
function log_ad_event(c: connection, proto: string,
                      etype: string, detail: string)
{
    local info: ADMonitor::Info = [
        $ts        = network_time(),
        $src_ip    = c$id$orig_h,
        $dst_ip    = c$id$resp_h,
        $dst_port  = c$id$resp_p,
        $proto     = proto,
        $event_type = etype,
        $detail    = detail
    ];
    Log::write(ADMonitor::LOG, info);
}

# ── LDAP: Bind anónimo ────────────────────────────────────────
event LDAP::bind_request(c: connection, message_id: int, version: int,
                         name: string, auth_type: LDAP::BindAuthType,
                         auth_info: string)
{
    local detail = fmt("DN='%s' auth_type=%s", name, auth_type);
    log_ad_event(c, "ldap", "BIND_REQUEST", detail);

    if ( name == "" && auth_type == LDAP::BindAuthType_BIND_AUTH_SIMPLE )
    {
        log_ad_event(c, "ldap", "ANONYMOUS_BIND", "DN vacío - sin credenciales");
        NOTICE([$note=LDAP_Anonymous_Bind,
                $conn=c,
                $msg=fmt("Bind LDAP anónimo desde %s", c$id$orig_h),
                $identifier=cat(c$id$orig_h)]);
    }
}

# ── LDAP: Solicitudes de búsqueda ────────────────────────────
event LDAP::search_request(c: connection, message_id: int,
                           base_object: string, scope: LDAP::SearchScope,
                           deref: LDAP::SearchDerefAlias,
                           size_limit: int, time_limit: int,
                           types_only: bool, filter: string,
                           attributes: vector of string)
{
    local detail = fmt("base='%s' filter='%s'", base_object, filter);
    log_ad_event(c, "ldap", "SEARCH_REQUEST", detail);
}

# ── Kerberos: AS-REQ (solicitud de TGT) ──────────────────────
event krb_as_request(c: connection, msg: KRB::KDC_Request)
{
    local client = msg?$client_name ? msg$client_name : "unknown";
    local realm  = msg?$service_realm ? msg$service_realm : "";
    local detail = fmt("client='%s' realm='%s'", client, realm);

    log_ad_event(c, "kerberos", "AS_REQ_TGT", detail);

    NOTICE([$note=KRB_TGT_Request,
            $conn=c,
            $msg=fmt("AS-REQ Kerberos desde %s para %s", c$id$orig_h, client),
            $identifier=cat(c$id$orig_h, client)]);
}

# ── Kerberos: AS-REP (respuesta del KDC al TGT) ──────────────
event krb_as_response(c: connection, msg: KRB::KDC_Response)
{
    log_ad_event(c, "kerberos", "AS_REP", "TGT response received");
}

# ── Kerberos: TGS-REQ (solicitud de service ticket) ──────────
event krb_tgs_request(c: connection, msg: KRB::KDC_Request)
{
    local svc    = msg?$service_name ? msg$service_name : "unknown";
    local detail = fmt("service='%s'", svc);
    log_ad_event(c, "kerberos", "TGS_REQ", detail);
}

# ── Kerberos: Error (fallo de autenticación) ──────────────────
event krb_error(c: connection, msg: KRB::Error_Msg)
{
    local detail = fmt("error_code=%s msg='%s'",
                       msg$error_code,
                       msg?$error_text ? msg$error_text : "");

    log_ad_event(c, "kerberos", "AUTH_FAILED", detail);

    NOTICE([$note=KRB_Auth_Failed,
            $conn=c,
            $msg=fmt("Kerberos error desde %s: %s", c$id$orig_h, detail),
            $identifier=cat(c$id$orig_h, cat(msg$error_code))]);
}

# ── SMB: Inicio de sesión ─────────────────────────────────────
# SMB sessions logged via base/protocols/smb built-in log
# smb1_session_request / smb2_session_request not available in this Zeek build

# ── NTLM: Autenticación ───────────────────────────────────────
event ntlm_negotiate(c: connection, negotiate: NTLM::Negotiate)
{
    log_ad_event(c, "ntlm", "NEGOTIATE",
                 fmt("flags=%s", negotiate$flags));

    NOTICE([$note=NTLM_Auth_Detected,
            $conn=c,
            $msg=fmt("NTLM negotiate desde %s", c$id$orig_h),
            $identifier=cat(c$id$orig_h)]);
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate)
{
    local user   = request?$user_name   ? request$user_name   : "";
    local domain = request?$domain_name ? request$domain_name : "";
    local detail = fmt("user='%s' domain='%s'", user, domain);
    log_ad_event(c, "ntlm", "AUTHENTICATE", detail);
}
