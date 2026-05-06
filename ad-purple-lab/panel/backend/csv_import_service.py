"""
csv_import_service.py — Parses PowerShell AD CSV exports for offline security analysis.

Supported CSVs (auto-detected by headers, fallback to filename):
  AD_Usuarios_*.csv     — Get-ADUser    -Filter * -Properties *
  AD_Computadoras_*.csv — Get-ADComputer -Filter * -Properties *
  AD_Grupos_*.csv       — Get-ADGroup   -Filter * -Properties *
  AD_OUs_*.csv          — Get-ADOrganizationalUnit -Filter * -Properties *
  policy.csv            — Get-ADDefaultDomainPasswordPolicy | Select-Object *
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
from typing import Any

from results_service import decode_uac, _generate_findings

# ── Type-detection signatures (lowercase header set) ─────────────────────────

_POLICY_SIG   = {"minpasswordlength", "lockoutthreshold", "complexityenabled"}
_GROUP_SIG    = {"groupscope", "groupcategory"}
_OU_SIG       = {"linkedgrouppolicyobjects"}
_COMPUTER_SIG = {"operatingsystem", "dnshostname"}
_USER_SIG     = {"doesnotrequirepreauth", "passwordneverexpires"}


def _detect_csv_type(headers: list[str]) -> str:
    lower = {h.strip().lower() for h in headers}
    if _POLICY_SIG   & lower: return "policy"
    if _GROUP_SIG    & lower: return "groups"
    if _OU_SIG       & lower: return "ous"
    if _COMPUTER_SIG & lower: return "computers"
    if _USER_SIG     & lower: return "users"
    return "unknown"


# ── Field helpers ────────────────────────────────────────────────────────────

def _parse_bool(val: str) -> bool:
    return val.strip().lower() in ("true", "1", "yes")


def _parse_spn(val: str) -> list[str]:
    val = val.strip()
    if val in ("", "{}", "System.String[]",
               "Microsoft.ActiveDirectory.Management.ADPropertyValueCollection"):
        return []
    val = val.strip("{}")
    return [s.strip() for s in re.split(r"[\s;,]+", val) if s.strip()]


def _parse_member_list(val: str) -> list[str]:
    if not val or val.strip() in ("{}", ""):
        return []
    return re.findall(r"CN=([^,\}]+)", val)


def _ou_from_dn(dn: str) -> str:
    m = re.search(r"OU=([^,]+)", dn)
    return m.group(1) if m else "Users"


def _ou_path_from_dn(dn: str) -> str:
    """Return all OU levels reversed, e.g. 'Central/Sistemas/Usuarios'."""
    parts = re.findall(r"OU=([^,]+)", dn)
    parts.reverse()
    return "/".join(parts) if parts else "Root"


def _timespan_to_days(ts: str) -> int:
    m = re.match(r"-?(\d+)\.", ts.strip())
    return int(m.group(1)) if m else -1


def _parse_date(val: str) -> datetime | None:
    if not val or val.strip().lower() in ("", "never", "0"):
        return None
    if val.strip().lstrip("-").isdigit():
        return None
    for fmt in ("%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(val.strip(), fmt)
        except ValueError:
            continue
    return None


def _days_since(dt: datetime | None, now: datetime) -> int | None:
    if dt is None:
        return None
    return max(0, (now - dt).days)


def _row(raw: dict) -> dict:
    return {k.strip().lower(): (v.strip() if v else "") for k, v in raw.items() if k}


def _read_csv(content: bytes) -> list[dict]:
    try:
        text = content.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(text))
        return list(reader)
    except Exception:
        return []


# ── Legacy OS risk detection ─────────────────────────────────────────────────

_OS_CRITICAL = re.compile(r"Windows\s+(XP|Vista|2000|Server\s+2003|Server\s+2000)", re.I)
_OS_HIGH     = re.compile(r"Windows\s+(7|Server\s+2008)", re.I)
_OS_MEDIUM   = re.compile(r"Windows\s+(8|8\.1|Server\s+2012)", re.I)


def _os_risk(os_str: str) -> str | None:
    if _OS_CRITICAL.search(os_str): return "critical"
    if _OS_HIGH.search(os_str):     return "high"
    if _OS_MEDIUM.search(os_str):   return "medium"
    return None


# ── Parsers ──────────────────────────────────────────────────────────────────

def _parse_users(content: bytes) -> list[dict]:
    rows = _read_csv(content)
    users: list[dict] = []

    for raw in rows:
        r   = _row(raw)
        sam = r.get("samaccountname", "")
        dn  = r.get("distinguishedname", "")
        upn = r.get("userprincipalname", "")
        canonical = r.get("canonicalname", "")

        raw_uac_str = r.get("useraccountcontrol", "")
        if raw_uac_str.lstrip("-").isdigit():
            uac        = int(raw_uac_str)
            uac_flags  = decode_uac(uac)
            disabled   = "ACCOUNTDISABLE"       in uac_flags
            no_expire  = "DONT_EXPIRE_PASSWORD" in uac_flags
            no_preauth = "DONT_REQ_PREAUTH"     in uac_flags
            pwd_not_req= "PASSWD_NOTREQD"       in uac_flags
        else:
            uac        = 0
            enabled    = _parse_bool(r.get("enabled", "True"))
            no_expire  = _parse_bool(r.get("passwordneverexpires",  "False"))
            no_preauth = _parse_bool(r.get("doesnotrequirepreauth", "False"))
            pwd_not_req= _parse_bool(r.get("passwordnotrequired",   "False"))
            disabled   = not enabled
            uac_flags  = []
            if disabled:     uac_flags.append("ACCOUNTDISABLE")
            if no_expire:    uac_flags.append("DONT_EXPIRE_PASSWORD")
            if no_preauth:   uac_flags.append("DONT_REQ_PREAUTH")
            if pwd_not_req:  uac_flags.append("PASSWD_NOTREQD")

        ll_raw = r.get("lastlogondate", "") or r.get("lastlogon", "")
        ps_raw = r.get("passwordlastset", "")

        users.append({
            "sam":           sam,
            "dn":            dn,
            "ou":            _ou_from_dn(dn) if dn else "Users",
            "ou_path":       _ou_path_from_dn(dn) if dn else "Root",
            "canonical":     canonical,
            "uac":           uac,
            "uac_flags":     uac_flags,
            "disabled":      disabled,
            "no_expire":     no_expire,
            "no_preauth":    no_preauth,
            "pwd_not_req":   pwd_not_req,
            "spn":           _parse_spn(r.get("serviceprincipalnames", "")),
            "last_logon":    ll_raw or "never",
            "last_logon_dt": _parse_date(ll_raw),
            "pwd_last_set":  ps_raw or "never",
            "upn":           upn,
            "display_name":  r.get("displayname", ""),
            "department":    r.get("department", ""),
            "company":       r.get("company", ""),
            "manager":       _ou_from_dn(r.get("manager", "")) if r.get("manager") else "",
            "risk_score":    0,
        })
    return users


def _parse_computers(content: bytes) -> list[dict]:
    rows = _read_csv(content)
    comps: list[dict] = []

    for raw in rows:
        r   = _row(raw)
        dn  = r.get("distinguishedname", "")
        raw_uac = r.get("useraccountcontrol", "")
        uac = int(raw_uac) if raw_uac.lstrip("-").isdigit() else 0
        os_str  = r.get("operatingsystem", "Desconocido")
        ll_raw  = r.get("lastlogondate", "") or r.get("lastlogon", "")

        comps.append({
            "name":          r.get("name", ""),
            "dn":            dn,
            "sam":           r.get("samaccountname", ""),
            "os":            os_str,
            "os_ver":        r.get("operatingsystemversion", ""),
            "uac":           uac,
            "is_dc":         "Domain Controllers" in dn,
            "enabled":       not bool(uac & 0x2) if uac else True,
            "last_logon":    ll_raw or "never",
            "last_logon_dt": _parse_date(ll_raw),
            "os_risk":       _os_risk(os_str),
            "ou":            _ou_from_dn(dn),
            "ip":            r.get("ipv4address", ""),
        })
    return comps


def _parse_groups(content: bytes) -> list[dict]:
    rows = _read_csv(content)
    groups: list[dict] = []

    for raw in rows:
        r       = _row(raw)
        members = _parse_member_list(r.get("members", "") or r.get("member", ""))
        groups.append({
            "name":         r.get("name", ""),
            "sam":          r.get("samaccountname", ""),
            "dn":           r.get("distinguishedname", ""),
            "scope":        r.get("groupscope", ""),
            "category":     r.get("groupcategory", ""),
            "member_count": len(members),
            "members":      members[:20],
            "description":  r.get("description", ""),
        })
    return groups


def _parse_ous(content: bytes) -> list[dict]:
    rows = _read_csv(content)
    ous: list[dict] = []

    _PS_COLL = "Microsoft.ActiveDirectory.Management.ADPropertyValueCollection"

    for raw in rows:
        r  = _row(raw)
        dn = r.get("distinguishedname", "")

        gpo_raw = r.get("linkedgrouppolicyobjects", "")
        gpos    = [
            x.strip() for x in re.split(r"[\s,;]+", gpo_raw.strip("{}"))
            if x.strip() and x.strip() != _PS_COLL
        ]

        managed_dn = r.get("managedby", "")
        ous.append({
            "name":        r.get("name", "") or r.get("cn", ""),
            "dn":          dn,
            "canonical":   r.get("canonicalname", ""),
            "description": r.get("description", ""),
            "managed_by":  _ou_from_dn(managed_dn) if managed_dn else "",
            "gpo_count":   len(gpos),
            "gpos":        gpos,
            "protected":   _parse_bool(r.get("protectedfromaccidentaldeletion", "False")),
            "created":     r.get("created", "") or r.get("whencreated", ""),
            "modified":    r.get("modified", "") or r.get("whenchanged", ""),
        })
    return ous


def _parse_policy(content: bytes) -> dict:
    rows = _read_csv(content)
    if not rows:
        return {}
    r = _row(rows[0])

    min_pwd     = int(r.get("minpasswordlength",    "0") or "0")
    history     = int(r.get("passwordhistorycount", "0") or "0")
    lockout_t   = int(r.get("lockoutthreshold",     "0") or "0")
    complexity  = 1 if _parse_bool(r.get("complexityenabled", "True")) else 0
    max_age_str = r.get("maxpasswordage", "")
    max_age_days = _timespan_to_days(max_age_str) if max_age_str else 42
    lockout_dur  = r.get("lockoutduration", "")

    dn = r.get("distinguishedname", "")
    if dn:
        parts  = [p.replace("DC=", "") for p in dn.split(",") if p.strip().upper().startswith("DC=")]
        domain = ".".join(parts)
    else:
        domain = ""

    return {
        "domain":            domain,
        "dn":                dn,
        "minPwdLength":      min_pwd,
        "maxPwdAge":         max_age_str,
        "maxPwdAge_days":    max_age_days,
        "minPwdAge":         r.get("minpasswordage", ""),
        "pwdHistoryLength":  history,
        "pwdProperties":     complexity,
        "lockoutThreshold":  lockout_t,
        "lockoutDuration":   lockout_dur,
        "behaviorVersion":   0,
        "machineAccountQuota": 0,
        "objectSid":         "",
    }


# ── Risk scoring ────────────────────────────────────────────────────────────

_DA_KW       = ["domain admin", "admins. del dom", "enterprise admin", "schema admin"]
_BAJA_KW_SET = {"baja", "disabled", "former", "offboard", "inactive"}


def _compute_risk_scores(users: list[dict], groups: list[dict]) -> None:
    """Populate risk_score (0-100) in-place for each user."""
    da_sams: set[str] = set()
    for g in groups:
        if any(x in g["name"].lower() for x in _DA_KW):
            for m in g["members"]:
                da_sams.add(m.lower())

    for u in users:
        score = 0
        if not u["disabled"]:
            if u["no_preauth"]:   score += 30
            if u["spn"]:          score += 25
            if u["no_expire"]:    score += 15
            if u["pwd_not_req"]:  score += 20
            if u["sam"].lower()          in da_sams: score += 35
            elif u["display_name"].lower() in da_sams: score += 35
            if any(k in u["ou"].lower() for k in _BAJA_KW_SET): score += 10
            if not u["last_logon_dt"]:   score += 5
        u["risk_score"] = min(score, 100)


# ── Attack path synthesis ─────────────────────────────────────────────────────

def _synthesize_attack_paths(
    users: list[dict],
    groups: list[dict],
    computers: list[dict],
) -> list[dict]:
    """Generate offline attack chains from CSV data without live DC access."""
    paths: list[dict] = []
    now = datetime.now()

    da_sams: set[str] = set()
    for g in groups:
        if any(x in g["name"].lower() for x in _DA_KW):
            for m in g["members"]:
                da_sams.add(m.lower())

    def _in_da(u: dict) -> bool:
        return u["sam"].lower() in da_sams or u["display_name"].lower() in da_sams

    # AP-001: AS-REP Roast → DA directo
    asrep_da = [u["sam"] for u in users if not u["disabled"] and u["no_preauth"] and _in_da(u)]
    if asrep_da:
        paths.append({
            "id": "AP-001", "severity": "critical",
            "title": "AS-REP Roasting → Acceso Domain Admin Inmediato",
            "chain": [
                "Atacante sin credenciales solicita AS-REP de cuentas sin pre-auth Kerberos",
                f"Obtiene hash offline de: {', '.join(asrep_da[:5])}",
                "Crackea hash con hashcat (modo 18200) → contraseña en texto plano",
                "Autentica como Domain Admin → dominio comprometido por completo",
            ],
            "accounts": asrep_da[:10],
            "mitre": "T1558.004 → T1078.002",
            "impact": "Compromiso total del dominio en una sola cadena, sin credenciales previas",
            "fix": "Habilitar pre-autenticación Kerberos. Set-ADUser -DoesNotRequirePreAuth $false",
        })

    # AP-002: Kerberoast → DA directo
    kerb_da = [u["sam"] for u in users if not u["disabled"] and u["spn"] and _in_da(u)]
    if kerb_da:
        paths.append({
            "id": "AP-002", "severity": "critical",
            "title": "Kerberoasting → Acceso Domain Admin Inmediato",
            "chain": [
                "Atacante con cualquier cuenta de dominio solicita TGS para SPN de cuenta DA",
                f"Objetivos: {', '.join(kerb_da[:5])}",
                "Crackea hash RC4 con hashcat (modo 13100) offline",
                "Autentica como DA → compromiso total del dominio",
            ],
            "accounts": kerb_da[:10],
            "mitre": "T1558.003 → T1078.002",
            "impact": "Compromiso de Domain Admin con solo una cuenta de dominio válida de inicio",
            "fix": "Migrar cuentas DA a gMSA. Nunca asignar SPNs a cuentas con privilegios DA.",
        })

    # AP-003: Kerberoast svc account → Operator groups
    _OP_GROUPS = ["backup operators", "account operators", "print operators", "server operators"]
    svc_kerb_priv: list[str] = []
    for u in users:
        if not u["disabled"] and u["spn"]:
            for g in groups:
                if any(x in g["name"].lower() for x in _OP_GROUPS):
                    if any(m.lower() in (u["sam"].lower(), u["display_name"].lower()) for m in g["members"]):
                        svc_kerb_priv.append(f"{u['sam']} → {g['name']}")
                        break
    if svc_kerb_priv:
        paths.append({
            "id": "AP-003", "severity": "high",
            "title": "Kerberoasting → Backup/Account Operators → Volcado NTDS",
            "chain": [
                f"Cuenta de servicio con SPN en grupo Operator: {', '.join(svc_kerb_priv[:3])}",
                "Kerberoasting entrega hash de contraseña → crackeo offline",
                "Backup Operators permite backup de NTDS.dit sin ser Domain Admin",
                "Extracción de todos los hashes del dominio sin privilegios DA directos",
            ],
            "accounts": [x.split(" → ")[0] for x in svc_kerb_priv[:10]],
            "mitre": "T1558.003 → T1003.003",
            "impact": "Volcado completo de NTDS.dit (todos los hashes del dominio)",
            "fix": "Remover de grupos Operators. Principio de mínimo privilegio. Usar gMSA.",
        })

    # AP-004: Zombie access — active account in offboarding OU with recent logon
    baja_recent = [
        u["sam"] for u in users
        if not u["disabled"]
        and any(k in (u["ou"] + " " + u["ou_path"]).lower() for k in _BAJA_KW_SET)
        and u["last_logon_dt"] is not None
        and (_days_since(u["last_logon_dt"], now) or 999) < 30
    ]
    if baja_recent:
        paths.append({
            "id": "AP-004", "severity": "high",
            "title": "Acceso Zombi — Ex-Empleado con Actividad Reciente en OU de Baja",
            "chain": [
                f"Cuentas en OUs de desvinculación aún activas: {', '.join(baja_recent[:5])}",
                "Logon registrado en los últimos 30 días → acceso activo confirmado",
                "Ex-empleado mantiene acceso válido a recursos corporativos",
                "Vector de insider threat o acceso no autorizado persistente",
            ],
            "accounts": baja_recent[:10],
            "mitre": "T1078.002 → T1133",
            "impact": "Acceso no autorizado con credenciales corporativas válidas por parte de ex-personal",
            "fix": "Deshabilitar INMEDIATAMENTE. Investigar en SIEM (Event ID 4624). Revisar proceso de offboarding.",
        })

    # AP-005: Legacy DC → full domain compromise
    legacy_dcs = [c for c in computers if c["is_dc"] and c.get("os_risk") in ("critical", "high")]
    if legacy_dcs:
        paths.append({
            "id": "AP-005", "severity": "critical",
            "title": "Domain Controller con OS Legado → Compromiso Total del Dominio",
            "chain": [
                f"DCs vulnerables: {', '.join(c['name'] + ' (' + c['os'] + ')' for c in legacy_dcs[:3])}",
                "Explotación remota vía EternalBlue (MS17-010) sin autenticación previa",
                "Ejecución de código como SYSTEM en el Domain Controller",
                "SYSTEM en DC = Domain Admin implícito → volcado total de NTDS.dit",
            ],
            "accounts": [c["name"] for c in legacy_dcs[:5]],
            "mitre": "T1210 → T1003.003",
            "impact": "Compromiso total del dominio desde red local, sin credenciales. CVEs con PoC públicos",
            "fix": "URGENTE: Aislar DCs en VLAN sin acceso. Planificar actualización de OS inmediata.",
        })

    # AP-006: Stale DA password → persistent access risk
    stale_da: list[str] = []
    for u in users:
        if not u["disabled"] and _in_da(u):
            days = _days_since(_parse_date(u["pwd_last_set"]), now)
            if days is not None and days > 365:
                stale_da.append(f"{u['sam']} ({days}d)")
    if stale_da:
        paths.append({
            "id": "AP-006", "severity": "high",
            "title": "Domain Admin con Contraseña Estancada (>365 días)",
            "chain": [
                f"Cuentas DA sin rotar contraseña: {', '.join(stale_da[:5])}",
                "Contraseña puede haber sido expuesta en breach anterior",
                "Verificación en HaveIBeenPwned / credential stuffing → si coincide: acceso DA",
                "Compromiso silencioso y difícil de detectar hasta auditoría",
            ],
            "accounts": [x.split(" (")[0] for x in stale_da[:10]],
            "mitre": "T1078.002 → T1110.004",
            "impact": "Acceso DA persistente con credenciales potencialmente filtradas en brechas anteriores",
            "fix": "Rotar contraseñas DA inmediatamente. MaxPasswordAge ≤ 90 días en GPO para cuentas privilegiadas.",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    paths.sort(key=lambda x: order.get(x["severity"], 5))
    return paths


# ── Cross-reference findings ─────────────────────────────────────────────────

def _generate_extra_findings(
    users: list[dict],
    computers: list[dict],
    groups: list[dict],
    ous: list[dict],
) -> list[dict]:
    findings: list[dict] = []
    now = datetime.now()

    # ── User findings ────────────────────────────────────────────────────────

    # USR-C01: Active accounts in off-boarding OUs
    _BAJA_KW = {"baja", "disabled", "former", "offboard", "inactive", "leave", "desvinculado"}
    baja_enabled = [
        u["sam"] for u in users
        if not u["disabled"]
        and any(kw in (u["canonical"] + " " + u["ou_path"]).lower() for kw in _BAJA_KW)
    ]
    if baja_enabled:
        findings.append({
            "id": "USR-C01",
            "severity": "high",
            "category": "Cuentas de Usuario",
            "title": f"Cuentas habilitadas en OUs de baja ({len(baja_enabled)})",
            "description": (
                f"Usuarios activos dentro de OUs de desvinculación: "
                f"{', '.join(baja_enabled[:10])}{'...' if len(baja_enabled) > 10 else ''}. "
                "Cuentas activas de ex-empleados representan un vector de acceso persistente."
            ),
            "recommendation": "Deshabilitar o eliminar cuentas. Revisar accesos recientes en SIEM (Event ID 4624).",
            "mitre": "T1078.002 — Valid Accounts: Domain Accounts",
        })

    # USR-C02: Dormant active accounts (no login 90+ days)
    dormant = [
        (u["sam"], d)
        for u in users
        if not u["disabled"]
        for d in [_days_since(u["last_logon_dt"], now)]
        if d is not None and d > 90
    ]
    if dormant:
        top = sorted(dormant, key=lambda x: -x[1])[:10]
        findings.append({
            "id": "USR-C02",
            "severity": "medium",
            "category": "Cuentas de Usuario",
            "title": f"Cuentas activas sin logon por más de 90 días ({len(dormant)})",
            "description": (
                "Cuentas habilitadas con inactividad prolongada: "
                + ", ".join(f"{s} ({d}d)" for s, d in top)
                + ("..." if len(dormant) > 10 else "")
                + ". Superficie de ataque innecesaria y difícil de monitorear."
            ),
            "recommendation": "Implementar limpieza automática de cuentas inactivas (GPO/script). Revisar propietarios.",
            "mitre": "T1078 — Valid Accounts",
        })

    # USR-C03: Active accounts that never logged on
    never_logon = [
        u["sam"] for u in users
        if not u["disabled"]
        and u["last_logon_dt"] is None
        and u["last_logon"].lower() in ("never", "", "0")
    ]
    if never_logon:
        findings.append({
            "id": "USR-C03",
            "severity": "low",
            "category": "Cuentas de Usuario",
            "title": f"Cuentas activas que nunca iniciaron sesión ({len(never_logon)})",
            "description": (
                f"Habilitadas pero sin uso: "
                f"{', '.join(never_logon[:10])}{'...' if len(never_logon) > 10 else ''}. "
                "Pueden ser cuentas de prueba, pre-aprovisionadas o ghost accounts."
            ),
            "recommendation": "Revisar y eliminar o deshabilitar cuentas sin uso. Auditar propietario.",
            "mitre": "T1078 — Valid Accounts",
        })

    # USR-C04: Domain Admin members with password never expires
    da_member_cns: set[str] = set()
    for g in groups:
        if any(x in g["name"].lower() for x in ["domain admin", "admins. del dom", "domain admins"]):
            da_member_cns.update(m.lower() for m in g["members"])
    if da_member_cns:
        da_no_expire = [
            u["sam"] for u in users
            if not u["disabled"] and u["no_expire"]
            and (u["sam"].lower() in da_member_cns
                 or u["display_name"].lower() in da_member_cns)
        ]
        if da_no_expire:
            findings.append({
                "id": "USR-C04",
                "severity": "critical",
                "category": "Cuentas Privilegiadas",
                "title": f"Domain Admins con contraseña sin expiración ({len(da_no_expire)})",
                "description": (
                    f"Administradores del dominio con DONT_EXPIRE_PASSWORD: {', '.join(da_no_expire)}. "
                    "Una contraseña comprometida provee acceso indefinido al dominio."
                ),
                "recommendation": "Eliminar DONT_EXPIRE_PASSWORD en cuentas DA. Rotar contraseñas periódicamente. Considerar PAM.",
                "mitre": "T1078.002 — Valid Accounts: Domain Accounts",
            })

    # USR-C05: Service accounts (svc/srv prefix) with risky configuration
    svc_risky = [
        u["sam"] for u in users
        if not u["disabled"]
        and (u["sam"].lower().startswith("svc") or u["sam"].lower().startswith("srv"))
        and (u["no_expire"] or u["no_preauth"])
    ]
    if svc_risky:
        findings.append({
            "id": "USR-C05",
            "severity": "high",
            "category": "Cuentas de Servicio",
            "title": f"Cuentas de servicio con configuración de riesgo ({len(svc_risky)})",
            "description": (
                f"Cuentas svc-*/srv-* con PasswordNeverExpires o DONT_REQ_PREAUTH: "
                f"{', '.join(svc_risky[:10])}. "
                "Objetivos primarios de Kerberoasting y AS-REP Roasting."
            ),
            "recommendation": "Migrar a gMSA (Group Managed Service Accounts). Habilitar pre-auth Kerberos.",
            "mitre": "T1558.003 — Kerberoasting",
        })

    # USR-C06: Reversible password encryption enabled
    reversible = [
        u["sam"] for u in users
        if not u["disabled"] and "ENCRYPTED_TEXT_PWD_ALLOWED" in u.get("uac_flags", [])
    ]
    if reversible:
        findings.append({
            "id": "USR-C06",
            "severity": "high",
            "category": "Cuentas de Usuario",
            "title": f"Cifrado reversible de contraseñas habilitado ({len(reversible)})",
            "description": (
                f"Cuentas con AllowReversiblePasswordEncryption: {', '.join(reversible[:10])}. "
                "Las contraseñas se almacenan en texto plano equivalente en NTDS.dit."
            ),
            "recommendation": "Deshabilitar inmediatamente. Cambiar contraseñas afectadas.",
            "mitre": "T1003.003 — NTDS (Credential Dumping)",
        })

    # ── Computer findings ────────────────────────────────────────────────────

    # COMP-C01: Critical legacy OS
    legacy_crit = [c for c in computers if c.get("os_risk") == "critical"]
    if legacy_crit:
        findings.append({
            "id": "COMP-C01",
            "severity": "critical",
            "category": "Equipos",
            "title": f"Equipos con OS fuera de soporte crítico ({len(legacy_crit)})",
            "description": (
                "SO sin parches ni soporte: "
                + ", ".join(f"{c['name']} ({c['os']})" for c in legacy_crit[:8])
                + ("..." if len(legacy_crit) > 8 else "")
                + ". Vulnerables a EternalBlue, MS17-010 y exploits públicos sin CVE."
            ),
            "recommendation": "Aislar en VLAN sin acceso a red corporativa. Planificar retiro urgente.",
            "mitre": "T1210 — Exploitation of Remote Services",
        })

    # COMP-C02: High-risk legacy OS
    legacy_high = [c for c in computers if c.get("os_risk") == "high"]
    if legacy_high:
        findings.append({
            "id": "COMP-C02",
            "severity": "high",
            "category": "Equipos",
            "title": f"Equipos con OS EOL (Win7 / Server 2008) ({len(legacy_high)})",
            "description": (
                ", ".join(f"{c['name']} ({c['os']})" for c in legacy_high[:8])
                + ("..." if len(legacy_high) > 8 else "")
            ),
            "recommendation": "Migrar urgente a Windows 10/11 o Server 2019/2022.",
            "mitre": "T1210 — Exploitation of Remote Services",
        })

    # COMP-C03: Medium-risk legacy OS
    legacy_med = [c for c in computers if c.get("os_risk") == "medium"]
    if legacy_med:
        findings.append({
            "id": "COMP-C03",
            "severity": "medium",
            "category": "Equipos",
            "title": f"Equipos con OS sin soporte mainstream (Server 2012) ({len(legacy_med)})",
            "description": ", ".join(f"{c['name']} ({c['os']})" for c in legacy_med[:8]),
            "recommendation": "Planificar migración. Aplicar parches ESU si disponibles.",
            "mitre": "T1190 — Exploit Public-Facing Application",
        })

    # COMP-C04: Inactive computers (90+ days, non-DC)
    inactive_comps = [
        (c["name"], d)
        for c in computers
        if not c["is_dc"]
        for d in [_days_since(c["last_logon_dt"], now)]
        if d is not None and d > 90
    ]
    if inactive_comps:
        top = sorted(inactive_comps, key=lambda x: -x[1])[:10]
        findings.append({
            "id": "COMP-C04",
            "severity": "low",
            "category": "Equipos",
            "title": f"Equipos inactivos por más de 90 días ({len(inactive_comps)})",
            "description": (
                ", ".join(f"{n} ({d}d)" for n, d in top)
                + ("..." if len(inactive_comps) > 10 else "")
            ),
            "recommendation": "Deshabilitar o eliminar objetos de equipos obsoletos del dominio.",
            "mitre": "T1078 — Valid Accounts",
        })

    # ── Group findings ───────────────────────────────────────────────────────

    # GRP-C01: Privileged groups with excessive membership
    _PRIV_KW = ["domain admin", "enterprise admin", "schema admin", "administrators",
                "admins. del dom"]
    priv_groups = [g for g in groups if any(x in g["name"].lower() for x in _PRIV_KW)]
    large_priv  = [(g["name"], g["member_count"]) for g in priv_groups if g["member_count"] > 5]
    if large_priv:
        findings.append({
            "id": "GRP-C01",
            "severity": "high",
            "category": "Grupos Privilegiados",
            "title": f"Grupos privilegiados con membresía excesiva ({len(large_priv)})",
            "description": (
                "Grupos con >5 miembros: "
                + ", ".join(f"{n} ({cnt})" for n, cnt in large_priv[:5])
                + ". Viola el principio de mínimo privilegio."
            ),
            "recommendation": "Reducir membresía a cuentas estrictamente necesarias. Implementar AD Tier Model.",
            "mitre": "T1069.002 — Permission Groups Discovery: Domain Groups",
        })

    # GRP-C02: Empty privileged groups (may indicate misconfiguration)
    empty_priv = [g["name"] for g in priv_groups if g["member_count"] == 0]
    if empty_priv:
        findings.append({
            "id": "GRP-C02",
            "severity": "info",
            "category": "Grupos Privilegiados",
            "title": f"Grupos privilegiados sin miembros ({len(empty_priv)})",
            "description": f"Sin miembros: {', '.join(empty_priv[:10])}. Verificar si es hardening intencional.",
            "recommendation": "Confirmar que el vaciado es intencional. Documentar en CMDB.",
            "mitre": "T1069.002 — Permission Groups Discovery",
        })

    # GRP-C03: Nested privilege — user in both DA and standard groups
    da_members = set()
    for g in groups:
        if any(x in g["name"].lower() for x in ["domain admin", "admins. del dom"]):
            da_members.update(m.lower() for m in g["members"])

    dual_role = [
        u["sam"] for u in users
        if not u["disabled"]
        and (u["sam"].lower() in da_members or u["display_name"].lower() in da_members)
        and u["last_logon_dt"] is not None
    ]
    if len(dual_role) > 0 and len(da_members) > 0:
        findings.append({
            "id": "GRP-C03",
            "severity": "medium",
            "category": "Grupos Privilegiados",
            "title": f"Domain Admins con cuentas de uso diario ({len(dual_role)})",
            "description": (
                f"Administradores que usan su cuenta DA para logon interactivo: {', '.join(dual_role[:10])}. "
                "Las cuentas DA no deben usarse para trabajo diario (Pass-the-Hash, credential exposure)."
            ),
            "recommendation": "Implementar cuentas separadas: una estándar para trabajo diario y una privilegiada (T0) solo para administración.",
            "mitre": "T1078.002 — Valid Accounts: Domain Accounts",
        })

    # ── OU findings ──────────────────────────────────────────────────────────

    if ous:
        user_ou_names = {_ou_from_dn(u["dn"]) for u in users}
        comp_ou_names = {_ou_from_dn(c["dn"]) for c in computers}

        # OU-C01: OUs without linked GPO (excluding system OUs)
        _SKIP_OU_KW = {"security groups", "exchange", "builtin", "system", "foreign", "lost", "microsoft"}
        ou_no_gpo = [
            o for o in ous
            if o["gpo_count"] == 0
            and not any(kw in o["name"].lower() for kw in _SKIP_OU_KW)
        ]
        if ou_no_gpo:
            findings.append({
                "id": "OU-C01",
                "severity": "medium",
                "category": "OUs",
                "title": f"OUs sin GPO vinculada ({len(ou_no_gpo)})",
                "description": (
                    f"OUs sin Group Policy Object aplicada: "
                    f"{', '.join(o['name'] for o in ou_no_gpo[:10])}{'...' if len(ou_no_gpo) > 10 else ''}. "
                    "Equipos y usuarios en estas OUs pueden carecer de hardening de seguridad."
                ),
                "recommendation": "Vincular GPOs de baseline (CIS Benchmarks) a OUs de usuarios y equipos. Revisar herencia.",
                "mitre": "T1484.001 — Group Policy Modification",
            })

        # OU-C02: Sensitive OUs without accidental-deletion protection
        _SENSITIVE_KW = {"usuarios", "users", "computers", "computadoras", "servidores", "servers", "workstations"}
        unprotected = [
            o for o in ous
            if not o["protected"]
            and any(kw in o["name"].lower() for kw in _SENSITIVE_KW)
        ]
        if unprotected:
            findings.append({
                "id": "OU-C02",
                "severity": "low",
                "category": "OUs",
                "title": f"OUs sensibles sin protección contra borrado accidental ({len(unprotected)})",
                "description": (
                    f"{', '.join(o['name'] for o in unprotected[:8])} "
                    "no tienen ProtectedFromAccidentalDeletion=True."
                ),
                "recommendation": "Set-ADOrganizationalUnit -Identity <DN> -ProtectedFromAccidentalDeletion $true",
                "mitre": "T1485 — Data Destruction",
            })

        # OU-C03: Empty OUs (no users or computers)
        empty_ous = [
            o for o in ous
            if o["name"] not in user_ou_names
            and o["name"] not in comp_ou_names
            and not any(kw in o["name"].lower() for kw in _SKIP_OU_KW)
        ]
        if len(empty_ous) > 3:
            findings.append({
                "id": "OU-C03",
                "severity": "info",
                "category": "OUs",
                "title": f"OUs aparentemente vacías ({len(empty_ous)})",
                "description": (
                    f"OUs sin usuarios ni equipos detectados: "
                    f"{', '.join(o['name'] for o in empty_ous[:8])}{'...' if len(empty_ous) > 8 else ''}. "
                    "Pueden indicar estructura obsoleta o migración incompleta."
                ),
                "recommendation": "Revisar y consolidar estructura de OUs. Eliminar OUs vacías obsoletas.",
                "mitre": "T1069.002 — Domain Groups / AD Structure Enumeration",
            })

    # ── New composite findings ───────────────────────────────────────────────

    # Rebuild da_members set (needed for USR-C07, USR-C08, USR-C09)
    _da_members_extra: set[str] = set()
    for g in groups:
        if any(x in g["name"].lower() for x in _DA_KW):
            for m in g["members"]:
                _da_members_extra.add(m.lower())

    def _in_da_e(u: dict) -> bool:
        return u["sam"].lower() in _da_members_extra or u["display_name"].lower() in _da_members_extra

    # USR-C07: Kerberoastable + Domain Admin
    da_kerberoast = [u["sam"] for u in users if not u["disabled"] and u["spn"] and _in_da_e(u)]
    if da_kerberoast:
        findings.append({
            "id": "USR-C07",
            "severity": "critical",
            "category": "Cuentas Privilegiadas",
            "title": f"Kerberoastable + Domain Admin ({len(da_kerberoast)})",
            "description": (
                f"Cuentas DA con SPN activo: {', '.join(da_kerberoast[:10])}. "
                "Crackear el TGS entrega acceso de Domain Admin de inmediato. "
                "Peor combinación posible: ataque offline que no requiere interacción de la víctima."
            ),
            "recommendation": "Migrar a gMSA. Nunca asignar SPNs a cuentas DA. Rotar contraseñas (>25 chars).",
            "mitre": "T1558.003 — Kerberoasting",
        })

    # USR-C08: Triple threat: AS-REP + no_expire + active
    triple_threat = [u["sam"] for u in users if not u["disabled"] and u["no_preauth"] and u["no_expire"]]
    if triple_threat:
        findings.append({
            "id": "USR-C08",
            "severity": "critical",
            "category": "Cuentas de Usuario",
            "title": f"Triple amenaza: AS-REP roastable + sin expiración + activo ({len(triple_threat)})",
            "description": (
                f"{', '.join(triple_threat[:10])} — AS-REP Roastable con contraseña que nunca vence. "
                "Ventana de cracking offline indefinida sin necesidad de credenciales previas."
            ),
            "recommendation": "Habilitar pre-autenticación Kerberos. Configurar expiración de contraseña. Resetear credenciales.",
            "mitre": "T1558.004 — AS-REP Roasting / T1078.002 — Valid Accounts",
        })

    # USR-C09: Service account in DA/Schema/Enterprise Admin
    _STRICT_PRIV = ["domain admin", "enterprise admin", "schema admin", "admins. del dom"]
    svc_in_priv: list[str] = []
    for g in groups:
        if any(x in g["name"].lower() for x in _STRICT_PRIV):
            for m in g["members"]:
                if m.lower().startswith(("svc", "srv")):
                    svc_in_priv.append(m)
    if svc_in_priv:
        findings.append({
            "id": "USR-C09",
            "severity": "critical",
            "category": "Cuentas de Servicio",
            "title": f"Cuentas de servicio en grupo privilegiado ({len(svc_in_priv)})",
            "description": (
                f"svc-*/srv-* con membresía en DA/Schema/Enterprise Admin: "
                f"{', '.join(svc_in_priv[:10])}. "
                "Las cuentas de servicio raramente se monitorean; comprometerlas es un vector de persistencia silencioso."
            ),
            "recommendation": "Eliminar de grupos privilegiados. Usar cuentas de servicio dedicadas con mínimo privilegio.",
            "mitre": "T1078.002 — Valid Accounts: Domain Accounts",
        })

    # USR-C10: Password stale >365 days
    stale_pwd: list[str] = []
    for u in users:
        if not u["disabled"]:
            days = _days_since(_parse_date(u["pwd_last_set"]), now)
            if days is not None and days > 365:
                stale_pwd.append(u["sam"])
    if stale_pwd:
        findings.append({
            "id": "USR-C10",
            "severity": "medium",
            "category": "Cuentas de Usuario",
            "title": f"Contraseñas sin cambiar por más de 365 días ({len(stale_pwd)})",
            "description": (
                f"{len(stale_pwd)} cuentas activas con contraseña estancada >1 año: "
                f"{', '.join(stale_pwd[:10])}{'...' if len(stale_pwd) > 10 else ''}. "
                "Aumenta la ventana de exposición post-breach."
            ),
            "recommendation": "Forzar cambio de contraseña. Configurar MaxPasswordAge ≤ 90 días en GPO.",
            "mitre": "T1110 — Brute Force",
        })

    # USR-C11: Ghost accounts (active, missing identity attributes)
    ghost = [
        u["sam"] for u in users
        if not u["disabled"]
        and not u.get("display_name")
        and (not u.get("department") or not u.get("company"))
    ]
    if ghost:
        findings.append({
            "id": "USR-C11",
            "severity": "low",
            "category": "Cuentas de Usuario",
            "title": f"Cuentas fantasma sin atributos de identidad ({len(ghost)})",
            "description": (
                f"{len(ghost)} cuentas activas sin nombre, departamento o empresa: "
                f"{', '.join(ghost[:10])}{'...' if len(ghost) > 10 else ''}. "
                "Candidatos a backdoors, cuentas de prueba olvidadas o usuarios huérfanos."
            ),
            "recommendation": "Revisar propietario. Deshabilitar si sin justificación. Completar atributos de identidad en AD.",
            "mitre": "T1078.002 — Valid Accounts: Domain Accounts",
        })

    # COMP-C05: Domain Controller with legacy OS
    legacy_dcs = [c for c in computers if c["is_dc"] and c.get("os_risk") in ("critical", "high")]
    if legacy_dcs:
        findings.append({
            "id": "COMP-C05",
            "severity": "critical",
            "category": "Equipos",
            "title": f"Domain Controllers con OS legado ({len(legacy_dcs)})",
            "description": (
                "DCs vulnerables: "
                + ", ".join(f"{c['name']} ({c['os']})" for c in legacy_dcs[:5])
                + ". Un DC comprometido entrega control total del dominio. "
                "Vulnerable a EternalBlue/MS17-010 y exploits con PoC público."
            ),
            "recommendation": "URGENTE: Aislar en VLAN. Planificar actualización de OS de DC inmediatamente. Sin excepciones.",
            "mitre": "T1210 — Exploitation of Remote Services",
        })

    # GRP-C04: Nested privilege escalation (group-in-group)
    _priv_group_names = {g["name"].lower() for g in groups if any(x in g["name"].lower() for x in _STRICT_PRIV)}
    nested_esc: list[str] = []
    for g in groups:
        if g["name"].lower() in _priv_group_names:
            continue
        for m in g["members"]:
            if any(pk in m.lower() for pk in ["domain admin", "enterprise admin", "schema admin", "admins"]):
                nested_esc.append(f"{m} → vía '{g['name']}'")
                break
    if nested_esc:
        findings.append({
            "id": "GRP-C04",
            "severity": "high",
            "category": "Grupos Privilegiados",
            "title": f"Escalada anidada hacia grupos privilegiados ({len(nested_esc)})",
            "description": (
                f"Grupos no privilegiados con membresía transitiva en DA/Admin: "
                f"{', '.join(nested_esc[:8])}{'...' if len(nested_esc) > 8 else ''}. "
                "Los miembros heredan privilegios de administrador sin que sea obvio."
            ),
            "recommendation": "Eliminar grupos anidados de grupos privilegiados. Auditar con Get-ADGroupMember -Recursive.",
            "mitre": "T1484.001 — Group Policy / Nested Group Escalation",
        })

    # GRP-C05: Kerberoastable accounts in Operator groups
    _OP_GROUPS = ["backup operators", "account operators", "print operators", "server operators"]
    svc_op: list[str] = []
    for u in users:
        if not u["disabled"] and u["spn"]:
            for g in groups:
                if any(x in g["name"].lower() for x in _OP_GROUPS):
                    if any(m.lower() in (u["sam"].lower(), u["display_name"].lower()) for m in g["members"]):
                        svc_op.append(f"{u['sam']} ({g['name']})")
                        break
    if svc_op:
        findings.append({
            "id": "GRP-C05",
            "severity": "critical",
            "category": "Cuentas de Servicio",
            "title": f"Cuentas Kerberoastables en grupos Operator ({len(svc_op)})",
            "description": (
                f"Cuentas con SPN en Backup/Account/Print/Server Operators: "
                f"{', '.join(svc_op[:8])}. "
                "Kerberoastear estas cuentas otorga capacidades de privilegio elevado frecuentemente ignoradas."
            ),
            "recommendation": "Remover de grupos Operators. Mínimo privilegio. Usar gMSA para cuentas de servicio.",
            "mitre": "T1558.003 — Kerberoasting",
        })

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: order.get(x["severity"], 5))
    return findings


# ── Service ──────────────────────────────────────────────────────────────────

class CsvImportService:
    """
    Accepts raw CSV bytes (keyed by filename), auto-classifies, parses AD objects,
    generates findings (base + cross-reference), and returns the same data structure
    as ResultsService.get_latest() so the frontend renders with the same component.

    The last successful analysis is cached in _last_result so that
    /csv/neo4j-import can consume it without requiring a re-upload.
    """

    def __init__(self):
        self._last_result: dict | None = None

    def get_last_result(self) -> dict | None:
        return self._last_result

    def analyze(self, file_contents: dict[str, bytes]) -> dict[str, Any]:
        categorized: dict[str, bytes] = {}
        skipped: list[str] = []

        for fname, content in file_contents.items():
            rows = _read_csv(content)
            if not rows:
                skipped.append(fname)
                continue
            headers = list(rows[0].keys())
            kind    = _detect_csv_type(headers)

            if kind == "unknown":
                fname_l = fname.lower()
                for key in ("policy", "ous", "groups", "computers", "users"):
                    if key in fname_l:
                        kind = key
                        break

            if kind != "unknown" and kind not in categorized:
                categorized[kind] = content
            else:
                skipped.append(fname)

        users_data = _parse_users(categorized.get("users",     b""))
        comps_data = _parse_computers(categorized.get("computers", b""))
        grps_data  = _parse_groups(categorized.get("groups",   b""))
        ous_data   = _parse_ous(categorized.get("ous",         b""))
        pol_data   = _parse_policy(categorized.get("policy",   b""))

        _compute_risk_scores(users_data, grps_data)
        attack_paths   = _synthesize_attack_paths(users_data, grps_data, comps_data)
        base_findings  = _generate_findings(pol_data, users_data, grps_data)
        extra_findings = _generate_extra_findings(users_data, comps_data, grps_data, ous_data)

        seen_ids = {f["id"] for f in base_findings}
        combined = base_findings + [f for f in extra_findings if f["id"] not in seen_ids]
        order    = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        combined.sort(key=lambda x: order.get(x["severity"], 5))

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in combined:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

        active   = [u for u in users_data if not u["disabled"]]
        disabled = [u for u in users_data if u["disabled"]]
        priv_ou  = {"Administradores", "Domain Admins", "Honeypots"}
        priv     = [u for u in users_data if u["ou"] in priv_ou]

        user_ou_set = {_ou_from_dn(u["dn"]) for u in users_data}
        comp_ou_set = {_ou_from_dn(c["dn"]) for c in comps_data}
        empty_ous   = [
            o for o in ous_data
            if o["name"] not in user_ou_set and o["name"] not in comp_ou_set
        ]

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        result = {
            "available":       True,
            "source":          "csv",
            "timestamp":       ts,
            "dump_dir":        "csv_import",
            "files_detected":  list(categorized.keys()),
            "files_skipped":   skipped,
            "summary":         {"errors": 0, "warnings": 0, "timestamp": ts, "steps": []},
            "findings":        combined,
            "severity_counts": sev_counts,
            "stats": {
                "total_users":        len(users_data),
                "active_users":       len(active),
                "disabled_users":     len(disabled),
                "privileged_users":   len(priv),
                "total_computers":    len(comps_data),
                "domain_controllers": sum(1 for c in comps_data if c["is_dc"]),
                "total_groups":       len(grps_data),
                "total_ous":          len(ous_data),
                "empty_ous":          len(empty_ous),
                "ports_open":         0,
                "ports_filtered":     0,
            },
            "users":               users_data,
            "computers":           comps_data,
            "groups":              grps_data,
            "ous":                 ous_data,
            "policy":              pol_data,
            "attack_paths":        attack_paths,
            "ports":               [],
            "bloodhound_available": False,
        }
        self._last_result = result
        return result
