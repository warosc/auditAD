"""
results_service.py — Parses raw audit outputs into structured, interpreted data.

Reads ldapdomaindump JSON, nmap output and audit summaries from /workspace/reports
and returns human-readable findings with severity classification.
"""
from __future__ import annotations

import glob
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

REPORTS_DIR = os.environ.get("REPORTS_DIR", "/workspace/reports")


# ── UAC flag decoder ────────────────────────────────────────────────────────

UAC_FLAGS = {
    0x0001: "SCRIPT",
    0x0002: "ACCOUNTDISABLE",
    0x0008: "HOMEDIR_REQUIRED",
    0x0010: "LOCKOUT",
    0x0020: "PASSWD_NOTREQD",
    0x0040: "PASSWD_CANT_CHANGE",
    0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x0100: "TEMP_DUPLICATE_ACCOUNT",
    0x0200: "NORMAL_ACCOUNT",
    0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x1000: "WORKSTATION_TRUST_ACCOUNT",
    0x2000: "SERVER_TRUST_ACCOUNT",
    0x10000: "DONT_EXPIRE_PASSWORD",
    0x20000: "MNS_LOGON_ACCOUNT",
    0x40000: "SMARTCARD_REQUIRED",
    0x80000: "TRUSTED_FOR_DELEGATION",
    0x100000: "NOT_DELEGATED",
    0x200000: "USE_DES_KEY_ONLY",
    0x400000: "DONT_REQ_PREAUTH",
    0x800000: "PASSWORD_EXPIRED",
    0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x4000000: "PARTIAL_SECRETS_ACCOUNT",
}


def decode_uac(uac: int) -> list[str]:
    return [name for flag, name in UAC_FLAGS.items() if uac & flag]


# ── Helpers ─────────────────────────────────────────────────────────────────

def _first(lst: list, default="") -> Any:
    return lst[0] if lst else default


def _latest_ldapdump_dir() -> str | None:
    dirs = sorted(glob.glob(os.path.join(REPORTS_DIR, "ldapdomaindump_*")), reverse=True)
    return dirs[0] if dirs else None


def _latest_nmap_file() -> str | None:
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "nmap", "nmap_ports_*.txt")), reverse=True)
    return files[0] if files else None


def _latest_audit_summary() -> str | None:
    files = sorted(glob.glob(os.path.join(REPORTS_DIR, "audit_summary_*.txt")), reverse=True)
    return files[0] if files else None


def _parse_nmap(filepath: str) -> list[dict]:
    ports = []
    try:
        with open(filepath, errors="replace") as f:
            for line in f:
                m = re.match(r"(\d+)/tcp\s+(open|closed|filtered)\s+(\S+)", line.strip())
                if m:
                    port, state, service = m.groups()
                    ports.append({"port": int(port), "state": state, "service": service})
    except OSError:
        pass
    return ports


def _parse_audit_summary(filepath: str) -> dict:
    result = {"errors": 0, "warnings": 0, "timestamp": "", "steps": []}
    try:
        with open(filepath, errors="replace") as f:
            content = f.read()
        # Extract timestamp from banner
        m = re.search(r"Fecha\s*:\s*(.+)", content)
        if m:
            result["timestamp"] = m.group(1).strip()
        # Count
        result["errors"]   = content.count("[FAIL]")
        result["warnings"] = content.count("[WARN]")
        # Identify steps
        for step in re.findall(r"Paso \d+[^═\n]*", content):
            result["steps"].append(step.strip("═ \n"))
    except OSError:
        pass
    return result


# ── Security findings generator ──────────────────────────────────────────────

def _generate_findings(policy: dict, users: list[dict], groups: list[dict]) -> list[dict]:
    findings: list[dict] = []

    # --- Policy findings ---
    lockout = policy.get("lockoutThreshold", -1)
    min_pwd = policy.get("minPwdLength", -1)
    max_pwd = policy.get("maxPwdAge_days", -1)
    pwd_props = policy.get("pwdProperties", 0)
    machine_quota = policy.get("machineAccountQuota", 10)
    behavior = policy.get("behaviorVersion", 0)

    if lockout == 0:
        findings.append({
            "id": "POL-001",
            "severity": "critical",
            "category": "Política de Contraseñas",
            "title": "Sin bloqueo de cuentas (Account Lockout = 0)",
            "description": "El umbral de bloqueo está en 0, permitiendo ataques de password spraying y fuerza bruta sin restricción.",
            "recommendation": "Configurar Account Lockout Threshold ≥ 5 intentos en Default Domain Policy.",
            "mitre": "T1110.003 — Password Spraying",
        })

    if 0 < min_pwd < 12:
        findings.append({
            "id": "POL-002",
            "severity": "high",
            "category": "Política de Contraseñas",
            "title": f"Longitud mínima de contraseña insuficiente ({min_pwd} caracteres)",
            "description": f"La política exige solo {min_pwd} caracteres. Las contraseñas cortas son vulnerables a ataques de diccionario y fuerza bruta offline.",
            "recommendation": "Aumentar minPwdLength a 14+ caracteres (NIST SP 800-63B).",
            "mitre": "T1110.002 — Password Cracking",
        })

    if pwd_props == 0:
        findings.append({
            "id": "POL-003",
            "severity": "high",
            "category": "Política de Contraseñas",
            "title": "Complejidad de contraseña deshabilitada",
            "description": "pwdProperties=0 indica que no se exige complejidad (mayúsculas, números, símbolos).",
            "recommendation": "Habilitar Password Complexity Requirements en Default Domain Policy.",
            "mitre": "T1110 — Brute Force",
        })

    if machine_quota > 0:
        findings.append({
            "id": "POL-004",
            "severity": "medium",
            "category": "Configuración del Dominio",
            "title": f"ms-DS-MachineAccountQuota = {machine_quota}",
            "description": f"Cualquier usuario autenticado puede agregar hasta {machine_quota} equipos al dominio. Permite ataques de Resource-Based Constrained Delegation (RBCD).",
            "recommendation": "Reducir MachineAccountQuota a 0 y usar cuentas privilegiadas para unir equipos.",
            "mitre": "T1136.002 — Create Domain Account / RBCD Attack",
        })

    # --- User findings ---
    no_expire = []
    not_req = []
    honeypots = []
    disabled_admin = False
    kerberoastable = []
    asrep_roastable = []

    for u in users:
        sam   = u.get("sam", "")
        uac   = u.get("uac", 0)
        flags = u.get("uac_flags", [])
        ou    = u.get("ou", "")
        spn   = u.get("spn", [])

        if "DONT_EXPIRE_PASSWORD" in flags and "ACCOUNTDISABLE" not in flags:
            no_expire.append(sam)

        if "PASSWD_NOTREQD" in flags and "ACCOUNTDISABLE" not in flags:
            not_req.append(sam)

        if "Honeypots" in ou:
            honeypots.append(sam)

        if sam == "Administrador" and "ACCOUNTDISABLE" not in flags:
            disabled_admin = False  # It's enabled

        if "DONT_REQ_PREAUTH" in flags and "ACCOUNTDISABLE" not in flags:
            asrep_roastable.append(sam)

        if spn and "ACCOUNTDISABLE" not in flags:
            kerberoastable.append(sam)

    if no_expire:
        findings.append({
            "id": "USR-001",
            "severity": "medium",
            "category": "Cuentas de Usuario",
            "title": f"Contraseña sin expiración en {len(no_expire)} cuenta(s)",
            "description": f"Cuentas con DONT_EXPIRE_PASSWORD: {', '.join(no_expire[:10])}{'...' if len(no_expire)>10 else ''}",
            "recommendation": "Revisar si la expiración es necesaria. Para cuentas de servicio usar gMSA.",
            "mitre": "T1078 — Valid Accounts",
        })

    if not_req:
        findings.append({
            "id": "USR-002",
            "severity": "high",
            "category": "Cuentas de Usuario",
            "title": f"Contraseña no requerida (PASSWD_NOTREQD) en {len(not_req)} cuenta(s)",
            "description": f"Estas cuentas pueden no tener contraseña: {', '.join(not_req)}",
            "recommendation": "Eliminar el flag PASSWD_NOTREQD y establecer contraseñas fuertes.",
            "mitre": "T1078 — Valid Accounts",
        })

    if asrep_roastable:
        findings.append({
            "id": "USR-003",
            "severity": "high",
            "category": "Kerberos",
            "title": f"Cuentas vulnerables a AS-REP Roasting ({len(asrep_roastable)})",
            "description": f"Cuentas sin pre-autenticación Kerberos: {', '.join(asrep_roastable)}. Un atacante puede obtener hashes offline.",
            "recommendation": "Habilitar Kerberos pre-authentication en todas las cuentas.",
            "mitre": "T1558.004 — AS-REP Roasting",
        })

    if kerberoastable:
        findings.append({
            "id": "USR-004",
            "severity": "high",
            "category": "Kerberos",
            "title": f"Cuentas con SPN vulnerables a Kerberoasting ({len(kerberoastable)})",
            "description": f"Cuentas con SPN: {', '.join(kerberoastable[:5])}. Un atacante autenticado puede solicitar TGS y crackear offline.",
            "recommendation": "Usar contraseñas largas (25+) en cuentas de servicio o migrar a gMSA.",
            "mitre": "T1558.003 — Kerberoasting",
        })

    if honeypots:
        findings.append({
            "id": "USR-005",
            "severity": "info",
            "category": "Detección",
            "title": f"Cuentas honeypot detectadas ({len(honeypots)})",
            "description": f"OU=Honeypots contiene: {', '.join(honeypots)}. Cualquier acceso a estas cuentas indica actividad maliciosa.",
            "recommendation": "Monitorear en Wazuh/SIEM alertas de Event ID 4625/4624 para estas cuentas.",
            "mitre": "T1078 — Valid Accounts (detection)",
        })

    # --- Group findings ---
    admin_groups = [g for g in groups if any(x in g.get("name","").lower()
                    for x in ["admin", "domain admin", "schema", "enterprise"])]
    if admin_groups:
        findings.append({
            "id": "GRP-001",
            "severity": "info",
            "category": "Grupos Privilegiados",
            "title": f"Grupos privilegiados identificados ({len(admin_groups)})",
            "description": f"Grupos de alto privilegio: {', '.join(g['name'] for g in admin_groups[:8])}",
            "recommendation": "Revisar membresía de grupos privilegiados. Minimizar pertenencia.",
            "mitre": "T1069.002 — Domain Groups Enumeration",
        })

    # Sort by severity
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: order.get(x["severity"], 5))
    return findings


# ── Main service ─────────────────────────────────────────────────────────────

class ResultsService:

    def get_latest(self) -> dict[str, Any]:
        dump_dir  = _latest_ldapdump_dir()
        nmap_file = _latest_nmap_file()
        summary_f = _latest_audit_summary()

        if not dump_dir:
            return {
                "available": False,
                "message": "No hay datos de auditoría. Ejecuta una auditoría desde el panel.",
            }

        ts = os.path.basename(dump_dir).replace("ldapdomaindump_", "")

        # ── Parse users ──
        users_raw  = self._load_json(os.path.join(dump_dir, "domain_users.json"))
        users_data = []
        for u in users_raw:
            a   = u.get("attributes", {})
            sam = _first(a.get("sAMAccountName", []))
            uac = _first(a.get("userAccountControl", [0]))
            flags = decode_uac(uac)
            dn  = u.get("dn", "")
            ou  = re.search(r"OU=([^,]+)", dn)
            spn = a.get("servicePrincipalName", [])
            users_data.append({
                "sam":       sam,
                "dn":        dn,
                "ou":        ou.group(1) if ou else "Users",
                "uac":       uac,
                "uac_flags": flags,
                "disabled":  "ACCOUNTDISABLE" in flags,
                "no_expire": "DONT_EXPIRE_PASSWORD" in flags,
                "no_preauth":"DONT_REQ_PREAUTH" in flags,
                "spn":       spn,
                "last_logon": str(_first(a.get("lastLogon", ["never"]))),
                "pwd_last_set": str(_first(a.get("pwdLastSet", ["never"]))),
                "upn":       _first(a.get("userPrincipalName", [])),
            })

        # ── Parse computers ──
        comps_raw  = self._load_json(os.path.join(dump_dir, "domain_computers.json"))
        comps_data = []
        for c in comps_raw:
            a  = c.get("attributes", {})
            dn = c.get("dn", "")
            uac = _first(a.get("userAccountControl", [0]))
            comps_data.append({
                "name":    _first(a.get("cn", ["?"])),
                "dn":      dn,
                "sam":     _first(a.get("sAMAccountName", ["?"])),
                "os":      _first(a.get("operatingSystem", ["Desconocido"])),
                "os_ver":  _first(a.get("operatingSystemVersion", [""])),
                "uac":     uac,
                "is_dc":   "Domain Controllers" in dn,
                "last_logon": str(_first(a.get("lastLogon", ["never"]))),
            })

        # ── Parse groups ──
        grps_raw  = self._load_json(os.path.join(dump_dir, "domain_groups.json"))
        grps_data = []
        for g in grps_raw:
            a  = g.get("attributes", {})
            dn = g.get("dn", "")
            members = a.get("member", [])
            grps_data.append({
                "name":    _first(a.get("cn", ["?"])),
                "sam":     _first(a.get("sAMAccountName", ["?"])),
                "dn":      dn,
                "member_count": len(members),
                "members": members[:20],
            })

        # ── Parse policy ──
        pol_raw  = self._load_json(os.path.join(dump_dir, "domain_policy.json"))
        pol_data = {}
        if pol_raw:
            a = pol_raw[0].get("attributes", {})
            pol_data = {
                "domain":            _first(a.get("dc", ["?"])),
                "dn":                _first(a.get("distinguishedName", [])),
                "minPwdLength":      _first(a.get("minPwdLength", [0])),
                "maxPwdAge":         str(_first(a.get("maxPwdAge", ["?"]))),
                "minPwdAge":         str(_first(a.get("minPwdAge", ["?"]))),
                "pwdHistoryLength":  _first(a.get("pwdHistoryLength", [0])),
                "pwdProperties":     _first(a.get("pwdProperties", [0])),
                "lockoutThreshold":  _first(a.get("lockoutThreshold", [0])),
                "lockoutDuration":   str(_first(a.get("lockoutDuration", ["?"]))),
                "behaviorVersion":   _first(a.get("msDS-Behavior-Version", [0])),
                "machineAccountQuota": _first(a.get("ms-DS-MachineAccountQuota", [10])),
                "objectSid":         _first(a.get("objectSid", [])),
                "maxPwdAge_days":    42,  # extracted from string for findings
            }
            # Extract days from maxPwdAge string
            m = re.search(r"(\d+) day", pol_data["maxPwdAge"])
            if m:
                pol_data["maxPwdAge_days"] = int(m.group(1))

        # ── Parse nmap ──
        ports_data = _parse_nmap(nmap_file) if nmap_file else []

        # ── Parse audit summary ──
        summary_data = _parse_audit_summary(summary_f) if summary_f else {}

        # ── Generate findings ──
        findings = _generate_findings(pol_data, users_data, grps_data)

        # ── Counts ──
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

        active_users    = [u for u in users_data if not u["disabled"]]
        disabled_users  = [u for u in users_data if u["disabled"]]
        privileged_ous  = ["Administradores", "Domain Admins", "Honeypots"]
        priv_users      = [u for u in users_data if u["ou"] in privileged_ous]

        return {
            "available":   True,
            "timestamp":   ts,
            "dump_dir":    os.path.basename(dump_dir),
            "summary":     summary_data,
            "findings":    findings,
            "severity_counts": severity_counts,
            "stats": {
                "total_users":    len(users_data),
                "active_users":   len(active_users),
                "disabled_users": len(disabled_users),
                "privileged_users": len(priv_users),
                "total_computers": len(comps_data),
                "domain_controllers": sum(1 for c in comps_data if c["is_dc"]),
                "total_groups":   len(grps_data),
                "ports_open":     sum(1 for p in ports_data if p["state"] == "open"),
                "ports_filtered": sum(1 for p in ports_data if p["state"] == "filtered"),
            },
            "users":     users_data,
            "computers": comps_data,
            "groups":    grps_data,
            "policy":    pol_data,
            "ports":     ports_data,
            "bloodhound_available": self._bloodhound_available(),
        }

    def _load_json(self, path: str) -> list:
        try:
            with open(path) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

    def _bloodhound_available(self) -> bool:
        zips = glob.glob(os.path.join(REPORTS_DIR, "bloodhound", "**", "*.zip"), recursive=True)
        return len(zips) > 0

    def _parse_attack_results(self) -> dict:
        """Parse AS-REP Roasting and Kerberoasting results."""
        result = {
            "asrep": {"run": False, "hashes": 0, "cracked": [], "vulnerable_accounts": []},
            "kerberoast": {"run": False, "hashes": 0, "cracked": [], "vulnerable_accounts": []},
        }

        # AS-REP Roasting
        asrep_dir = os.path.join(REPORTS_DIR, "asrep_roast")
        if os.path.exists(asrep_dir):
            result["asrep"]["run"] = True
            # Latest cracked file
            cracked_files = sorted(glob.glob(os.path.join(asrep_dir, "asrep_cracked_*.txt")), reverse=True)
            if cracked_files:
                for line in Path(cracked_files[0]).read_text(errors="replace").splitlines():
                    if line.startswith("#") or ":" not in line:
                        continue
                    user, _, pwd = line.partition(":")
                    if user.strip():
                        result["asrep"]["cracked"].append({"user": user.strip(), "password": pwd.strip()})
            # Count hashes
            hash_files = sorted(glob.glob(os.path.join(asrep_dir, "asrep_hashes_*.txt")), reverse=True)
            if hash_files:
                content = Path(hash_files[0]).read_text(errors="replace")
                result["asrep"]["hashes"] = content.count("krb5asrep")
            # Vulnerable users from report
            report_files = sorted(glob.glob(os.path.join(asrep_dir, "asrep_*.txt")), reverse=True)
            for rf in report_files[:1]:
                content = Path(rf).read_text(errors="replace")
                for line in content.splitlines():
                    if "→" in line and "cuenta" not in line.lower() and "fail" in line.lower():
                        user = line.split("→")[-1].strip()
                        if user and " " not in user:
                            result["asrep"]["vulnerable_accounts"].append(user)

        # Kerberoasting
        kerb_dir = os.path.join(REPORTS_DIR, "kerberoast")
        if os.path.exists(kerb_dir):
            result["kerberoast"]["run"] = True
            cracked_files = sorted(glob.glob(os.path.join(kerb_dir, "kerberoast_cracked_*.txt")), reverse=True)
            if cracked_files:
                for line in Path(cracked_files[0]).read_text(errors="replace").splitlines():
                    if line.startswith("#") or ":" not in line:
                        continue
                    user, _, pwd = line.partition(":")
                    if user.strip():
                        result["kerberoast"]["cracked"].append({"user": user.strip(), "password": pwd.strip()})
            hash_files = sorted(glob.glob(os.path.join(kerb_dir, "kerberoast_hashes_*.txt")), reverse=True)
            if hash_files:
                content = Path(hash_files[0]).read_text(errors="replace")
                result["kerberoast"]["hashes"] = content.count("krb5tgs")

        return result

    def get_attack_results(self) -> dict:
        """Returns parsed attack module results."""
        attacks = self._parse_attack_results()
        total_cracked = len(attacks["asrep"]["cracked"]) + len(attacks["kerberoast"]["cracked"])
        return {
            "available": attacks["asrep"]["run"] or attacks["kerberoast"]["run"],
            "total_cracked": total_cracked,
            "asrep": attacks["asrep"],
            "kerberoast": attacks["kerberoast"],
        }
