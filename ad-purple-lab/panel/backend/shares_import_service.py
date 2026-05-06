"""
shares_import_service.py — Parses SMB share + NTFS permission CSV exports for security analysis.

Supported CSVs (auto-detected by headers):
  AD_Shares.csv    — Get-SmbShare output
  AD_ShareACL.csv  — Get-SmbShareAccess output (share-level ACLs)
  AD_NTFS.csv      — Get-Acl output (NTFS ACLs per share path)
"""
from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any

# ── Detection signatures ──────────────────────────────────────────────────────

_SHARES_SIG  = {"sharename", "path", "encryptdata"}
_SHARE_ALT   = {"name", "path", "description", "currentusers"}
_SHAREACL_SIG = {"sharename", "accountname", "accessright"}
_NTFS_SIG    = {"identityreference", "filesystemrights", "accesscontroltype"}

# Accounts/groups that are considered high-risk when they have broad access
_DANGEROUS_PRINCIPALS = {
    "everyone",
    "todos",
    "au",                          # Authenticated Users abbreviation
    "authenticated users",
    "usuarios autenticados",
    "anonymous logon",
    "acceso anónimo",
    "creator owner",
    "network",
    "interactive",
    "nt authority\\everyone",
    "nt authority\\authenticated users",
    "builtin\\users",
    "builtin\\everyone",
    "domain users",
    "usuarios del dominio",
}

_SENSITIVE_PATH_PATTERNS = re.compile(
    r"(password|passwd|secret|backup|bak|script|admin|finance|financ|nomina|"
    r"contabil|confidential|confiden|key|private|priv|clave|dato|sensib|human|"
    r"rrhh|hr|legal|audit|log|config|deploy|devops|prod|produc)",
    re.IGNORECASE,
)

_WRITE_RIGHTS = {"fullcontrol", "modify", "write", "change", "writedac", "writeowner",
                 "genericsall", "genericwrite", "takeownership", "changeaccess"}

_ADMIN_SHARES = {"admin$", "ipc$", "c$", "d$", "e$", "f$", "print$", "fax$", "sysvol", "netlogon"}


def _detect_csv_type(headers: list[str]) -> str:
    lower = {h.strip().lower() for h in headers}
    # ShareACL first (most specific)
    if _SHAREACL_SIG <= lower:
        return "share_acl"
    if _NTFS_SIG <= lower:
        return "ntfs"
    if _SHARES_SIG <= lower or (_SHARE_ALT <= lower and "path" in lower):
        return "shares"
    return "unknown"


def _parse_bool(val: str) -> bool:
    return val.strip().lower() in ("true", "1", "yes")


def _norm_principal(name: str) -> str:
    return name.strip().lower().removeprefix("nt authority\\").removeprefix("builtin\\")


def _is_dangerous(principal: str) -> bool:
    p = principal.strip().lower()
    for d in _DANGEROUS_PRINCIPALS:
        if d in p:
            return True
    return False


def _is_orphaned_sid(principal: str) -> bool:
    return bool(re.match(r"^s-1-5-21(-\d+){3,}-\d+$", principal.strip(), re.IGNORECASE))


def _has_write(rights: str) -> bool:
    r = rights.lower().replace(" ", "")
    return any(w in r for w in _WRITE_RIGHTS)


def _is_sensitive_path(path: str) -> bool:
    return bool(_SENSITIVE_PATH_PATTERNS.search(path))


def _is_root_path(path: str) -> bool:
    normalized = path.strip().replace("\\", "/")
    return bool(re.match(r"^[a-zA-Z]:/?$", normalized)) or normalized in ("/", "")


# ── Parsers ───────────────────────────────────────────────────────────────────

def _parse_shares(content: bytes) -> list[dict]:
    rows = []
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
    for row in reader:
        r = {k.strip(): v.strip() for k, v in row.items()}
        # Normalize: Get-SmbShare has 'Name', we alias to 'ShareName'
        name = r.get("Name") or r.get("ShareName") or r.get("name") or ""
        path = r.get("Path") or r.get("path") or ""
        rows.append({
            "name":         name,
            "path":         path,
            "description":  r.get("Description") or r.get("description") or "",
            "encrypt":      _parse_bool(r.get("EncryptData") or r.get("encryptdata") or ""),
            "caching":      r.get("CachingMode") or r.get("cachingmode") or "",
            "current_users": int(r.get("CurrentUsers") or r.get("currentusers") or "0"),
            "is_hidden":    name.endswith("$"),
            "is_admin":     name.lower() in _ADMIN_SHARES,
            "is_root_path": _is_root_path(path),
            "is_sensitive": _is_sensitive_path(name + " " + path),
        })
    return rows


def _parse_share_acl(content: bytes) -> list[dict]:
    rows = []
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
    for row in reader:
        r = {k.strip(): v.strip() for k, v in row.items()}
        share   = r.get("ShareName") or r.get("Name") or ""
        account = r.get("AccountName") or r.get("Account") or ""
        right   = r.get("AccessRight") or r.get("AccessControlType") or ""
        rows.append({
            "share":          share,
            "account":        account,
            "access_right":   right,
            "access_type":    r.get("AccessControlType") or "Allow",
            "is_deny":        (r.get("AccessControlType") or "").lower() == "deny",
            "is_dangerous":   _is_dangerous(account),
            "has_write":      _has_write(right),
            "is_orphaned_sid": _is_orphaned_sid(account),
        })
    return rows


def _parse_ntfs(content: bytes) -> list[dict]:
    rows = []
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
    for row in reader:
        r = {k.strip(): v.strip() for k, v in row.items()}
        identity = r.get("IdentityReference") or r.get("Identity") or ""
        rights   = r.get("FileSystemRights") or r.get("Rights") or ""
        rows.append({
            "share":          r.get("ShareName") or "",
            "path":           r.get("Path") or "",
            "identity":       identity,
            "rights":         rights,
            "access_type":    r.get("AccessControlType") or "Allow",
            "is_deny":        (r.get("AccessControlType") or "").lower() == "deny",
            "is_inherited":   _parse_bool(r.get("IsInherited") or ""),
            "inheritance":    r.get("InheritanceFlags") or "",
            "is_dangerous":   _is_dangerous(identity),
            "has_write":      _has_write(rights),
            "is_orphaned_sid": _is_orphaned_sid(identity),
            "is_sensitive":   _is_sensitive_path(r.get("Path") or ""),
        })
    return rows


# ── Security findings ─────────────────────────────────────────────────────────

_FID = 0

def _fid() -> str:
    global _FID
    _FID += 1
    return f"SHARE-{_FID:03d}"


def _reset_fid():
    global _FID
    _FID = 0


def _generate_findings(
    shares: list[dict],
    share_acls: list[dict],
    ntfs_rows: list[dict],
) -> list[dict]:
    _reset_fid()
    findings: list[dict] = []

    # Build quick lookup: share name → share info
    share_map = {s["name"].lower(): s for s in shares}

    # ── Share-level ACL findings ──────────────────────────────────────────────

    # F1 — Everyone/Anonymous with Full Control (share level)
    crit_acls = [
        a for a in share_acls
        if a["is_dangerous"] and a["has_write"] and not a["is_deny"]
    ]
    if crit_acls:
        accounts = sorted({a["account"] for a in crit_acls})
        shares_affected = sorted({a["share"] for a in crit_acls})
        findings.append({
            "id":       _fid(),
            "severity": "critical",
            "category": "Permisos de Carpetas",
            "title":    f"Acceso de escritura global en {len(shares_affected)} recurso(s) compartido(s)",
            "mitre":    "T1078 / T1083",
            "description": (
                f"Los siguientes grupos/cuentas con acceso irrestricto tienen permisos de escritura "
                f"o control total a nivel de compartición SMB: **{', '.join(accounts[:10])}**. "
                f"Recursos afectados: {', '.join(shares_affected[:10])}."
            ),
            "recommendation": (
                "Eliminar 'Everyone' y 'Authenticated Users' de ACLs de compartición. "
                "Usar grupos AD específicos. Aplicar principio de mínimo privilegio."
            ),
            "affected": shares_affected,
            "count": len(shares_affected),
        })

    # F2 — Unencrypted non-admin SMB shares
    unencrypted = [s for s in shares if not s["encrypt"] and not s["is_admin"]]
    if unencrypted:
        names = [s["name"] for s in unencrypted]
        findings.append({
            "id":       _fid(),
            "severity": "high",
            "category": "Configuración SMB",
            "title":    f"{len(unencrypted)} recurso(s) compartido(s) sin cifrado SMB",
            "mitre":    "T1021.002",
            "description": (
                f"Los siguientes recursos no tienen cifrado SMB activado, permitiendo "
                f"captura de tráfico en la red: **{', '.join(names[:15])}**."
            ),
            "recommendation": (
                "Activar EncryptData en cada recurso compartido: "
                "`Set-SmbShare -Name <share> -EncryptData $true`. "
                "O forzar cifrado global: `Set-SmbServerConfiguration -EncryptData $true`."
            ),
            "affected": names,
            "count": len(unencrypted),
        })

    # F3 — Shares exposed to large groups with read (info/medium depending on count)
    wide_read = [
        a for a in share_acls
        if a["is_dangerous"] and not a["has_write"] and not a["is_deny"]
    ]
    if wide_read:
        shares_aff = sorted({a["share"] for a in wide_read})
        findings.append({
            "id":       _fid(),
            "severity": "medium",
            "category": "Permisos de Carpetas",
            "title":    f"Lectura abierta a grupos globales en {len(shares_aff)} recurso(s)",
            "mitre":    "T1083",
            "description": (
                f"Grupos como 'Everyone' o 'Authenticated Users' tienen acceso de lectura "
                f"a los recursos: **{', '.join(shares_aff[:15])}**. "
                f"Esto permite enumeración masiva de información."
            ),
            "recommendation": (
                "Restringir lectura a grupos AD específicos. "
                "Activar Access-Based Enumeration (ABE) en todos los recursos."
            ),
            "affected": shares_aff,
            "count": len(shares_aff),
        })

    # F4 — Shares pointing to root drive paths
    root_shares = [s for s in shares if s["is_root_path"] and not s["is_admin"]]
    if root_shares:
        names = [f"{s['name']} → {s['path']}" for s in root_shares]
        findings.append({
            "id":       _fid(),
            "severity": "high",
            "category": "Configuración SMB",
            "title":    f"{len(root_shares)} recurso(s) apuntando a raíz de unidad",
            "mitre":    "T1083",
            "description": (
                f"Los siguientes recursos SMB exponen directorios raíz de unidad: "
                f"**{', '.join(names[:10])}**. "
                f"Esto puede exponer toda la estructura de archivos del servidor."
            ),
            "recommendation": (
                "Mover los recursos a subdirectorios específicos en vez de raíces de unidad. "
                "Revisar si la exposición es intencional o un error de configuración."
            ),
            "affected": [s["name"] for s in root_shares],
            "count": len(root_shares),
        })

    # F5 — Orphaned SIDs in share ACLs
    orphan_acl = [a for a in share_acls if a["is_orphaned_sid"]]
    if orphan_acl:
        sids = sorted({a["account"] for a in orphan_acl})
        shares_aff = sorted({a["share"] for a in orphan_acl})
        findings.append({
            "id":       _fid(),
            "severity": "medium",
            "category": "Gestión de Identidades",
            "title":    f"{len(sids)} SID(s) huérfano(s) en ACLs de recursos compartidos",
            "mitre":    "T1531",
            "description": (
                f"Se encontraron SIDs no resueltos (cuentas eliminadas) en ACLs de compartición SMB: "
                f"**{', '.join(sids[:5])}**. "
                f"Afectan a los recursos: {', '.join(shares_aff[:10])}."
            ),
            "recommendation": (
                "Eliminar los SIDs huérfanos de todas las ACLs. "
                "Usar `icacls` o herramientas de PowerShell para limpiar entradas no resueltas."
            ),
            "affected": shares_aff,
            "count": len(sids),
        })

    # ── NTFS ACL findings ─────────────────────────────────────────────────────

    if ntfs_rows:
        # F6 — Everyone/Anonymous with FullControl at NTFS level
        ntfs_crit = [
            n for n in ntfs_rows
            if n["is_dangerous"] and n["has_write"] and not n["is_deny"]
        ]
        if ntfs_crit:
            paths = sorted({n["path"] or n["share"] for n in ntfs_crit})
            accounts = sorted({n["identity"] for n in ntfs_crit})
            findings.append({
                "id":       _fid(),
                "severity": "critical",
                "category": "Permisos NTFS",
                "title":    f"Control total NTFS para grupos globales en {len(paths)} ruta(s)",
                "mitre":    "T1078 / T1222",
                "description": (
                    f"Permisos NTFS FullControl/Modify asignados a: **{', '.join(accounts[:8])}** "
                    f"en las rutas: **{', '.join(paths[:8])}**. "
                    f"Un atacante con acceso de red puede modificar o borrar datos."
                ),
                "recommendation": (
                    "Auditar y restringir permisos NTFS. Aplicar modelo de acceso por grupos AD. "
                    "Revisar herencia de permisos con `icacls /findsid Everyone /t /q`."
                ),
                "affected": paths,
                "count": len(paths),
            })

        # F7 — Sensitive paths with permissive access
        sensitive_write = [
            n for n in ntfs_rows
            if n["is_sensitive"] and n["has_write"] and not n["is_deny"] and not n["is_inherited"]
        ]
        if sensitive_write:
            paths = sorted({n["path"] or n["share"] for n in sensitive_write})
            findings.append({
                "id":       _fid(),
                "severity": "critical",
                "category": "Datos Sensibles",
                "title":    f"Rutas sensibles con permisos de escritura en {len(paths)} ubicación(es)",
                "mitre":    "T1083 / T1005",
                "description": (
                    f"Se detectaron rutas con nombres que sugieren datos sensibles "
                    f"(backup, passwords, scripts, RRHH, finance, etc.) con permisos de escritura directa: "
                    f"**{', '.join(paths[:8])}**."
                ),
                "recommendation": (
                    "Revisar el propósito de estas carpetas. Si contienen datos sensibles: "
                    "1) Restringir acceso a grupos mínimos necesarios. "
                    "2) Activar auditoría NTFS con Group Policy. "
                    "3) Cifrar contenido sensible."
                ),
                "affected": paths,
                "count": len(paths),
            })

        # F8 — Orphaned SIDs in NTFS ACLs
        ntfs_orphan = [n for n in ntfs_rows if n["is_orphaned_sid"]]
        if ntfs_orphan:
            paths = sorted({n["path"] or n["share"] for n in ntfs_orphan})
            sids  = sorted({n["identity"] for n in ntfs_orphan})
            findings.append({
                "id":       _fid(),
                "severity": "low",
                "category": "Gestión de Identidades",
                "title":    f"{len(sids)} SID(s) huérfano(s) en permisos NTFS",
                "mitre":    "T1531",
                "description": (
                    f"SIDs sin cuenta AD asociada en ACLs NTFS: **{', '.join(sids[:5])}**. "
                    f"Afectan a {len(paths)} ruta(s)."
                ),
                "recommendation": (
                    "Limpiar SIDs huérfanos: `icacls <path> /remove:g <SID> /t /c`. "
                    "Revisar periódicamente con scripts de auditoría de ACLs."
                ),
                "affected": paths,
                "count": len(sids),
            })

    # ── Share configuration findings ──────────────────────────────────────────

    # F9 — Non-admin hidden shares
    hidden_non_admin = [s for s in shares if s["is_hidden"] and not s["is_admin"]]
    if hidden_non_admin:
        names = [s["name"] for s in hidden_non_admin]
        findings.append({
            "id":       _fid(),
            "severity": "medium",
            "category": "Configuración SMB",
            "title":    f"{len(hidden_non_admin)} recurso(s) compartido(s) oculto(s) no administrativo(s)",
            "mitre":    "T1083",
            "description": (
                f"Recursos con nombre terminado en '$' que no son recursos administrativos estándar: "
                f"**{', '.join(names)}**. "
                f"Pueden ser usados para ocultar datos o acceso no documentado."
            ),
            "recommendation": (
                "Documentar y justificar cada recurso oculto no estándar. "
                "Si no tienen propósito legítimo, eliminarlos."
            ),
            "affected": names,
            "count": len(names),
        })

    # F10 — Shares without description
    no_desc = [s for s in shares if not s["description"] and not s["is_admin"]]
    if no_desc:
        names = [s["name"] for s in no_desc]
        findings.append({
            "id":       _fid(),
            "severity": "info",
            "category": "Documentación",
            "title":    f"{len(no_desc)} recurso(s) sin descripción",
            "mitre":    "N/A",
            "description": (
                f"Los siguientes recursos compartidos no tienen descripción: "
                f"**{', '.join(names[:20])}**. "
                f"Dificulta auditorías y gestión de acceso."
            ),
            "recommendation": (
                "Añadir descripción a todos los recursos compartidos indicando propósito y propietario: "
                "`Set-SmbShare -Name <share> -Description 'Propósito — Propietario'`."
            ),
            "affected": names,
            "count": len(names),
        })

    return findings


# ── Main service ──────────────────────────────────────────────────────────────

class SharesImportService:
    def __init__(self):
        self._last_result: dict | None = None

    def get_last_result(self) -> dict | None:
        return self._last_result

    def analyze(self, files: dict[str, bytes]) -> dict:
        shares:     list[dict] = []
        share_acls: list[dict] = []
        ntfs_rows:  list[dict] = []
        unknown:    list[str]  = []

        for fname, content in files.items():
            try:
                reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
                headers = reader.fieldnames or []
                csv_type = _detect_csv_type(list(headers))
            except Exception:
                csv_type = "unknown"

            if csv_type == "shares":
                shares = _parse_shares(content)
            elif csv_type == "share_acl":
                share_acls = _parse_share_acl(content)
            elif csv_type == "ntfs":
                ntfs_rows = _parse_ntfs(content)
            else:
                unknown.append(fname)

        findings = _generate_findings(shares, share_acls, ntfs_rows)

        sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

        # Risk score 0-100
        risk = min(100, sev_counts["critical"] * 25 + sev_counts["high"] * 10 +
                   sev_counts["medium"] * 4 + sev_counts["low"] * 1)

        # Top risky shares: those appearing in critical/high findings
        risky_share_names: set[str] = set()
        for f in findings:
            if f["severity"] in ("critical", "high"):
                risky_share_names.update(f.get("affected", []))

        result: dict[str, Any] = {
            "available":     True,
            "analyzed_at":   datetime.utcnow().isoformat() + "Z",
            "unknown_files": unknown,
            "stats": {
                "total_shares":    len(shares),
                "admin_shares":    sum(1 for s in shares if s["is_admin"]),
                "encrypted":       sum(1 for s in shares if s["encrypt"]),
                "unencrypted":     sum(1 for s in shares if not s["encrypt"] and not s["is_admin"]),
                "hidden_shares":   sum(1 for s in shares if s["is_hidden"] and not s["is_admin"]),
                "total_share_acl": len(share_acls),
                "total_ntfs_ace":  len(ntfs_rows),
                "risky_shares":    len(risky_share_names),
                "orphaned_sids":   len({a["account"] for a in share_acls if a["is_orphaned_sid"]}),
            },
            "severity_counts": sev_counts,
            "risk_score":      risk,
            "findings":        findings,
            "shares":          shares,
            "share_acls":      share_acls,
            "ntfs":            ntfs_rows,
        }

        self._last_result = result
        return result
