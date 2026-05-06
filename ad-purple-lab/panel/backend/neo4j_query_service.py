"""
neo4j_query_service.py — Pre-built Cypher query catalog for AD/BloodHound graph analysis.

Schema support:
  csv        — ADUser, ADGroup, ADComputer, ADOU  (rels: MEMBER_OF, IN_OU, CHILD_OF)
  bloodhound — User, Group, Computer, Domain       (rels: MemberOf, AdminTo, GenericAll, ...)
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# ── Connection config ─────────────────────────────────────────────────────────

_auth = os.environ.get("NEO4J_AUTH", "neo4j/ChangeThisNeo4jPass123!")
_u, _p = _auth.split("/", 1) if "/" in _auth else ("neo4j", _auth)

NEO4J_URI  = os.environ.get("NEO4J_BOLT_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", _u)
NEO4J_PASS = os.environ.get("NEO4J_PASS", _p)

# ── Query catalog ─────────────────────────────────────────────────────────────

def _p(**kw) -> dict:
    return {"required": False, **kw}

QUERY_CATALOG: dict[str, dict] = {

    # ── Reconocimiento ────────────────────────────────────────────────────────

    "user_by_sam": {
        "id":          "user_by_sam",
        "title":       "Buscar usuario por SAM",
        "description": "Busca un usuario específico por su SAM account name. Devuelve todas las propiedades del nodo.",
        "category":    "Reconocimiento",
        "risk":        "info",
        "schema":      "csv",
        "params": [
            _p(name="sam", label="SAM Account Name", placeholder="john.doe", required=True),
        ],
        "cypher": "MATCH (n:ADUser) WHERE n.sam = $sam RETURN n",
    },

    "all_active_users": {
        "id":          "all_active_users",
        "title":       "Usuarios activos",
        "description": "Lista completa de usuarios habilitados en el dominio (máx. 200).",
        "category":    "Reconocimiento",
        "risk":        "info",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (n:ADUser) WHERE n.disabled = false "
            "RETURN n.sam AS sam, n.display_name AS display_name, "
            "n.ou AS ou, n.last_logon AS last_logon "
            "ORDER BY n.sam LIMIT 200"
        ),
    },

    "user_graph": {
        "id":          "user_graph",
        "title":       "Grafo de usuario (grupos + OU)",
        "description": "Visualiza un usuario con sus grupos y Organizational Unit.",
        "category":    "Reconocimiento",
        "risk":        "info",
        "schema":      "csv",
        "params": [
            _p(name="sam", label="SAM Account Name", placeholder="john.doe", required=True),
        ],
        "cypher": (
            "MATCH (u:ADUser {sam: $sam}) "
            "OPTIONAL MATCH (u)-[r1:MEMBER_OF]->(g:ADGroup) "
            "OPTIONAL MATCH (u)-[r2:IN_OU]->(o:ADOU) "
            "RETURN u, r1, g, r2, o"
        ),
    },

    # ── Cuentas ───────────────────────────────────────────────────────────────

    "disabled_users": {
        "id":          "disabled_users",
        "title":       "Usuarios deshabilitados",
        "description": "Lista todos los usuarios con la cuenta deshabilitada en el dominio.",
        "category":    "Cuentas",
        "risk":        "low",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (n:ADUser) WHERE n.disabled = true "
            "RETURN n.sam AS sam, n.display_name AS display_name, n.ou AS ou "
            "ORDER BY n.sam"
        ),
    },

    "recent_logons": {
        "id":          "recent_logons",
        "title":       "Accesos recientes",
        "description": "Usuarios activos que han iniciado sesión recientemente.",
        "category":    "Cuentas",
        "risk":        "medium",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (n:ADUser) WHERE n.disabled = false "
            "AND n.last_logon IS NOT NULL AND n.last_logon <> '' "
            "RETURN n.sam AS sam, n.display_name AS display_name, "
            "n.last_logon AS last_logon, n.ou AS ou "
            "ORDER BY n.last_logon DESC LIMIT 50"
        ),
    },

    # ── Vulnerabilidades ──────────────────────────────────────────────────────

    "no_password_users": {
        "id":          "no_password_users",
        "title":       "Sin contraseña requerida (PASSWD_NOTREQD)",
        "description": "Cuentas activas con el flag PASSWD_NOTREQD activado. Vulnerabilidad crítica — la cuenta puede no tener contraseña.",
        "category":    "Vulnerabilidades",
        "risk":        "critical",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (n:ADUser) WHERE n.pwd_not_req = true AND n.disabled = false "
            "RETURN n.sam AS sam, n.display_name AS display_name, n.ou AS ou"
        ),
    },

    "legacy_os": {
        "id":          "legacy_os",
        "title":       "Sistemas operativos EOL",
        "description": "Computadoras con sistemas operativos fuera de soporte (XP, Vista, 7, 2003, 2008). Alto riesgo de explotación.",
        "category":    "Vulnerabilidades",
        "risk":        "critical",
        "schema":      "csv",
        "params": [],
        "cypher": (
            'MATCH (n:ADComputer) WHERE n.os_risk IN ["critical", "high"] '
            "RETURN n.name AS name, n.os AS os, n.os_ver AS version, "
            "n.ou AS ou, n.is_dc AS is_dc ORDER BY n.os"
        ),
    },

    # ── Kerberos ──────────────────────────────────────────────────────────────

    "kerberoastable": {
        "id":          "kerberoastable",
        "title":       "Kerberoasteables (SPN)",
        "description": "Usuarios con Service Principal Names registrados. Susceptibles a Kerberoasting (T1558.003) — permite crackear el hash TGS offline.",
        "category":    "Kerberos",
        "risk":        "high",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (n:ADUser) WHERE n.spn_count > 0 AND n.disabled = false "
            "RETURN n.sam AS sam, n.display_name AS display_name, "
            "n.spn_count AS spn_count, n.ou AS ou "
            "ORDER BY n.spn_count DESC"
        ),
    },

    "asrep_roastable": {
        "id":          "asrep_roastable",
        "title":       "AS-REP Roastables (no pre-auth)",
        "description": "Usuarios sin pre-autenticación Kerberos requerida. Susceptibles a AS-REP Roasting (T1558.004) — hash obtenible sin credenciales.",
        "category":    "Kerberos",
        "risk":        "high",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (n:ADUser) WHERE n.no_preauth = true AND n.disabled = false "
            "RETURN n.sam AS sam, n.display_name AS display_name, n.ou AS ou"
        ),
    },

    # ── Privilegios ───────────────────────────────────────────────────────────

    "domain_admins": {
        "id":          "domain_admins",
        "title":       "Domain Admins",
        "description": "Miembros del grupo Domain Admins. Alerta crítica si hay cuentas de servicio o inesperadas.",
        "category":    "Privilegios",
        "risk":        "high",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (u:ADUser)-[:MEMBER_OF]->(g:ADGroup) "
            'WHERE g.name = "Domain Admins" OR g.sam = "Domain Admins" '
            "RETURN u.sam AS sam, u.display_name AS display_name, "
            "u.disabled AS disabled, u.last_logon AS last_logon"
        ),
    },

    "privileged_groups_graph": {
        "id":          "privileged_groups_graph",
        "title":       "Grafo — grupos privilegiados",
        "description": "Visualización de usuarios activos en grupos de alto privilegio (Domain Admins, Enterprise Admins, Administrators, etc.).",
        "category":    "Privilegios",
        "risk":        "high",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (u:ADUser)-[r:MEMBER_OF]->(g:ADGroup) "
            'WHERE g.name IN ["Domain Admins","Enterprise Admins","Schema Admins",'
            '"Administrators","Backup Operators","Account Operators","Print Operators"] '
            "AND u.disabled = false "
            "RETURN u, r, g"
        ),
    },

    # ── Grupos ────────────────────────────────────────────────────────────────

    "group_members": {
        "id":          "group_members",
        "title":       "Miembros de un grupo",
        "description": "Lista todos los usuarios que pertenecen a un grupo AD específico.",
        "category":    "Grupos",
        "risk":        "info",
        "schema":      "csv",
        "params": [
            _p(name="group", label="Nombre del grupo", placeholder="Domain Admins", required=True),
        ],
        "cypher": (
            "MATCH (u:ADUser)-[:MEMBER_OF]->(g:ADGroup) "
            "WHERE g.name = $group OR g.sam = $group "
            "RETURN u.sam AS sam, u.display_name AS display_name, "
            "u.ou AS ou, u.disabled AS disabled"
        ),
    },

    "group_graph": {
        "id":          "group_graph",
        "title":       "Grafo de grupo",
        "description": "Visualización de un grupo con todos sus miembros.",
        "category":    "Grupos",
        "risk":        "info",
        "schema":      "csv",
        "params": [
            _p(name="group", label="Nombre del grupo", placeholder="Domain Admins", required=True),
        ],
        "cypher": (
            "MATCH (u:ADUser)-[r:MEMBER_OF]->(g:ADGroup) "
            "WHERE g.name = $group OR g.sam = $group "
            "RETURN u, r, g"
        ),
    },

    # ── ACL / Escalada ────────────────────────────────────────────────────────

    "dangerous_acls": {
        "id":          "dangerous_acls",
        "title":       "Permisos peligrosos (ACL Abuse)",
        "description": "Entidades con GenericAll, GenericWrite, WriteDacl, WriteOwner o AllExtendedRights. Requiere datos BloodHound.",
        "category":    "ACL / Escalada",
        "risk":        "critical",
        "schema":      "bloodhound",
        "params": [],
        "cypher": (
            "MATCH (n)-[r]->(m) "
            'WHERE type(r) IN ["GenericAll","GenericWrite","WriteDacl","WriteOwner","AllExtendedRights"] '
            "RETURN n, r, m LIMIT 50"
        ),
    },

    "path_to_da": {
        "id":          "path_to_da",
        "title":       "Caminos a Domain Admin (shortestPath)",
        "description": "Rutas más cortas hacia el grupo Domain Admins desde cualquier usuario. Requiere datos BloodHound.",
        "category":    "ACL / Escalada",
        "risk":        "critical",
        "schema":      "bloodhound",
        "params": [],
        "cypher": (
            "MATCH p=shortestPath((n:User)-[*1..10]->(m:Group)) "
            'WHERE m.name CONTAINS "DOMAIN ADMINS" '
            "RETURN p LIMIT 10"
        ),
    },

    "admin_to": {
        "id":          "admin_to",
        "title":       "AdminTo — acceso admin a equipos",
        "description": "Usuarios o grupos con acceso de administrador local a computadoras. Requiere datos BloodHound.",
        "category":    "ACL / Escalada",
        "risk":        "high",
        "schema":      "bloodhound",
        "params": [],
        "cypher": "MATCH (u)-[r:AdminTo]->(c) RETURN u, r, c LIMIT 50",
    },

    "has_session": {
        "id":          "has_session",
        "title":       "HasSession — sesiones activas",
        "description": "Usuarios con sesiones activas en computadoras del dominio. Requiere datos BloodHound.",
        "category":    "ACL / Escalada",
        "risk":        "medium",
        "schema":      "bloodhound",
        "params": [],
        "cypher": "MATCH (c)-[r:HasSession]->(u) RETURN c, r, u LIMIT 50",
    },

    # ── OUs ───────────────────────────────────────────────────────────────────

    "ou_control": {
        "id":          "ou_control",
        "title":       "Control sobre OUs",
        "description": "Entidades con cualquier relación sobre Organizational Units (permisos, herencia, etc.).",
        "category":    "OUs",
        "risk":        "high",
        "schema":      "csv",
        "params": [],
        "cypher": "MATCH (n)-[r]->(o:ADOU) RETURN n, type(r) AS rel_type, o LIMIT 50",
    },

    # ── Inventario ────────────────────────────────────────────────────────────

    "computers_by_os": {
        "id":          "computers_by_os",
        "title":       "Equipos por sistema operativo",
        "description": "Inventario de computadoras agrupado por OS y versión.",
        "category":    "Inventario",
        "risk":        "info",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (n:ADComputer) "
            "RETURN n.os AS os, n.os_ver AS version, count(*) AS count, "
            "collect(n.name)[..5] AS examples "
            "ORDER BY count DESC"
        ),
    },

    "all_groups": {
        "id":          "all_groups",
        "title":       "Todos los grupos",
        "description": "Lista completa de grupos AD con conteo de miembros.",
        "category":    "Inventario",
        "risk":        "info",
        "schema":      "csv",
        "params": [],
        "cypher": (
            "MATCH (g:ADGroup) "
            "RETURN g.name AS name, g.sam AS sam, g.scope AS scope, "
            "g.member_count AS member_count, g.description AS description "
            "ORDER BY g.member_count DESC"
        ),
    },

    "ou_tree": {
        "id":          "ou_tree",
        "title":       "Árbol de OUs (grafo)",
        "description": "Visualización de la jerarquía de Organizational Units del dominio.",
        "category":    "Inventario",
        "risk":        "info",
        "schema":      "csv",
        "params": [],
        "cypher": "MATCH (o:ADOU)-[r:CHILD_OF]->(p:ADOU) RETURN o, r, p LIMIT 80",
    },

    # ── NTFS / File Server ────────────────────────────────────────────────────

    "ntfs_fullcontrol_users": {
        "id":          "ntfs_fullcontrol_users",
        "title":       "Usuarios con FullControl/Modify en carpetas",
        "description": "Usuarios AD con derechos de escritura completa o modificación en carpetas del servidor de archivos.",
        "category":    "NTFS / File Server",
        "risk":        "critical",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (u:ADUser)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE a.rights CONTAINS 'FullControl' OR a.rights CONTAINS 'Modify' "
            "RETURN u.sam AS sam, u.disabled AS disabled, u.pwd_not_req AS pwd_not_req, "
            "f.path AS folder, a.rights AS rights, a.inherited AS inherited, a.via AS via "
            "ORDER BY u.sam LIMIT 200"
        ),
    },

    "ntfs_attack_path": {
        "id":          "ntfs_attack_path",
        "title":       "Camino de ataque: usuario comprometible → carpeta crítica",
        "description": "Usuarios con flags de riesgo AD (AS-REP, pwd_not_req) que tienen FullControl/Modify sobre carpetas. Combinación de ataque Kerberos + File Server.",
        "category":    "NTFS / File Server",
        "risk":        "critical",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (u:ADUser)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE (u.no_preauth = true OR u.pwd_not_req = true) "
            "AND (a.rights CONTAINS 'FullControl' OR a.rights CONTAINS 'Modify') "
            "RETURN u.sam AS sam, u.no_preauth AS asrep, u.pwd_not_req AS no_pwd, "
            "f.path AS folder, a.rights AS rights "
            "ORDER BY u.sam LIMIT 100"
        ),
    },

    "ntfs_vuln_users_access": {
        "id":          "ntfs_vuln_users_access",
        "title":       "Usuarios vulnerables con acceso a carpetas",
        "description": "Cuentas con flags de riesgo AD (pwd_not_req, AS-REP, no_expire) que tienen ANY acceso a carpetas del File Server.",
        "category":    "NTFS / File Server",
        "risk":        "critical",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (u:ADUser)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE u.pwd_not_req = true OR u.no_preauth = true OR u.no_expire = true "
            "RETURN u.sam AS sam, u.pwd_not_req AS pwd_not_req, u.no_preauth AS asrep, "
            "u.no_expire AS no_expire, f.path AS folder, a.rights AS rights "
            "ORDER BY u.sam LIMIT 200"
        ),
    },

    "ntfs_disabled_with_access": {
        "id":          "ntfs_disabled_with_access",
        "title":       "Cuentas deshabilitadas con acceso a carpetas",
        "description": "Cuentas AD deshabilitadas que aún conservan permisos en el servidor de archivos. Deben eliminarse tras baja.",
        "category":    "NTFS / File Server",
        "risk":        "high",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (u:ADUser {disabled: true})-[a:HAS_ACCESS]->(f:Folder) "
            "RETURN u.sam AS sam, f.path AS folder, a.rights AS rights, a.inherited AS inherited "
            "ORDER BY u.sam LIMIT 200"
        ),
    },

    "ntfs_sensitive_folders": {
        "id":          "ntfs_sensitive_folders",
        "title":       "Acceso a carpetas con nombres sensibles",
        "description": "Usuarios con acceso a carpetas cuyo nombre sugiere contenido sensible: backup, finance, scripts, passwords, RRHH, nomina, legal.",
        "category":    "NTFS / File Server",
        "risk":        "high",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (u:ADUser)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE f.path =~ '(?i).*(backup|finance|script|password|passwd|rrhh|hr|legal|"
            "secret|confiden|nomina|salary|audit|deploy|devops|admin|clave|dato).*' "
            "RETURN u.sam AS sam, f.path AS folder, a.rights AS rights, a.inherited AS inherited "
            "ORDER BY f.path LIMIT 200"
        ),
    },

    "ntfs_groups_wide_access": {
        "id":          "ntfs_groups_wide_access",
        "title":       "Grupos AD con mayor radio de acceso en File Server",
        "description": "Grupos con acceso a múltiples carpetas. Un compromiso del grupo implica acceso masivo.",
        "category":    "NTFS / File Server",
        "risk":        "high",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (g:ADGroup)-[a:HAS_ACCESS]->(f:Folder) "
            "WITH g, count(f) AS folder_count, collect(f.path)[..5] AS samples "
            "WHERE folder_count > 1 "
            "RETURN g.sam AS group_sam, g.name AS group_name, g.member_count AS members, "
            "folder_count, samples "
            "ORDER BY folder_count DESC LIMIT 50"
        ),
    },

    "ntfs_direct_permissions": {
        "id":          "ntfs_direct_permissions",
        "title":       "Permisos directos (no heredados)",
        "description": "Accesos asignados directamente a usuarios/grupos sin herencia de directorio padre. Requieren revisión manual especial.",
        "category":    "NTFS / File Server",
        "risk":        "medium",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (u:ADUser)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE a.inherited = 'False' OR a.inherited = 'false' OR a.inherited = false "
            "RETURN u.sam AS sam, f.path AS folder, a.rights AS rights "
            "ORDER BY f.path LIMIT 200"
        ),
    },

    "ntfs_user_all_access": {
        "id":          "ntfs_user_all_access",
        "title":       "Todas las carpetas accesibles por un usuario",
        "description": "Lista completa de carpetas del File Server a las que tiene acceso un usuario específico (directo o por grupo).",
        "category":    "NTFS / File Server",
        "risk":        "info",
        "schema":      "ntfs",
        "params": [
            _p(name="sam", label="SAM Account Name", placeholder="john.doe", required=True),
        ],
        "cypher": (
            "MATCH (u:ADUser {sam: $sam})-[a:HAS_ACCESS]->(f:Folder) "
            "RETURN f.path AS folder, a.rights AS rights, a.inherited AS inherited, a.via AS via "
            "ORDER BY f.path"
        ),
    },

    "ntfs_folder_users": {
        "id":          "ntfs_folder_users",
        "title":       "Usuarios con acceso a una carpeta (búsqueda por ruta)",
        "description": "Todos los usuarios con acceso a una ruta específica o que contenga el término buscado.",
        "category":    "NTFS / File Server",
        "risk":        "info",
        "schema":      "ntfs",
        "params": [
            _p(name="path", label="Ruta o nombre de carpeta (parcial)", placeholder="Finance", required=True),
        ],
        "cypher": (
            "MATCH (u:ADUser)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE f.path CONTAINS $path "
            "RETURN u.sam AS sam, f.path AS folder, a.rights AS rights, a.via AS via "
            "ORDER BY u.sam LIMIT 200"
        ),
    },

    "ntfs_graph_user": {
        "id":          "ntfs_graph_user",
        "title":       "Grafo de acceso de un usuario (carpetas + grupos AD)",
        "description": "Visualización del camino de acceso de un usuario: grupos AD a los que pertenece y carpetas del File Server a las que tiene acceso.",
        "category":    "NTFS / File Server",
        "risk":        "info",
        "schema":      "ntfs",
        "params": [
            _p(name="sam", label="SAM Account Name", placeholder="john.doe", required=True),
        ],
        "cypher": (
            "MATCH (u:ADUser {sam: $sam}) "
            "OPTIONAL MATCH (u)-[r1:HAS_ACCESS]->(f:Folder) "
            "OPTIONAL MATCH (u)-[r2:MEMBER_OF]->(g:ADGroup)-[r3:HAS_ACCESS]->(f2:Folder) "
            "RETURN u, r1, f, r2, g, r3, f2 LIMIT 100"
        ),
    },

    "ntfs_folder_graph": {
        "id":          "ntfs_folder_graph",
        "title":       "Grafo de usuarios para una carpeta",
        "description": "Visualización de todos los usuarios y grupos que tienen acceso a una carpeta específica.",
        "category":    "NTFS / File Server",
        "risk":        "info",
        "schema":      "ntfs",
        "params": [
            _p(name="path", label="Ruta de carpeta (parcial)", placeholder="Finance", required=True),
        ],
        "cypher": (
            "MATCH (n)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE f.path CONTAINS $path "
            "RETURN n, a, f LIMIT 80"
        ),
    },

    "ntfs_lateral_movement": {
        "id":          "ntfs_lateral_movement",
        "title":       "Escalamiento lateral: usuario → grupo → carpeta crítica",
        "description": "Detecta cadenas donde un usuario pertenece a un grupo que tiene FullControl en carpetas, ampliando el radio de impacto si el usuario es comprometido.",
        "category":    "NTFS / File Server",
        "risk":        "critical",
        "schema":      "ntfs",
        "params":      [],
        "cypher": (
            "MATCH (u:ADUser)-[:MEMBER_OF]->(g:ADGroup)-[a:HAS_ACCESS]->(f:Folder) "
            "WHERE a.rights CONTAINS 'FullControl' OR a.rights CONTAINS 'Modify' "
            "RETURN u.sam AS sam, g.sam AS via_group, f.path AS folder, a.rights AS rights "
            "ORDER BY u.sam LIMIT 100"
        ),
    },
}


# ── Serialization helpers ─────────────────────────────────────────────────────

def _node_title(node) -> str:
    props = dict(node)
    for key in ("sam", "name", "display_name"):
        if props.get(key):
            return str(props[key])
    return next(iter(node.labels), "node")


def _serialize_primitive(val: Any) -> Any:
    if val is None or isinstance(val, (bool, int, float, str)):
        return val
    if isinstance(val, list):
        return [_serialize_primitive(v) for v in val]
    return str(val)


def _extract_graph(records, graph_nodes: dict, graph_edges: list):
    """Walk all record values and pull out Node/Relationship/Path objects."""
    try:
        from neo4j.graph import Node, Relationship, Path
    except ImportError:
        return

    seen_edges: set = set()

    def _add_node(node):
        nid = node.element_id
        if nid not in graph_nodes:
            graph_nodes[nid] = {
                "id":    nid,
                "label": next(iter(node.labels), "Unknown"),
                "title": _node_title(node),
                "props": {k: _serialize_primitive(v) for k, v in dict(node).items()},
            }

    def _add_rel(rel):
        eid = rel.element_id
        if eid in seen_edges:
            return
        seen_edges.add(eid)
        _add_node(rel.start_node)
        _add_node(rel.end_node)
        graph_edges.append({
            "id":   eid,
            "from": rel.start_node.element_id,
            "to":   rel.end_node.element_id,
            "type": rel.type,
        })

    for rec in records:
        for val in rec.values():
            if val is None:
                continue
            if isinstance(val, Node):
                _add_node(val)
            elif isinstance(val, Relationship):
                _add_rel(val)
            elif isinstance(val, Path):
                for node in val.nodes:
                    _add_node(node)
                for rel in val.relationships:
                    _add_rel(rel)


def _serialize_row(rec) -> dict:
    """Flatten a record to primitive values for table display."""
    try:
        from neo4j.graph import Node, Relationship, Path
    except ImportError:
        Node = Relationship = Path = None

    row = {}
    for key, val in rec.items():
        if val is None:
            row[key] = ""
        elif Node and isinstance(val, Node):
            props = dict(val)
            name  = props.get("sam") or props.get("name") or props.get("display_name", "?")
            label = next(iter(val.labels), "Node")
            row[key] = f"[{label}: {name}]"
        elif Relationship and isinstance(val, Relationship):
            row[key] = val.type
        elif Path and isinstance(val, Path):
            row[key] = " → ".join(_node_title(n) for n in val.nodes)
        elif isinstance(val, list):
            row[key] = ", ".join(str(v) for v in val[:5])
            if len(val) > 5:
                row[key] += f" (+{len(val)-5})"
        else:
            row[key] = _serialize_primitive(val)
    return row


# ── Service ───────────────────────────────────────────────────────────────────

class Neo4jQueryService:

    def __init__(self):
        self._driver = None
        self._log: list[dict] = []

    def _drv(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS)
            )
        return self._driver

    # ── Catalog ───────────────────────────────────────────────────────────────

    def get_catalog(self) -> list[dict]:
        return [
            {
                "id":          q["id"],
                "title":       q["title"],
                "description": q["description"],
                "category":    q["category"],
                "risk":        q["risk"],
                "schema":      q.get("schema", "csv"),
                "params":      q.get("params", []),
                "cypher":      q["cypher"],
            }
            for q in QUERY_CATALOG.values()
        ]

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        STAT_QUERIES = {
            "total_users":     "MATCH (n:ADUser) RETURN count(n) AS c",
            "disabled_users":  "MATCH (n:ADUser) WHERE n.disabled = true RETURN count(n) AS c",
            "no_pwd_users":    "MATCH (n:ADUser) WHERE n.pwd_not_req = true AND n.disabled = false RETURN count(n) AS c",
            "kerberoastable":  "MATCH (n:ADUser) WHERE n.spn_count > 0 AND n.disabled = false RETURN count(n) AS c",
            "asrep_roast":     "MATCH (n:ADUser) WHERE n.no_preauth = true AND n.disabled = false RETURN count(n) AS c",
            "total_computers": "MATCH (n:ADComputer) RETURN count(n) AS c",
            "total_groups":    "MATCH (n:ADGroup) RETURN count(n) AS c",
            "legacy_os":       'MATCH (n:ADComputer) WHERE n.os_risk IN ["critical","high"] RETURN count(n) AS c',
        }
        try:
            drv   = self._drv()
            stats = {}
            with drv.session() as s:
                for key, cypher in STAT_QUERIES.items():
                    try:
                        stats[key] = s.run(cypher).single()["c"]
                    except Exception:
                        stats[key] = None
            return {"connected": True, "stats": stats}
        except Exception as exc:
            return {"connected": False, "error": str(exc), "stats": {}}

    # ── Execute ───────────────────────────────────────────────────────────────

    def execute(self, query_id: str, params: dict[str, str]) -> dict:
        if query_id not in QUERY_CATALOG:
            raise ValueError(f"Query desconocida: '{query_id}'")

        entry = QUERY_CATALOG[query_id]

        for p in entry.get("params", []):
            if p.get("required") and not str(params.get(p["name"], "")).strip():
                raise ValueError(f"Parámetro requerido faltante: '{p['name']}'")

        # Coerce string params to typed values
        typed: dict[str, Any] = {}
        for k, v in params.items():
            s = str(v).strip()
            if s == "true":    typed[k] = True
            elif s == "false": typed[k] = False
            else:
                try:    typed[k] = int(s)
                except ValueError:
                    try:    typed[k] = float(s)
                    except ValueError: typed[k] = s

        self._append_log(query_id, typed)
        logger.info("neo4j execute %s params=%s", query_id, typed)

        try:
            with self._drv().session() as s:
                result  = s.run(entry["cypher"], typed)
                records = list(result)

            graph_nodes: dict[str, dict] = {}
            graph_edges: list[dict]      = []
            _extract_graph(records, graph_nodes, graph_edges)

            rows    = [_serialize_row(r) for r in records]
            columns = list(rows[0].keys()) if rows else []

            return {
                "query_id":  query_id,
                "title":     entry["title"],
                "rows":      rows,
                "columns":   columns,
                "graph": {
                    "nodes": list(graph_nodes.values()),
                    "edges": graph_edges,
                },
                "count":     len(rows),
                "has_graph": len(graph_nodes) > 0,
            }
        except Exception as exc:
            logger.error("neo4j query %s failed: %s", query_id, exc)
            raise RuntimeError(f"Error ejecutando '{query_id}': {exc}")

    # ── Query log ─────────────────────────────────────────────────────────────

    def _append_log(self, query_id: str, params: dict):
        self._log.append({
            "query_id":  query_id,
            "params":    params,
            "timestamp": datetime.utcnow().isoformat(),
        })
        if len(self._log) > 1000:
            self._log = self._log[-500:]

    def get_log(self) -> list[dict]:
        return list(reversed(self._log[-100:]))
