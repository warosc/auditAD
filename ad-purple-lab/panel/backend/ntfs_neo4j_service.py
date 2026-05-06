"""
ntfs_neo4j_service.py — Import NTFS ACL data into Neo4j as Folder nodes + HAS_ACCESS relationships.

Supported CSV formats (auto-detected by headers):
  NTFS_Permissions.csv    — Folder, Identity, Rights, Type, Inherited
  NTFS_User_Effective.csv — User, Folder, Rights, Type, Inherited[, Via]

New labels:  Folder
New rels:    (:ADUser)-[:HAS_ACCESS]->(Folder)
             (:ADGroup)-[:HAS_ACCESS]->(Folder)
"""
from __future__ import annotations

import csv
import io
import os
import re
from typing import Any

_auth = os.environ.get("NEO4J_AUTH", "neo4j/ChangeThisNeo4jPass123!")
_u, _p = _auth.split("/", 1) if "/" in _auth else ("neo4j", _auth)

NEO4J_URI  = os.environ.get("NEO4J_BOLT_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", _u)
NEO4J_PASS = os.environ.get("NEO4J_PASS", _p)

BATCH = 500


def _detect_csv_type(headers: list[str]) -> str:
    lower = {h.strip().lower() for h in headers}
    if "user" in lower and "folder" in lower and "rights" in lower:
        return "effective"
    if "identity" in lower and "folder" in lower and "rights" in lower:
        return "raw"
    return "unknown"


def _strip_domain(identity: str) -> str:
    """Strip domain prefix: DOMAIN\\name → name, UPN user@domain → user."""
    if "\\" in identity:
        return identity.split("\\", 1)[1].strip()
    if "@" in identity:
        return identity.split("@")[0].strip()
    return identity.strip()


def _normalize_path(path: str) -> str:
    return path.strip().rstrip("\\").rstrip("/")


def _parse_effective(content: bytes) -> list[dict]:
    rows = []
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
    for row in reader:
        r = {k.strip(): v.strip() for k, v in row.items()}
        user   = _strip_domain(r.get("User") or "").lower()
        folder = _normalize_path(r.get("Folder") or "")
        rights = r.get("Rights") or r.get("rights") or ""
        if not user or not folder:
            continue
        rows.append({
            "user":      user,
            "folder":    folder,
            "rights":    rights,
            "inherited": r.get("Inherited") or r.get("inherited") or "",
            "via":       _strip_domain(r.get("Via") or ""),
            "acc_type":  r.get("Type") or r.get("type") or "Allow",
        })
    return rows


def _parse_raw(content: bytes) -> list[dict]:
    rows = []
    reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
    for row in reader:
        r = {k.strip(): v.strip() for k, v in row.items()}
        identity = _strip_domain(r.get("Identity") or r.get("identity") or "").lower()
        folder   = _normalize_path(r.get("Folder") or "")
        rights   = r.get("Rights") or r.get("rights") or ""
        if not identity or not folder:
            continue
        rows.append({
            "identity":  identity,
            "folder":    folder,
            "rights":    rights,
            "inherited": r.get("Inherited") or r.get("inherited") or "",
            "acc_type":  r.get("Type") or r.get("type") or "Allow",
        })
    return rows


class NtfsNeo4jService:

    def __init__(self):
        self._driver = None

    def _drv(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        return self._driver

    def _batch(self, session, cypher: str, rows: list[dict]) -> int:
        total = 0
        for i in range(0, len(rows), BATCH):
            session.run(cypher, rows=rows[i:i + BATCH]).consume()
            total += len(rows[i:i + BATCH])
        return total

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        try:
            with self._drv().session() as s:
                folders    = s.run("MATCH (f:Folder) RETURN count(f) AS c").single()["c"]
                has_access = s.run("MATCH ()-[r:HAS_ACCESS]->() RETURN count(r) AS c").single()["c"]
            return {"connected": True, "folders": folders, "has_access_rels": has_access}
        except Exception as exc:
            return {"connected": False, "error": str(exc), "folders": 0, "has_access_rels": 0}

    # ── Purge ─────────────────────────────────────────────────────────────────

    def purge(self) -> dict[str, int]:
        with self._drv().session() as s:
            rels = s.run("MATCH ()-[r:HAS_ACCESS]->() DELETE r RETURN count(*) AS c").single()["c"]
            folders = s.run("MATCH (f:Folder) DETACH DELETE f RETURN count(*) AS c").single()["c"]
        return {"folders_deleted": folders, "rels_deleted": rels}

    # ── Indexes ───────────────────────────────────────────────────────────────

    def _ensure_indexes(self, session):
        indexes = [
            "CREATE INDEX ntfs_folder_path IF NOT EXISTS FOR (f:Folder) ON (f.path)",
            "CREATE INDEX ntfs_folder_name IF NOT EXISTS FOR (f:Folder) ON (f.name)",
        ]
        for idx in indexes:
            try:
                session.run(idx).consume()
            except Exception:
                pass

    # ── Import from NTFS_User_Effective.csv ───────────────────────────────────

    def _import_effective(self, session, rows: list[dict]) -> dict[str, int]:
        # Create Folder nodes
        folder_set = list({r["folder"] for r in rows if r["folder"]})
        folder_rows = [
            {
                "path": p,
                "name": p.split("\\")[-1].split("/")[-1],
                "depth": len(re.findall(r"[/\\]", p)),
            }
            for p in folder_set
        ]
        self._batch(session,
            "UNWIND $rows AS r MERGE (f:Folder {path: r.path}) SET f.name = r.name, f.depth = r.depth",
            folder_rows,
        )

        # HAS_ACCESS: user → folder  (MERGE ADUser so we don't require AD import first)
        self._batch(session,
            """
            UNWIND $rows AS r
            MERGE (u:ADUser {sam: r.user})
            MERGE (f:Folder {path: r.folder})
            MERGE (u)-[rel:HAS_ACCESS]->(f)
            SET rel.rights    = r.rights,
                rel.inherited = r.inherited,
                rel.via       = r.via,
                rel.acc_type  = r.acc_type
            """,
            rows,
        )
        return {"folders": len(folder_set), "relationships": len(rows)}

    # ── Import from NTFS_Permissions.csv ──────────────────────────────────────

    def _import_raw(self, session, rows: list[dict]) -> dict[str, int]:
        folder_set = list({r["folder"] for r in rows if r["folder"]})
        folder_rows = [
            {
                "path": p,
                "name": p.split("\\")[-1].split("/")[-1],
                "depth": len(re.findall(r"[/\\]", p)),
            }
            for p in folder_set
        ]
        self._batch(session,
            "UNWIND $rows AS r MERGE (f:Folder {path: r.path}) SET f.name = r.name, f.depth = r.depth",
            folder_rows,
        )

        # Try matching against existing ADUser nodes first
        user_rels = self._batch(session,
            """
            UNWIND $rows AS r
            MATCH (u:ADUser) WHERE u.sam = r.identity OR u.upn STARTS WITH r.identity
            MERGE (f:Folder {path: r.folder})
            MERGE (u)-[rel:HAS_ACCESS]->(f)
            SET rel.rights = r.rights, rel.inherited = r.inherited, rel.acc_type = r.acc_type
            """,
            rows,
        )

        # Then try ADGroup nodes
        grp_rels = self._batch(session,
            """
            UNWIND $rows AS r
            MATCH (g:ADGroup) WHERE g.sam = r.identity OR g.name = r.identity
            MERGE (f:Folder {path: r.folder})
            MERGE (g)-[rel:HAS_ACCESS]->(f)
            SET rel.rights = r.rights, rel.inherited = r.inherited, rel.acc_type = r.acc_type
            """,
            rows,
        )
        return {"folders": len(folder_set), "relationships": user_rels + grp_rels}

    # ── Public import entry-point ─────────────────────────────────────────────

    def import_csv(self, filename: str, content: bytes) -> dict[str, Any]:
        reader = csv.DictReader(io.StringIO(content.decode("utf-8-sig", errors="replace")))
        headers = list(reader.fieldnames or [])
        csv_type = _detect_csv_type(headers)

        if csv_type == "unknown":
            return {
                "status":  "error",
                "message": f"Formato CSV no reconocido en '{filename}'. "
                           f"Cabeceras detectadas: {headers[:8]}. "
                           f"Esperado: User/Folder/Rights o Identity/Folder/Rights.",
            }

        if csv_type == "effective":
            rows = _parse_effective(content)
        else:
            rows = _parse_raw(content)

        if not rows:
            return {"status": "error", "message": "CSV vacío o sin filas válidas."}

        with self._drv().session() as s:
            self._ensure_indexes(s)
            if csv_type == "effective":
                stats = self._import_effective(s, rows)
            else:
                stats = self._import_raw(s, rows)

        return {
            "status":   "ok",
            "csv_type": csv_type,
            "rows_parsed": len(rows),
            **stats,
        }
