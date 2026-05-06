"""
neo4j_import_service.py — Imports AD CSV analysis results into Neo4j as a property graph.

Labels used (DISTINCT from BloodHound's User/Computer/Group):
  :ADUser      — users from CSV export
  :ADComputer  — computers from CSV export
  :ADGroup     — groups from CSV export
  :ADOU        — Organizational Units from CSV export

Relationships:
  (:ADUser)-[:MEMBER_OF]->(:ADGroup)
  (:ADComputer)-[:MEMBER_OF]->(:ADGroup)
  (:ADUser)-[:IN_OU]->(:ADOU)
  (:ADComputer)-[:IN_OU]->(:ADOU)
  (:ADOU)-[:CHILD_OF]->(:ADOU)

Purge modes:
  csv  — Remove only AD* labels (safe, preserves BloodHound data)
  all  — Remove everything from the database
  none — Append without purging (may create duplicates)
"""
from __future__ import annotations

import os
from typing import Any

# ── Connection config ─────────────────────────────────────────────────────────
# NEO4J_AUTH env var: "user/password"  (set by docker-compose)
_auth = os.environ.get("NEO4J_AUTH", "neo4j/ChangeThisNeo4jPass123!")
_u, _p = _auth.split("/", 1) if "/" in _auth else ("neo4j", _auth)

NEO4J_URI  = os.environ.get("NEO4J_BOLT_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", _u)
NEO4J_PASS = os.environ.get("NEO4J_PASS", _p)

BATCH      = 500
CSV_LABELS = ("ADUser", "ADComputer", "ADGroup", "ADOU")


class Neo4jImportService:

    def __init__(self):
        self._driver = None

    def _drv(self):
        if self._driver is None:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS)
            )
        return self._driver

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        try:
            drv = self._drv()
            with drv.session() as s:
                s.run("RETURN 1").consume()
            counts: dict[str, int] = {}
            with drv.session() as s:
                for lbl in CSV_LABELS:
                    r = s.run(f"MATCH (n:{lbl}) RETURN count(n) AS c")
                    counts[lbl] = r.single()["c"]
            return {"connected": True, "uri": NEO4J_URI, "counts": counts}
        except Exception as exc:
            return {"connected": False, "uri": NEO4J_URI, "error": str(exc)}

    # ── Purge ─────────────────────────────────────────────────────────────────

    def purge_csv_labels(self) -> int:
        """Delete only CSV-imported nodes. BloodHound data is untouched."""
        total = 0
        with self._drv().session() as s:
            for lbl in CSV_LABELS:
                r = s.run(f"MATCH (n:{lbl}) DETACH DELETE n RETURN count(*) AS c")
                total += r.single()["c"] or 0
        return total

    def purge_all(self) -> int:
        """Delete ALL nodes/relationships in the database."""
        with self._drv().session() as s:
            r = s.run("MATCH (n) DETACH DELETE n RETURN count(*) AS c")
            return r.single()["c"] or 0

    # ── Import ────────────────────────────────────────────────────────────────

    def _batch(self, session, cypher: str, rows: list[dict]) -> int:
        total = 0
        for i in range(0, len(rows), BATCH):
            chunk = rows[i : i + BATCH]
            session.run(cypher, rows=chunk).consume()
            total += len(chunk)
        return total

    def import_data(self, data: dict) -> dict[str, int]:
        users     = data.get("users",     [])
        computers = data.get("computers", [])
        groups    = data.get("groups",    [])
        ous       = data.get("ous",       [])

        nodes = 0
        rels  = 0

        with self._drv().session() as s:

            # ── Indexes (idempotent) ──────────────────────────────────────
            idx = [
                ("ADUser",     "sam"),
                ("ADUser",     "display_name"),
                ("ADComputer", "name"),
                ("ADComputer", "sam"),
                ("ADGroup",    "sam"),
                ("ADOU",       "name"),
                ("ADOU",       "dn"),
            ]
            for lbl, prop in idx:
                try:
                    s.run(
                        f"CREATE INDEX idx_{lbl}_{prop} IF NOT EXISTS "
                        f"FOR (n:{lbl}) ON (n.{prop})"
                    ).consume()
                except Exception:
                    pass

            # ── OUs ──────────────────────────────────────────────────────
            ou_rows = [
                {
                    "name":        o["name"],
                    "dn":          o["dn"],
                    "canonical":   o["canonical"],
                    "gpo_count":   o["gpo_count"],
                    "protected":   o["protected"],
                    "description": o["description"],
                    "managed_by":  o["managed_by"],
                }
                for o in ous
                if o.get("name")
            ]
            if ou_rows:
                nodes += self._batch(s,
                    "UNWIND $rows AS r CREATE (n:ADOU) SET n = r",
                    ou_rows,
                )

            # OU hierarchy — CHILD_OF
            ou_dn_map = {o["dn"]: o["name"] for o in ous if o.get("dn")}
            child_of = []
            for o in ous:
                dn = o.get("dn", "")
                parts = dn.split(",", 1)
                if len(parts) == 2:
                    parent_dn = parts[1]
                    if parent_dn in ou_dn_map:
                        child_of.append({
                            "child":  o["name"],
                            "parent": ou_dn_map[parent_dn],
                        })
            if child_of:
                rels += self._batch(s,
                    """
                    UNWIND $rows AS r
                    MATCH (c:ADOU {name: r.child})
                    MATCH (p:ADOU {name: r.parent})
                    CREATE (c)-[:CHILD_OF]->(p)
                    """,
                    child_of,
                )

            # ── Groups ───────────────────────────────────────────────────
            grp_rows = [
                {
                    "name":         g["name"],
                    "sam":          g["sam"],
                    "dn":           g["dn"],
                    "scope":        g["scope"],
                    "category":     g["category"],
                    "member_count": g["member_count"],
                    "description":  g["description"],
                }
                for g in groups
                if g.get("name")
            ]
            if grp_rows:
                nodes += self._batch(s,
                    "UNWIND $rows AS r CREATE (n:ADGroup) SET n = r",
                    grp_rows,
                )

            # ── Users ────────────────────────────────────────────────────
            user_rows = [
                {
                    "sam":          u["sam"],
                    "dn":           u["dn"],
                    "ou":           u["ou"],
                    "ou_path":      u["ou_path"],
                    "upn":          u["upn"],
                    "display_name": u["display_name"],
                    "department":   u["department"],
                    "company":      u["company"],
                    "disabled":     u["disabled"],
                    "no_expire":    u["no_expire"],
                    "no_preauth":   u["no_preauth"],
                    "pwd_not_req":  u["pwd_not_req"],
                    "spn_count":    len(u["spn"]),
                    "last_logon":   u["last_logon"],
                    "pwd_last_set": u["pwd_last_set"],
                }
                for u in users
                if u.get("sam")
            ]
            if user_rows:
                nodes += self._batch(s,
                    "UNWIND $rows AS r CREATE (n:ADUser) SET n = r",
                    user_rows,
                )

            # ── Computers ────────────────────────────────────────────────
            comp_rows = [
                {
                    "name":       c["name"],
                    "sam":        c["sam"],
                    "dn":         c["dn"],
                    "os":         c["os"],
                    "os_ver":     c["os_ver"],
                    "is_dc":      c["is_dc"],
                    "enabled":    c["enabled"],
                    "last_logon": c["last_logon"],
                    "os_risk":    c["os_risk"] or "none",
                    "ou":         c["ou"],
                    "ip":         c["ip"],
                }
                for c in computers
                if c.get("name")
            ]
            if comp_rows:
                nodes += self._batch(s,
                    "UNWIND $rows AS r CREATE (n:ADComputer) SET n = r",
                    comp_rows,
                )

            # ── Relationships: MEMBER_OF (users + computers → groups) ────
            memb_rows = []
            for g in groups:
                for cn in g.get("members", []):
                    memb_rows.append({"group_sam": g["sam"], "member": cn})

            if memb_rows:
                # Try user match (by sam or display_name)
                rels += self._batch(s,
                    """
                    UNWIND $rows AS r
                    MATCH (g:ADGroup {sam: r.group_sam})
                    MATCH (u:ADUser)
                      WHERE u.sam = r.member OR u.display_name = r.member
                    MERGE (u)-[:MEMBER_OF]->(g)
                    """,
                    memb_rows,
                )
                # Try computer match (by name or sam without $)
                rels += self._batch(s,
                    """
                    UNWIND $rows AS r
                    MATCH (g:ADGroup {sam: r.group_sam})
                    MATCH (c:ADComputer)
                      WHERE c.name = r.member OR c.sam = r.member
                    MERGE (c)-[:MEMBER_OF]->(g)
                    """,
                    memb_rows,
                )

            # ── Relationships: IN_OU (users + computers → OUs) ──────────
            user_ou = [
                {"sam": u["sam"], "ou": u["ou"]}
                for u in users
                if u.get("sam") and u.get("ou")
            ]
            if user_ou:
                rels += self._batch(s,
                    """
                    UNWIND $rows AS r
                    MATCH (u:ADUser {sam: r.sam})
                    MATCH (o:ADOU   {name: r.ou})
                    CREATE (u)-[:IN_OU]->(o)
                    """,
                    user_ou,
                )

            comp_ou = [
                {"name": c["name"], "ou": c["ou"]}
                for c in computers
                if c.get("name") and c.get("ou")
            ]
            if comp_ou:
                rels += self._batch(s,
                    """
                    UNWIND $rows AS r
                    MATCH (c:ADComputer {name: r.name})
                    MATCH (o:ADOU       {name: r.ou})
                    CREATE (c)-[:IN_OU]->(o)
                    """,
                    comp_ou,
                )

        return {"nodes": nodes, "relationships": rels}
