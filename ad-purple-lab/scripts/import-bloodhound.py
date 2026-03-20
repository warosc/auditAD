#!/usr/bin/env python3
"""
import-bloodhound.py — Importa datos BloodHound (ZIP o JSON) en Neo4j.
Compatible con neo4j driver 5.x/6.x y BloodHound Classic JSON format.

Uso:
  python3 import-bloodhound.py <archivo.zip|archivo.json> [opciones]

Opciones:
  --bolt      URI bolt de Neo4j  (default: bolt://neo4j:7687)
  --user      Usuario Neo4j      (default: neo4j)
  --password  Password Neo4j
  --clear     Limpiar DB antes de importar
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

try:
    from neo4j import GraphDatabase
except ImportError:
    print("[ERROR] neo4j driver no instalado. Ejecuta: pip install neo4j")
    sys.exit(1)


# ── Constraints BloodHound ─────────────────────────────────────────────────

CONSTRAINTS = [
    "CREATE CONSTRAINT IF NOT EXISTS FOR (u:User)     REQUIRE u.objectid IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (c:Computer) REQUIRE c.objectid IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (g:Group)    REQUIRE g.objectid IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (d:Domain)   REQUIRE d.objectid IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (o:OU)       REQUIRE o.objectid IS UNIQUE",
    "CREATE CONSTRAINT IF NOT EXISTS FOR (p:GPO)      REQUIRE p.objectid IS UNIQUE",
]

# ── Mapeo tipo JSON → label Neo4j ──────────────────────────────────────────

TYPE_LABEL = {
    "users":      "User",
    "computers":  "Computer",
    "groups":     "Group",
    "domains":    "Domain",
    "ous":        "OU",
    "gpos":       "GPO",
    "containers": "Container",
}

# ── Helpers ────────────────────────────────────────────────────────────────

def _label_from_filename(filename: str) -> str:
    name = Path(filename).stem.lower()
    for key, label in TYPE_LABEL.items():
        if name.endswith(key):
            return label
    return None


def _props(obj: dict) -> dict:
    """Flatten BloodHound object properties for Neo4j."""
    props = dict(obj.get("Properties", {}))
    props["objectid"] = obj.get("ObjectIdentifier", "").upper()
    props["name"] = props.get("name", obj.get("ObjectIdentifier", "?")).upper()
    return props


def import_nodes(tx, label: str, data: list[dict]):
    if not data:
        return
    query = (
        f"UNWIND $rows AS row "
        f"MERGE (n:{label} {{objectid: row.objectid}}) "
        f"SET n += row"
    )
    rows = [_props(obj) for obj in data]
    tx.run(query, rows=rows)


def import_aces(tx, aces: list[dict], src_id: str):
    """Import ACE (Access Control Entry) edges."""
    if not aces:
        return
    for ace in aces:
        right = ace.get("RightName", "")
        principal_id = ace.get("PrincipalSID", "").upper()
        principal_type = ace.get("PrincipalType", "Base")
        is_inherited = ace.get("IsInherited", False)
        if not right or not principal_id:
            continue
        tx.run(
            "MERGE (a {objectid: $src}) "
            "MERGE (b {objectid: $dst}) "
            f"MERGE (b)-[r:{right}]->(a) "
            "SET r.isinherited = $inherited",
            src=src_id.upper(),
            dst=principal_id,
            inherited=is_inherited,
        )


def import_members(tx, members: list[dict], group_id: str):
    if not members:
        return
    for m in members:
        mid = m.get("ObjectIdentifier", "").upper()
        mtype = m.get("ObjectType", "Base")
        if not mid:
            continue
        tx.run(
            "MERGE (a {objectid: $gid}) "
            "MERGE (b {objectid: $mid}) "
            "MERGE (b)-[:MemberOf]->(a)",
            gid=group_id.upper(),
            mid=mid,
        )


def import_sessions(tx, sessions: list[dict]):
    if not sessions:
        return
    for s in sessions:
        uid = s.get("UserId", "").upper()
        cid = s.get("ComputerId", "").upper()
        if uid and cid:
            tx.run(
                "MERGE (u:User {objectid: $uid}) "
                "MERGE (c:Computer {objectid: $cid}) "
                "MERGE (u)-[:HasSession]->(c)",
                uid=uid, cid=cid,
            )


def import_localadmins(tx, admins: list[dict], computer_id: str):
    if not admins:
        return
    for a in admins:
        aid = a.get("ObjectIdentifier", "").upper()
        if aid:
            tx.run(
                "MERGE (a {objectid: $aid}) "
                "MERGE (c:Computer {objectid: $cid}) "
                "MERGE (a)-[:AdminTo]->(c)",
                aid=aid, cid=computer_id.upper(),
            )


def process_json(driver, label: str, data: dict):
    """Process one BloodHound JSON file."""
    objects = data.get("data", [])
    total = len(objects)
    if total == 0:
        print(f"  [SKIP] {label}: sin objetos")
        return

    print(f"  [+] {label}: {total} objetos", end="", flush=True)

    with driver.session() as session:
        # Import nodes in batches of 500
        batch = []
        for obj in objects:
            batch.append(obj)
            if len(batch) >= 500:
                session.execute_write(import_nodes, label, batch)
                batch = []
        if batch:
            session.execute_write(import_nodes, label, batch)

        # Import relationships
        for obj in objects:
            oid = obj.get("ObjectIdentifier", "")
            if not oid:
                continue

            # ACEs
            aces = obj.get("Aces", [])
            if aces:
                session.execute_write(import_aces, aces, oid)

            # Group members
            if label == "Group":
                members = obj.get("Members", [])
                session.execute_write(import_members, members, oid)

            # Computer: sessions, local admins
            if label == "Computer":
                sessions = obj.get("Sessions", {}).get("Results", [])
                session.execute_write(import_sessions, sessions)
                admins = obj.get("LocalAdmins", {}).get("Results", [])
                session.execute_write(import_localadmins, admins, oid)

    print(" ✓")


def clear_database(driver):
    print("  Limpiando base de datos...")
    with driver.session() as session:
        session.run("MATCH (n) DETACH DELETE n")
    print("  DB vaciada.")


def setup_constraints(driver):
    with driver.session() as session:
        for q in CONSTRAINTS:
            try:
                session.run(q)
            except Exception:
                pass


def import_file(driver, path: Path):
    label = _label_from_filename(path.name)
    if not label:
        print(f"  [SKIP] {path.name}: tipo desconocido")
        return
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    process_json(driver, label, data)


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Importa datos BloodHound en Neo4j")
    parser.add_argument("files", nargs="+", help="Archivos ZIP o JSON de BloodHound")
    parser.add_argument("--bolt",     default="bolt://neo4j:7687")
    parser.add_argument("--user",     default="neo4j")
    parser.add_argument("--password", default="ChangeThisNeo4jPass123!")
    parser.add_argument("--clear",    action="store_true", help="Limpiar DB antes de importar")
    args = parser.parse_args()

    print(f"\n[BloodHound → Neo4j] {args.bolt}")
    print(f"  Usuario : {args.user}")
    print(f"  Archivos: {args.files}\n")

    try:
        driver = GraphDatabase.driver(args.bolt, auth=(args.user, args.password))
        driver.verify_connectivity()
    except Exception as e:
        print(f"[ERROR] No se pudo conectar a Neo4j: {e}")
        sys.exit(1)

    if args.clear:
        clear_database(driver)

    setup_constraints(driver)

    for file_arg in args.files:
        path = Path(file_arg)
        if not path.exists():
            print(f"[ERROR] Archivo no encontrado: {path}")
            continue

        print(f"Procesando: {path.name}")

        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as zf:
                for name in sorted(zf.namelist()):
                    if name.endswith(".json"):
                        tmp = Path("/tmp") / name
                        tmp.write_bytes(zf.read(name))
                        import_file(driver, tmp)
                        tmp.unlink()
        elif path.suffix.lower() == ".json":
            import_file(driver, path)
        else:
            print(f"  [SKIP] Formato no soportado: {path.suffix}")

    driver.close()

    print("\n[OK] Importación completada.")
    print("     Abre Neo4j Browser: http://localhost:7474")
    print("     Query: MATCH (n) RETURN n LIMIT 100\n")


if __name__ == "__main__":
    main()
