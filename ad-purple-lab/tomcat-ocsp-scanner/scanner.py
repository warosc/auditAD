"""
scanner.py — Tomcat OCSP / TLS scanner for AD Purple Lab.

Supports:
  - Single target via --target flag or SCAN_TARGET env var
  - Custom ports via --ports flag or SCAN_PORTS env var (comma-separated)
  - Bulk targets from targets.txt (fallback when no target specified)
  - Reports: CSV + JSON written to ./output/

OCSP Stapling check:
  Checks whether the TLS endpoint sends an OCSP stapled response in the
  ServerHello (TLS extension 0x0018). Absence means the client must do a
  live OCSP roundtrip on every TLS handshake, leaking the browsed domain
  to the CA's OCSP responder — a privacy and latency concern.

Tomcat vulnerable versions (as of 2026-04):
  CVE-2025-24813 / partial PUT — 9.0.0.M1-9.0.98, 10.1.0-10.1.34, 11.0.0-11.0.2
  CVE-2024-56337 / RCE via case-insensitive FS — 9.0.0.M1-9.0.97, 10.1.0-10.1.33, 11.0.0-11.0.1
  Ranges kept in config.yaml; extend as needed.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import socket
import ssl
import struct
import sys
from datetime import datetime
from pathlib import Path

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Default configuration ──────────────────────────────────────────────────

DEFAULT_CONFIG: dict = {
    "targets_file": "targets.txt",
    "output_csv":   "output/report.csv",
    "output_json":  "output/report.json",
    "ports":        [443, 8443, 8080],
    "timeout":      5,
    "vulnerable_versions": [
        # CVE-2024-56337 / CVE-2025-24813
        ["9.0.0",  "9.0.98"],  ["10.1.0", "10.1.34"],  ["11.0.0", "11.0.2"],
        ["9.0.0",  "9.0.97"],  ["10.1.0", "10.1.33"],  ["11.0.0", "11.0.1"],
        # CVE-2025-48988 / CVE-2025-49124 / CVE-2025-49125
        ["9.0.0",  "9.0.99"],  ["10.1.0", "10.1.29"],  ["11.0.0", "11.0.3"],
        # CVE-2025-53506 / CVE-2025-52520 / CVE-2025-52434
        ["9.0.0",  "9.0.101"], ["10.1.0", "10.1.31"],  ["11.0.0", "11.0.5"],
        # CVE-2025-48989
        ["9.0.0",  "9.0.103"], ["10.1.0", "10.1.33"],  ["11.0.0", "11.0.7"],
        # CVE-2025-55752
        ["9.0.0",  "9.0.106"], ["10.1.0", "10.1.36"],  ["11.0.0", "11.0.10"],
        # CVE-2026-24734
        ["9.0.0",  "9.0.114"], ["10.1.0", "10.1.49"],  ["11.0.0", "11.0.17"],
    ],
}

CVE_MAP = {
    # ── 2024 ──────────────────────────────────────────────────────────────
    # CVE-2025-24813  Partial PUT / partial GET session fixation
    ("9.0.0",  "9.0.98"):  ["CVE-2025-24813"],
    ("10.1.0", "10.1.34"): ["CVE-2025-24813"],
    ("11.0.0", "11.0.2"):  ["CVE-2025-24813"],
    # CVE-2024-56337  RCE via case-insensitive FS (Windows/macOS)
    ("9.0.0",  "9.0.97"):  ["CVE-2024-56337"],
    ("10.1.0", "10.1.33"): ["CVE-2024-56337"],
    ("11.0.0", "11.0.1"):  ["CVE-2024-56337"],
    # ── 2025 ──────────────────────────────────────────────────────────────
    # CVE-2025-48988  Allocation of Resources Without Limits (DoS)
    ("9.0.0",  "9.0.99"):  ["CVE-2025-48988"],
    ("10.1.0", "10.1.29"): ["CVE-2025-48988"],
    ("11.0.0", "11.0.3"):  ["CVE-2025-48988"],
    # CVE-2025-49124  Untrusted Search Path — Windows installer only
    ("9.0.0",  "9.0.99"):  ["CVE-2025-49124"],
    ("10.1.0", "10.1.29"): ["CVE-2025-49124"],
    # CVE-2025-49125  Session/auth vulnerability
    ("9.0.0",  "9.0.99"):  ["CVE-2025-49125"],
    ("10.1.0", "10.1.29"): ["CVE-2025-49125"],
    ("11.0.0", "11.0.3"):  ["CVE-2025-49125"],
    # CVE-2025-53506  HTTP/2 Uncontrolled Resource Consumption
    ("9.0.0",  "9.0.101"): ["CVE-2025-53506"],
    ("10.1.0", "10.1.31"): ["CVE-2025-53506"],
    ("11.0.0", "11.0.5"):  ["CVE-2025-53506"],
    # CVE-2025-52520  Integer Overflow in multipart upload
    ("9.0.0",  "9.0.101"): ["CVE-2025-52520"],
    ("10.1.0", "10.1.31"): ["CVE-2025-52520"],
    ("11.0.0", "11.0.5"):  ["CVE-2025-52520"],
    # CVE-2025-52434  Race Condition vulnerability
    ("9.0.0",  "9.0.101"): ["CVE-2025-52434"],
    ("10.1.0", "10.1.31"): ["CVE-2025-52434"],
    ("11.0.0", "11.0.5"):  ["CVE-2025-52434"],
    # CVE-2025-48989  Improper Resource Shutdown — DoS (BEAST-style)
    ("9.0.0",  "9.0.103"): ["CVE-2025-48989"],
    ("10.1.0", "10.1.33"): ["CVE-2025-48989"],
    ("11.0.0", "11.0.7"):  ["CVE-2025-48989"],
    # CVE-2025-55752  Relative Path Traversal (regression bug 60013)
    ("9.0.0",  "9.0.106"): ["CVE-2025-55752"],
    ("10.1.0", "10.1.36"): ["CVE-2025-55752"],
    ("11.0.0", "11.0.10"): ["CVE-2025-55752"],
    # ── 2026 ──────────────────────────────────────────────────────────────
    # CVE-2026-24734  Improper Input Validation — OCSP / Tomcat Native APR
    ("9.0.0",  "9.0.114"): ["CVE-2026-24734"],
    ("10.1.0", "10.1.49"): ["CVE-2026-24734"],
    ("11.0.0", "11.0.17"): ["CVE-2026-24734"],
}


# ── Config loading ─────────────────────────────────────────────────────────

def load_config() -> dict:
    config_path = Path("config.yaml")
    if config_path.exists():
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(data)
        return cfg
    return DEFAULT_CONFIG.copy()


# ── Version helpers ────────────────────────────────────────────────────────

def _parse_version(version: str) -> tuple:
    parts = []
    for token in str(version).split("."):
        clean = re.sub(r"\D+.*", "", token)
        parts.append(int(clean) if clean.isdigit() else 0)
    return tuple(parts)


def version_in_range(version: str, minimum: str, maximum: str) -> bool:
    try:
        v = _parse_version(version)
        return _parse_version(minimum) <= v <= _parse_version(maximum)
    except Exception:
        return False


def is_vulnerable(version: str, rules: list) -> bool | str:
    if not version or version in ("Unknown", "Detected but version unknown"):
        return "Unknown"
    for min_v, max_v in rules:
        if version_in_range(version, min_v, max_v):
            return True
    return False


def get_cves(version: str) -> list[str]:
    if not version or version in ("Unknown", "Detected but version unknown"):
        return []
    cves: set[str] = set()
    for (min_v, max_v), ids in CVE_MAP.items():
        if version_in_range(version, min_v, max_v):
            cves.update(ids)
    return sorted(cves)


# ── Network helpers ────────────────────────────────────────────────────────

def is_port_open(host: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def extract_version(text: str) -> str:
    match = re.search(r"Apache Tomcat/([\d\.]+)", text)
    return match.group(1) if match else "Unknown"


def get_tomcat_version(host: str, port: int, timeout: int = 5, use_https: bool = False) -> str:
    scheme = "https" if use_https else "http"
    # Try multiple paths: root, a guaranteed 404, and the Tomcat manager page
    probe_paths = [
        "/",
        "/this-path-does-not-exist-xyz404",
        "/manager/html",
        "/index.jsp",
    ]
    for path in probe_paths:
        url = f"{scheme}://{host}:{port}{path}"
        try:
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            # Check response body
            version = extract_version(resp.text)
            if version != "Unknown":
                return version
            # Check Server header
            server = resp.headers.get("Server", "")
            version = extract_version(server)
            if version != "Unknown":
                return version
            # Check X-Powered-By
            powered = resp.headers.get("X-Powered-By", "")
            version = extract_version(powered)
            if version != "Unknown":
                return version
            if "Apache Tomcat" in resp.text or "Apache Tomcat" in server:
                return "Detected but version unknown"
        except Exception:
            continue
    return "Unknown"


# ── OCSP stapling via raw TLS handshake ───────────────────────────────────

def check_ocsp_stapling_raw(host: str, port: int, timeout: int = 5) -> bool:
    """
    Send a TLS ClientHello with the status_request extension (RFC 6066) and
    look for a CertificateStatus record in the server response.
    Returns True if the server sends an OCSP stapled response.
    """
    # Minimal TLS 1.2 ClientHello with status_request extension
    # Extension type 0x0018 = status_request, 0x000f = heartbeat, etc.
    sni_bytes   = host.encode()
    sni_len     = len(sni_bytes)
    sni_list_len = sni_len + 3
    sni_ext_data = (
        b"\x00" + sni_list_len.to_bytes(2, "big") +
        b"\x00" + sni_len.to_bytes(2, "big") +
        sni_bytes
    )
    sni_ext = b"\x00\x00" + len(sni_ext_data).to_bytes(2, "big") + sni_ext_data

    # status_request extension
    status_req_ext = (
        b"\x00\x18"          # type: status_request
        b"\x00\x05"          # length 5
        b"\x01"              # OCSP
        b"\x00\x00"          # responder_id_list length 0
        b"\x00\x00"          # extensions length 0
    )

    exts = sni_ext + status_req_ext
    exts_len = len(exts)

    # Random (32 bytes) + session_id_len(1) + cipher_suites + compression
    random_bytes = b"\x00" * 32
    session_id   = b"\x00"
    cipher_suites = (
        b"\x00\x1c"          # length 28 (14 suites)
        b"\xc0\x2c"          # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        b"\xc0\x2b"          # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        b"\xc0\x30"          # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        b"\xc0\x2f"          # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        b"\x00\x9d"          # TLS_RSA_WITH_AES_256_GCM_SHA384
        b"\x00\x9c"          # TLS_RSA_WITH_AES_128_GCM_SHA256
        b"\xc0\x14"          # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        b"\xc0\x13"          # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        b"\x00\x35"          # TLS_RSA_WITH_AES_256_CBC_SHA
        b"\x00\x2f"          # TLS_RSA_WITH_AES_128_CBC_SHA
        b"\x00\x0a"          # TLS_RSA_WITH_3DES_EDE_CBC_SHA
        b"\x00\x05"          # TLS_RSA_WITH_RC4_128_SHA
        b"\x00\x04"          # TLS_RSA_WITH_RC4_128_MD5
        b"\xff\xff"          # empty renegotiation info SCSV
    )
    compression  = b"\x01\x00"

    hello_body = (
        b"\x03\x03" +        # TLS 1.2
        random_bytes +
        session_id +
        cipher_suites +
        compression +
        exts_len.to_bytes(2, "big") +
        exts
    )
    hello_len = len(hello_body)
    handshake  = b"\x01" + hello_len.to_bytes(3, "big") + hello_body
    record     = b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(record)

        data = b""
        for _ in range(20):
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # Record type 22 (0x16) = Handshake; content type 11 = Certificate
            # Record type 22 content type 20 = CertificateStatus (0x16)
            # Look for record content type 0x16 (handshake) and handshake type 0x16 (cert_status)
            if len(data) >= 5:
                # Scan for CertificateStatus handshake message (type=22=0x16)
                i = 0
                while i < len(data) - 4:
                    rec_type = data[i]
                    if rec_type == 0x16:  # TLS Handshake record
                        rec_len = struct.unpack(">H", data[i+3:i+5])[0]
                        if i + 5 + rec_len <= len(data):
                            hs_body = data[i+5:i+5+rec_len]
                            # handshake type 20 (0x14) = CertificateStatus
                            if hs_body and hs_body[0] == 0x14:
                                sock.close()
                                return True
                    i += 1
                # Also stop after ServerHelloDone (0x0e) or Finished
                if b"\x16\x03" in data and b"\x0e\x00\x00\x00" in data:
                    break
        sock.close()
    except Exception:
        pass
    return False


# ── Full TLS check ─────────────────────────────────────────────────────────

def check_tls(host: str, port: int, timeout: int = 5) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    result = {
        "handshake":    False,
        "protocol":     None,
        "cipher":       None,
        "ocsp_stapling": False,
        "insecure_tls": False,
        "cert_expiry":  None,
        "cert_cn":      None,
        "weak_reason":  None,
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                protocol = tls.version() or "unknown"
                cipher   = tls.cipher() or ("unknown", "", "")
                cert     = tls.getpeercert()
                result["handshake"] = True
                result["protocol"]  = protocol
                result["cipher"]    = cipher[0]

                # TLS version weakness
                if protocol in {"TLSv1", "TLSv1.1"}:
                    result["insecure_tls"] = True
                    result["weak_reason"]  = f"Deprecated protocol: {protocol}"

                # Cipher weakness
                weak_ciphers = ["rc4", "des", "3des", "md5", "export", "null", "anon"]
                cipher_lower = cipher[0].lower()
                for w in weak_ciphers:
                    if w in cipher_lower:
                        result["insecure_tls"] = True
                        result["weak_reason"]  = (result.get("weak_reason") or "") + f" Weak cipher: {cipher[0]}"
                        break

                # Certificate info
                if cert:
                    not_after = cert.get("notAfter")
                    result["cert_expiry"] = not_after
                    subject = dict(x[0] for x in cert.get("subject", []))
                    result["cert_cn"] = subject.get("commonName")
    except ssl.SSLError as e:
        result["handshake"] = False
        result["weak_reason"] = str(e)
    except Exception:
        pass

    # OCSP stapling via raw socket check
    if result["handshake"]:
        result["ocsp_stapling"] = check_ocsp_stapling_raw(host, port, timeout)

    return result


# ── Single target scan ─────────────────────────────────────────────────────

def scan_target(host: str, config: dict) -> dict:
    ports   = config.get("ports",   DEFAULT_CONFIG["ports"])
    timeout = config.get("timeout", DEFAULT_CONFIG["timeout"])
    rules   = config.get("vulnerable_versions", DEFAULT_CONFIG["vulnerable_versions"])

    result: dict = {
        "target":         host,
        "port_8080":      False,
        "port_8443":      False,
        "port_443":       False,
        "tomcat_version": "Unknown",
        "vulnerable":     "Unknown",
        "cves":           [],
        "tls_443":        False,
        "tls_8443":       False,
        "ocsp_stapling":  False,
        "ocsp_missing_ports": [],
        "tls_protocol":   None,
        "tls_cipher":     None,
        "insecure_tls":   False,
        "weak_reason":    None,
        "cert_expiry":    None,
        "cert_cn":        None,
        "findings":       [],
        "checked_at":     datetime.utcnow().isoformat() + "Z",
    }

    print(f"\n[*] Scanning {host}")
    print(f"    Ports: {ports}")

    # Port scan
    for p in ports:
        key = f"port_{p}"
        open_ = is_port_open(host, p, timeout)
        if key in result:
            result[key] = open_
        print(f"    [{'+' if open_ else '-'}] Port {p}: {'OPEN' if open_ else 'closed'}")

    # Tomcat version detection (HTTP on 8080, HTTPS on 8443/443)
    http_ports  = [p for p in ports if p == 8080 and result.get(f"port_{p}")]
    https_ports = [p for p in ports if p in (443, 8443) and result.get(f"port_{p}")]

    for p in http_ports:
        v = get_tomcat_version(host, p, timeout, use_https=False)
        if v != "Unknown":
            result["tomcat_version"] = v
            break

    if result["tomcat_version"] == "Unknown":
        for p in https_ports:
            v = get_tomcat_version(host, p, timeout, use_https=True)
            if v != "Unknown":
                result["tomcat_version"] = v
                break

    version = result["tomcat_version"]
    print(f"    [i] Tomcat version: {version}")

    vuln = is_vulnerable(version, rules)
    result["vulnerable"] = vuln
    result["cves"]       = get_cves(version) if vuln is True else []

    if vuln is True:
        cve_str = ", ".join(result["cves"]) if result["cves"] else "see config"
        print(f"    [!] VULNERABLE: {version}  ({cve_str})")
        result["findings"].append(f"Vulnerable Tomcat version: {version} ({cve_str})")
    elif vuln == "Unknown":
        print(f"    [?] Version unknown — could not confirm vulnerability status")
    else:
        print(f"    [✓] Version appears patched: {version}")

    # TLS / OCSP checks
    tls_ports_to_check = [p for p in (443, 8443) if result.get(f"port_{p}")]

    for p in tls_ports_to_check:
        print(f"\n    [TLS] Checking port {p}...")
        info = check_tls(host, p, timeout)

        key = f"tls_{p}"
        if key in result:
            result[key] = info["handshake"]

        if not info["handshake"]:
            print(f"    [-] TLS handshake failed on port {p}")
            continue

        print(f"    [+] Protocol : {info['protocol']}")
        print(f"    [+] Cipher   : {info['cipher']}")

        if info["cert_cn"]:
            print(f"    [+] Cert CN  : {info['cert_cn']}")
        if info["cert_expiry"]:
            print(f"    [+] Cert exp : {info['cert_expiry']}")

        if info["ocsp_stapling"]:
            print(f"    [✓] OCSP stapling: PRESENT (port {p})")
            result["ocsp_stapling"] = True
        else:
            print(f"    [!] OCSP stapling: MISSING (port {p})")
            result["ocsp_missing_ports"].append(p)
            result["findings"].append(
                f"OCSP stapling absent on port {p} — "
                "clients must perform live OCSP roundtrip, leaking domain to CA responder"
            )

        if info["insecure_tls"]:
            print(f"    [!] INSECURE TLS: {info['weak_reason']}")
            result["insecure_tls"] = True
            result["weak_reason"]  = info["weak_reason"]
            result["findings"].append(f"Insecure TLS on port {p}: {info['weak_reason']}")
        else:
            print(f"    [✓] TLS configuration looks secure on port {p}")

        # Carry forward best protocol / cipher
        if not result["tls_protocol"] and info["protocol"]:
            result["tls_protocol"] = info["protocol"]
        if not result["tls_cipher"] and info["cipher"]:
            result["tls_cipher"] = info["cipher"]
        if not result["cert_expiry"] and info["cert_expiry"]:
            result["cert_expiry"] = info["cert_expiry"]
        if not result["cert_cn"] and info["cert_cn"]:
            result["cert_cn"] = info["cert_cn"]

    if not tls_ports_to_check:
        print("    [i] No TLS ports reachable — OCSP stapling check skipped")

    return result


# ── Output helpers ─────────────────────────────────────────────────────────

def write_outputs(results: list[dict], csv_path: str, json_path: str) -> None:
    Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(results, jf, indent=2, ensure_ascii=False, default=str)

    if results:
        flat_rows = []
        for r in results:
            row = dict(r)
            row["cves"]     = ", ".join(r.get("cves", []))
            row["findings"] = " | ".join(r.get("findings", []))
            row["ocsp_missing_ports"] = ", ".join(str(p) for p in r.get("ocsp_missing_ports", []))
            flat_rows.append(row)

        with open(csv_path, "w", encoding="utf-8", newline="") as cf:
            writer = csv.DictWriter(cf, fieldnames=list(flat_rows[0].keys()))
            writer.writeheader()
            writer.writerows(flat_rows)


def print_summary(results: list[dict]) -> None:
    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    vuln_count  = sum(1 for r in results if r.get("vulnerable") is True)
    ocsp_miss   = sum(1 for r in results if r.get("ocsp_missing_ports"))
    insecure    = sum(1 for r in results if r.get("insecure_tls"))

    print(f"  Targets scanned   : {len(results)}")
    print(f"  Vulnerable Tomcat : {vuln_count}")
    print(f"  OCSP stapling missing : {ocsp_miss}")
    print(f"  Insecure TLS      : {insecure}")
    print()
    for r in results:
        flags = []
        if r.get("vulnerable") is True:
            flags.append(f"VULN({r['tomcat_version']})")
        if r.get("ocsp_missing_ports"):
            flags.append(f"NO-OCSP(:{','.join(str(p) for p in r['ocsp_missing_ports'])})")
        if r.get("insecure_tls"):
            flags.append("INSECURE-TLS")
        status = "  [!] " if flags else "  [✓] "
        print(f"{status}{r['target']}  {' '.join(flags)}")
    print("=" * 60)


# ── Entry point ────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Tomcat OCSP/TLS vulnerability scanner"
    )
    parser.add_argument(
        "--target", "-t",
        default=os.environ.get("SCAN_TARGET", ""),
        help="Single host/domain to scan (overrides targets.txt)",
    )
    parser.add_argument(
        "--ports", "-p",
        default=os.environ.get("SCAN_PORTS", ""),
        help="Comma-separated port list, e.g. 443,8443,8080 (overrides config)",
    )
    return parser.parse_args()


def main() -> None:
    args   = parse_args()
    config = load_config()

    # Override ports if provided
    if args.ports:
        try:
            config["ports"] = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            print(f"ERROR: invalid ports value: {args.ports}", file=sys.stderr)
            sys.exit(1)

    # Determine targets
    if args.target:
        targets = [args.target.strip()]
        print(f"[+] Single-target mode: {args.target}")
    else:
        targets_path = Path(config.get("targets_file", DEFAULT_CONFIG["targets_file"]))
        if not targets_path.exists():
            print(f"ERROR: targets file not found: {targets_path}", file=sys.stderr)
            sys.exit(1)
        targets = [
            line.strip()
            for line in targets_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]
        if not targets:
            print("ERROR: targets file is empty", file=sys.stderr)
            sys.exit(1)
        print(f"[+] Bulk mode: {len(targets)} targets from {targets_path}")

    print(f"[+] Ports to scan: {config['ports']}")
    print(f"[+] Timeout: {config['timeout']}s")
    print(f"[+] Checking {len(targets)} target(s)...\n")

    results = []
    for host in targets:
        results.append(scan_target(host, config))

    print_summary(results)

    csv_out  = config["output_csv"]
    json_out = config["output_json"]

    # Single-target: use target name in filename to avoid overwriting bulk report
    if args.target:
        safe_name = re.sub(r"[^\w\-.]", "_", args.target)
        ts        = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        csv_out   = f"output/report_{safe_name}_{ts}.csv"
        json_out  = f"output/report_{safe_name}_{ts}.json"

    write_outputs(results, csv_out, json_out)
    print(f"\n[✔] Reports saved:")
    print(f"    CSV : {csv_out}")
    print(f"    JSON: {json_out}")


if __name__ == "__main__":
    main()
