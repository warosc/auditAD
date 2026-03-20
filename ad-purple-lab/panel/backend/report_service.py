"""
report_service.py — Lists and serves audit reports from the mounted
./reports bind-mount (/workspace/reports inside the container).
"""
from __future__ import annotations

import glob
import os
from datetime import datetime
from typing import Any


REPORTS_DIR = os.environ.get("REPORTS_DIR", "/workspace/reports")
WORKSPACE    = os.environ.get("WORKSPACE",    "/workspace")


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} TB"


def _report_type(filepath: str) -> str:
    name = os.path.basename(filepath).lower()
    if "audit_summary" in name:
        return "audit"
    if "bloodhound" in name or name.endswith(".zip"):
        return "bloodhound"
    if "ldap" in name:
        return "ldap"
    if "dns" in name:
        return "dns"
    if "nmap" in name:
        return "nmap"
    if name.endswith(".tar.gz"):
        return "export"
    return "report"


class ReportService:

    def list_reports(self) -> dict[str, Any]:
        reports: list[dict[str, Any]] = []

        if not os.path.exists(REPORTS_DIR):
            return {"reports": [], "total": 0, "warning": f"{REPORTS_DIR} not mounted"}

        # Walk the reports directory
        for pattern in ("**/*.txt", "**/*.json", "**/*.zip"):
            for fp in glob.glob(os.path.join(REPORTS_DIR, pattern), recursive=True):
                try:
                    st = os.stat(fp)
                    reports.append({
                        "filename": os.path.basename(fp),
                        "path":     fp,
                        "size":     st.st_size,
                        "size_human": _human_size(st.st_size),
                        "created":  datetime.fromtimestamp(st.st_mtime).isoformat(),
                        "type":     _report_type(fp),
                    })
                except OSError:
                    pass

        # tar.gz exports (written by export-logs.sh to /workspace/)
        for fp in glob.glob(os.path.join(WORKSPACE, "*.tar.gz")):
            try:
                st = os.stat(fp)
                reports.append({
                    "filename": os.path.basename(fp),
                    "path":     fp,
                    "size":     st.st_size,
                    "size_human": _human_size(st.st_size),
                    "created":  datetime.fromtimestamp(st.st_mtime).isoformat(),
                    "type":     "export",
                })
            except OSError:
                pass

        reports.sort(key=lambda x: x["created"], reverse=True)
        return {"reports": reports, "total": len(reports)}

    def resolve_path(self, filename: str) -> str | None:
        """
        Safely resolve *filename* to an absolute path accessible by this
        service. Returns None if not found.
        Prevents path traversal by using basename only.
        """
        safe = os.path.basename(filename)

        # Search within reports dir
        for dirpath, _, files in os.walk(REPORTS_DIR):
            if safe in files:
                return os.path.join(dirpath, safe)

        # Check workspace root (exports)
        candidate = os.path.join(WORKSPACE, safe)
        if os.path.isfile(candidate):
            return candidate

        return None

    def audit_history(self) -> dict[str, Any]:
        """Returns last 20 audit summary files with a short preview."""
        summaries: list[dict[str, Any]] = []
        pattern = os.path.join(REPORTS_DIR, "audit_summary_*.txt")

        for fp in sorted(glob.glob(pattern), reverse=True)[:20]:
            try:
                st = os.stat(fp)
                with open(fp, errors="replace") as fh:
                    preview = fh.read(600)
                summaries.append({
                    "filename": os.path.basename(fp),
                    "created":  datetime.fromtimestamp(st.st_mtime).isoformat(),
                    "preview":  preview,
                    "size":     st.st_size,
                })
            except OSError:
                pass

        return {"history": summaries, "total": len(summaries)}
