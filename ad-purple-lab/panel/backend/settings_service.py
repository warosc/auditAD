"""
settings_service.py — Persistent lab settings backed by SQLite.

All settings are stored as key-value pairs. SETTING_DEFS describes
the full schema: label, group, type, default and optional constraints.
On exec_run, get_env_dict() returns the live values to pass as env vars
to the kali-audit container — overriding whatever .env has at startup.
"""
from __future__ import annotations

import os
from typing import Any

from sqlalchemy import select, delete
from database import AsyncSessionLocal
from models import Setting

# ── Setting definitions ────────────────────────────────────────────────────
# Each entry: key → {label, group, type, default, ...optional constraints}
SETTING_DEFS: list[dict[str, Any]] = [
    # ── Active Directory ──────────────────────────────────────────────
    {"key": "DC_IP",            "label": "DC IP Address",        "group": "ad",      "type": "text",     "default": "192.168.1.10",   "placeholder": "192.168.1.10"},
    {"key": "AD_DOMAIN",        "label": "Dominio AD",           "group": "ad",      "type": "text",     "default": "corp.local",     "placeholder": "corp.local"},
    {"key": "AD_FQDN",          "label": "FQDN del DC",          "group": "ad",      "type": "text",     "default": "dc01.corp.local","placeholder": "dc01.corp.local"},
    {"key": "AD_USERNAME",      "label": "Usuario de auditoría", "group": "ad",      "type": "text",     "default": "audit.user",     "placeholder": "audit.user"},
    {"key": "AD_PASSWORD",      "label": "Contraseña",           "group": "ad",      "type": "password", "default": "",               "placeholder": "••••••••"},
    {"key": "LDAP_BASE_DN",     "label": "LDAP Base DN",         "group": "ad",      "type": "text",     "default": "DC=corp,DC=local","placeholder": "DC=corp,DC=local"},
    {"key": "KERBEROS_REALM",   "label": "Kerberos Realm",       "group": "ad",      "type": "text",     "default": "CORP.LOCAL",     "placeholder": "CORP.LOCAL"},
    {"key": "DNS_SERVER",       "label": "Servidor DNS",         "group": "ad",      "type": "text",     "default": "192.168.1.10",   "placeholder": "IP del DC"},
    {"key": "TARGET_SUBNET",    "label": "Subnet objetivo",      "group": "ad",      "type": "text",     "default": "192.168.1.0/24", "placeholder": "192.168.1.0/24"},

    # ── Rate limiting ─────────────────────────────────────────────────
    {"key": "LDAP_DELAY",           "label": "LDAP Delay (s)",       "group": "rate", "type": "number", "default": "0.2", "min": 0,   "max": 10,  "step": 0.1, "help": "Pausa entre consultas LDAP"},
    {"key": "PORTSCAN_RATE",        "label": "Port Scan Rate",        "group": "rate", "type": "number", "default": "20",  "min": 1,   "max": 500, "step": 1,   "help": "Paquetes/s para nmap"},
    {"key": "BLOODHOUND_THREADS",   "label": "BloodHound Threads",    "group": "rate", "type": "number", "default": "5",   "min": 1,   "max": 20,  "step": 1,   "help": "Workers paralelos para la colección"},
    {"key": "BLOODHOUND_TIMEOUT",   "label": "BloodHound Timeout (s)","group": "rate", "type": "number", "default": "30",  "min": 5,   "max": 300, "step": 5,   "help": "Timeout por operación BloodHound"},

    # ── Audit flags ───────────────────────────────────────────────────
    {"key": "SAFE_MODE",          "label": "Safe Mode",          "group": "audit", "type": "bool", "default": "true",  "help": "Deshabilita cualquier acción que modifique el AD"},
    {"key": "ENABLE_BLOODHOUND",  "label": "Habilitar BloodHound","group": "audit", "type": "bool", "default": "true"},
    {"key": "ENABLE_LDAP_DUMP",   "label": "Habilitar LDAP Dump", "group": "audit", "type": "bool", "default": "true"},
    {"key": "ENABLE_PORT_CHECKS", "label": "Habilitar Port Scan", "group": "audit", "type": "bool", "default": "true"},

    # ── Wazuh ─────────────────────────────────────────────────────────
    {"key": "WAZUH_MANAGER_HOST", "label": "Wazuh Manager IP/Host", "group": "wazuh", "type": "text", "default": "", "placeholder": "IP de tu host Docker"},

    # ── Capture ───────────────────────────────────────────────────────
    {"key": "CAPTURE_INTERFACE",  "label": "Interfaz de captura",   "group": "capture", "type": "text", "default": "eth0", "placeholder": "eth0"},
]

# Fast lookup by key
_DEFS_BY_KEY: dict[str, dict] = {d["key"]: d for d in SETTING_DEFS}


class SettingsService:
    # ── Read ──────────────────────────────────────────────────────────

    async def get_all(self) -> list[dict[str, Any]]:
        """Return all setting definitions merged with DB values."""
        db_values = await self._load_db()
        result = []
        for defn in SETTING_DEFS:
            key = defn["key"]
            # Priority: DB → env var → hardcoded default
            value = db_values.get(key) or os.environ.get(key) or defn["default"]
            result.append({**defn, "value": value})
        return result

    async def get_by_group(self, group: str) -> list[dict[str, Any]]:
        all_settings = await self.get_all()
        return [s for s in all_settings if s["group"] == group]

    async def get_env_dict(self) -> dict[str, str]:
        """Return {KEY: value} dict to be passed to docker exec_run as env overrides."""
        db_values = await self._load_db()
        env: dict[str, str] = {}
        for defn in SETTING_DEFS:
            key = defn["key"]
            value = db_values.get(key) or os.environ.get(key) or defn["default"]
            if value:
                env[key] = str(value)
        return env

    # ── Write ─────────────────────────────────────────────────────────

    async def save(self, data: dict[str, str]) -> None:
        """Upsert the provided key-value pairs. Unknown keys are ignored."""
        valid_keys = set(_DEFS_BY_KEY.keys())
        async with AsyncSessionLocal() as session:
            for key, value in data.items():
                if key not in valid_keys:
                    continue
                existing = await session.get(Setting, key)
                if existing:
                    existing.value = str(value)
                else:
                    session.add(Setting(key=key, value=str(value)))
            await session.commit()

    # ── Internal ──────────────────────────────────────────────────────

    async def _load_db(self) -> dict[str, str]:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(Setting))
            rows = result.scalars().all()
            return {row.key: row.value for row in rows}

    @staticmethod
    def get_definitions() -> list[dict[str, Any]]:
        """Return raw definitions for the frontend schema (no DB values)."""
        return SETTING_DEFS
