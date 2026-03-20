"use client";

import { useEffect, useState, useCallback } from "react";
import {
  Save,
  Plus,
  Trash2,
  ToggleLeft,
  ToggleRight,
  RefreshCw,
  Download,
  Copy,
  Check,
} from "lucide-react";
import { api, SettingDef, ScheduledJob } from "@/lib/api";

// ── Types ─────────────────────────────────────────────────────

type Tab = "ad" | "rate" | "audit-flags" | "schedule" | "wazuh" | "capture";

const TABS: { id: Tab; label: string }[] = [
  { id: "ad",          label: "Active Directory" },
  { id: "rate",        label: "Rate Limits" },
  { id: "audit-flags", label: "Flags de Auditoría" },
  { id: "schedule",    label: "Automatización" },
  { id: "wazuh",       label: "Wazuh Cliente" },
  { id: "capture",     label: "Captura" },
];

// ── Helpers ───────────────────────────────────────────────────

function groupBy<T>(arr: T[], key: (item: T) => string): Record<string, T[]> {
  return arr.reduce<Record<string, T[]>>((acc, item) => {
    const k = key(item);
    (acc[k] ??= []).push(item);
    return acc;
  }, {});
}

// ── Sub-components ────────────────────────────────────────────

function FieldInput({
  def,
  value,
  onChange,
}: {
  def: SettingDef;
  value: string;
  onChange: (v: string) => void;
}) {
  if (def.type === "bool") {
    const on = value === "true";
    return (
      <button
        type="button"
        onClick={() => onChange(on ? "false" : "true")}
        className="flex items-center gap-2 text-sm"
      >
        {on ? (
          <ToggleRight className="w-7 h-7 text-soc-accent" />
        ) : (
          <ToggleLeft className="w-7 h-7 text-soc-dim" />
        )}
        <span className={on ? "text-soc-accent" : "text-soc-dim"}>
          {on ? "Habilitado" : "Deshabilitado"}
        </span>
      </button>
    );
  }

  if (def.type === "number") {
    return (
      <input
        type="number"
        value={value}
        min={def.min}
        max={def.max}
        step={def.step ?? 1}
        onChange={(e) => onChange(e.target.value)}
        className="w-40 rounded border border-soc-border bg-soc-card px-2 py-1 text-sm text-soc-text focus:outline-none focus:border-soc-accent"
      />
    );
  }

  return (
    <input
      type={def.type === "password" ? "password" : "text"}
      value={value}
      placeholder={def.placeholder ?? def.default}
      onChange={(e) => onChange(e.target.value)}
      className="w-full max-w-sm rounded border border-soc-border bg-soc-card px-2 py-1 text-sm text-soc-text focus:outline-none focus:border-soc-accent"
    />
  );
}

function SettingsGroup({
  defs,
  values,
  onChange,
}: {
  defs: SettingDef[];
  values: Record<string, string>;
  onChange: (key: string, val: string) => void;
}) {
  return (
    <div className="space-y-4">
      {defs.map((def) => (
        <div key={def.key} className="flex flex-col gap-1">
          <label className="text-xs font-medium text-soc-dim uppercase tracking-wide">
            {def.label}
          </label>
          <FieldInput
            def={def}
            value={values[def.key] ?? def.default}
            onChange={(v) => onChange(def.key, v)}
          />
          {def.help && (
            <p className="text-[11px] text-soc-dim opacity-70">{def.help}</p>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Schedule tab ─────────────────────────────────────────────

function ScheduleTab() {
  const [jobs, setJobs]           = useState<ScheduledJob[]>([]);
  const [auditTypes, setAuditTypes] = useState<Record<string, string>>({});
  const [loading, setLoading]     = useState(true);
  const [newType, setNewType]     = useState("");
  const [newInterval, setNewInterval] = useState(60);
  const [adding, setAdding]       = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await api.schedule();
      setJobs(r.jobs);
      setAuditTypes(r.audit_types);
      if (!newType && Object.keys(r.audit_types).length > 0) {
        setNewType(Object.keys(r.audit_types)[0]);
      }
    } finally {
      setLoading(false);
    }
  }, [newType]);

  useEffect(() => { load(); }, []);

  async function handleAdd() {
    if (!newType) return;
    setAdding(true);
    try {
      await api.addScheduleJob(newType, newInterval);
      await load();
    } finally {
      setAdding(false);
    }
  }

  async function handleToggle(id: number, enabled: boolean) {
    await api.toggleScheduleJob(id, !enabled);
    setJobs((prev) =>
      prev.map((j) => (j.id === id ? { ...j, enabled: !enabled } : j))
    );
  }

  async function handleDelete(id: number) {
    await api.deleteScheduleJob(id);
    setJobs((prev) => prev.filter((j) => j.id !== id));
  }

  if (loading) return <p className="text-soc-dim text-sm">Cargando...</p>;

  return (
    <div className="space-y-6">
      {/* Add job */}
      <div className="rounded-lg border border-soc-border bg-soc-card p-4 space-y-3">
        <p className="text-sm font-semibold text-soc-text">Nueva tarea programada</p>
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex flex-col gap-1">
            <label className="text-[11px] text-soc-dim">Tipo de auditoría</label>
            <select
              value={newType}
              onChange={(e) => setNewType(e.target.value)}
              className="rounded border border-soc-border bg-soc-surface px-2 py-1 text-sm text-soc-text"
            >
              {Object.entries(auditTypes).map(([k, v]) => (
                <option key={k} value={k}>{v}</option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[11px] text-soc-dim">Intervalo (minutos)</label>
            <input
              type="number"
              min={1}
              value={newInterval}
              onChange={(e) => setNewInterval(Number(e.target.value))}
              className="w-28 rounded border border-soc-border bg-soc-surface px-2 py-1 text-sm text-soc-text"
            />
          </div>
          <button
            onClick={handleAdd}
            disabled={adding}
            className="flex items-center gap-1.5 rounded bg-soc-accent/20 border border-soc-accent/40 px-3 py-1.5 text-sm text-soc-accent hover:bg-soc-accent/30 disabled:opacity-50"
          >
            <Plus className="w-4 h-4" />
            {adding ? "Agregando..." : "Agregar"}
          </button>
        </div>
      </div>

      {/* Job list */}
      {jobs.length === 0 ? (
        <p className="text-sm text-soc-dim">No hay tareas programadas.</p>
      ) : (
        <div className="space-y-2">
          {jobs.map((job) => (
            <div
              key={job.id}
              className="flex items-center justify-between rounded-lg border border-soc-border bg-soc-card px-4 py-3"
            >
              <div className="flex flex-col gap-0.5">
                <p className="text-sm font-medium text-soc-text">{job.label}</p>
                <p className="text-xs text-soc-dim">
                  Cada {job.interval_minutes} min
                  {job.last_run && (
                    <> · Última: {new Date(job.last_run).toLocaleString()}</>
                  )}
                  {job.next_run && (
                    <> · Próxima: {new Date(job.next_run).toLocaleString()}</>
                  )}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => handleToggle(job.id, job.enabled)}
                  title={job.enabled ? "Deshabilitar" : "Habilitar"}
                >
                  {job.enabled ? (
                    <ToggleRight className="w-6 h-6 text-soc-accent" />
                  ) : (
                    <ToggleLeft className="w-6 h-6 text-soc-dim" />
                  )}
                </button>
                <button
                  onClick={() => handleDelete(job.id)}
                  className="text-red-400 hover:text-red-300"
                  title="Eliminar"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Wazuh tab ─────────────────────────────────────────────────

function WazuhTab({
  values,
  onChange,
}: {
  values: Record<string, string>;
  onChange: (key: string, val: string) => void;
}) {
  const [copied, setCopied] = useState(false);
  const managerHost = values["WAZUH_MANAGER_HOST"] || "<IP_DEL_HOST>";
  const psCmd =
    `Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi" ` +
    `-OutFile $env:tmp\\wazuh.msi; ` +
    `msiexec /i $env:tmp\\wazuh.msi /q WAZUH_MANAGER="${managerHost}" WAZUH_AGENT_NAME="DC01"; ` +
    `NET START WazuhSvc`;

  function copyCmd() {
    navigator.clipboard.writeText(psCmd).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1">
        <label className="text-xs font-medium text-soc-dim uppercase tracking-wide">
          Wazuh Manager IP / Host
        </label>
        <input
          type="text"
          value={values["WAZUH_MANAGER_HOST"] ?? ""}
          placeholder="IP de tu host Docker (ej. 192.168.1.5)"
          onChange={(e) => onChange("WAZUH_MANAGER_HOST", e.target.value)}
          className="w-full max-w-sm rounded border border-soc-border bg-soc-card px-2 py-1 text-sm text-soc-text focus:outline-none focus:border-soc-accent"
        />
        <p className="text-[11px] text-soc-dim opacity-70">
          Dirección desde la que el agente Windows DC puede alcanzar el contenedor wazuh-manager.
        </p>
      </div>

      <div className="rounded-lg border border-soc-border bg-soc-card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <p className="text-sm font-semibold text-soc-text">
            Comando de instalación (PowerShell — DC Windows)
          </p>
          <div className="flex gap-2">
            <a
              href="https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 rounded border border-soc-border px-2 py-1 text-xs text-soc-dim hover:text-soc-text"
            >
              <Download className="w-3 h-3" />
              Descargar MSI
            </a>
            <button
              onClick={copyCmd}
              className="flex items-center gap-1 rounded border border-soc-border px-2 py-1 text-xs text-soc-dim hover:text-soc-text"
            >
              {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
              {copied ? "Copiado" : "Copiar"}
            </button>
          </div>
        </div>
        <pre className="rounded bg-soc-surface p-3 text-[11px] text-soc-text whitespace-pre-wrap break-all">
          {psCmd}
        </pre>
        <p className="text-[11px] text-soc-dim opacity-70">
          Ejecutar como Administrador en PowerShell del DC Windows. El agente se registrará automáticamente con el manager.
        </p>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────

export default function SettingsPage() {
  const [tab, setTab]       = useState<Tab>("ad");
  const [defs, setDefs]     = useState<SettingDef[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving]   = useState(false);
  const [saved, setSaved]     = useState(false);
  const [error, setError]     = useState("");

  useEffect(() => {
    api.settings().then((settings) => {
      setDefs(settings);
      const initial: Record<string, string> = {};
      for (const s of settings) {
        initial[s.key] = s.value ?? s.default;
      }
      setValues(initial);
      setLoading(false);
    });
  }, []);

  function handleChange(key: string, val: string) {
    setValues((prev) => ({ ...prev, [key]: val }));
    setSaved(false);
  }

  async function handleSave() {
    setSaving(true);
    setError("");
    try {
      await api.saveSettings(values);
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Error al guardar");
    } finally {
      setSaving(false);
    }
  }

  const byGroup = groupBy(defs, (d) => d.group);

  const TAB_GROUP_MAP: Record<Tab, string[]> = {
    "ad":          ["ad"],
    "rate":        ["rate"],
    "audit-flags": ["audit"],
    "schedule":    [],
    "wazuh":       ["wazuh"],
    "capture":     ["capture"],
  };

  const currentDefs = TAB_GROUP_MAP[tab]
    .flatMap((g) => byGroup[g] ?? []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-soc-dim text-sm">
        Cargando configuración...
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 p-6 max-w-3xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-soc-text">Configuración del Lab</h1>
          <p className="text-sm text-soc-dim mt-0.5">
            Todos los valores se persisten y se inyectan en las auditorías en tiempo real.
          </p>
        </div>
        {tab !== "schedule" && (
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-2 rounded bg-soc-accent/20 border border-soc-accent/40 px-4 py-2 text-sm font-medium text-soc-accent hover:bg-soc-accent/30 disabled:opacity-50 transition-colors"
          >
            {saving ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : saved ? (
              <Check className="w-4 h-4 text-green-400" />
            ) : (
              <Save className="w-4 h-4" />
            )}
            {saving ? "Guardando..." : saved ? "Guardado" : "Guardar cambios"}
          </button>
        )}
      </div>

      {error && (
        <div className="rounded border border-red-500/30 bg-red-500/10 px-4 py-2 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 border-b border-soc-border">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`px-4 py-2 text-sm transition-colors ${
              tab === id
                ? "border-b-2 border-soc-accent text-soc-accent font-medium"
                : "text-soc-dim hover:text-soc-text"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="rounded-lg border border-soc-border bg-soc-card p-5">
        {tab === "schedule" ? (
          <ScheduleTab />
        ) : tab === "wazuh" ? (
          <WazuhTab values={values} onChange={handleChange} />
        ) : (
          <SettingsGroup defs={currentDefs} values={values} onChange={handleChange} />
        )}
      </div>
    </div>
  );
}
