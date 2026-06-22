"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  FileSpreadsheet, Download, RefreshCw, Shield, Database,
  Users, Monitor, Network, AlertTriangle, Table, Key,
} from "lucide-react";

// ── Types (subset of the audit results payload) ──────────────────────────────

interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number; }

interface Stats {
  total_users: number; active_users: number; disabled_users: number;
  privileged_users: number; total_computers: number; domain_controllers: number;
  total_groups: number; ports_open: number; ports_filtered: number;
}

interface Finding {
  id: string; severity: string; category: string; title: string;
  description: string; recommendation: string; mitre: string;
}

interface Policy { domain?: string; objectSid?: string; }

interface Results {
  available: boolean; message?: string; timestamp: string; dump_dir: string;
  findings: Finding[]; severity_counts: SeverityCounts; stats: Stats;
  policy?: Policy; ports?: { port: number }[];
}

interface CrackedCred { user: string; password: string; }
interface AttackModule { run: boolean; hashes: number; cracked: CrackedCred[]; vulnerable_accounts: string[]; }
interface AttackResults {
  available: boolean; total_cracked: number;
  asrep: AttackModule; kerberoast: AttackModule;
}

// ── CSV helpers ──────────────────────────────────────────────────────────────
// Separador ';' + BOM UTF-8 → Excel en español abre el archivo correctamente
// (acentos y columnas separadas sin reconfigurar nada).

const SEP = ";";

function csvCell(value: unknown): string {
  const s = value == null ? "" : String(value);
  return /[";\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(rows: (string | number)[][]): string {
  return rows.map((r) => r.map(csvCell).join(SEP)).join("\r\n");
}

function downloadCsv(filename: string, content: string) {
  const blob = new Blob(["﻿" + content], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const SEV_LABEL: Record<string, string> = {
  critical: "CRÍTICO", high: "ALTO", medium: "MEDIO", low: "BAJO", info: "INFO",
};

// ── Page ─────────────────────────────────────────────────────────────────────

export default function ExportPage() {
  const [data, setData] = useState<Results | null>(null);
  const [attacks, setAttacks] = useState<AttackResults | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [r, a] = await Promise.all([
        fetch("/api/audit/results/latest", { cache: "no-store" }),
        fetch("/api/audit/results/attacks", { cache: "no-store" }),
      ]);
      setData(await r.json());
      setAttacks(await a.json());
    } catch {
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Filas del resumen (también es la fuente del CSV de resumen)
  const summaryRows = useMemo<{ metric: string; value: string | number }[]>(() => {
    if (!data?.available) return [];
    const sc = data.severity_counts;
    const st = data.stats;
    const totalRisk = sc.critical * 4 + sc.high * 3 + sc.medium * 2 + sc.low;
    const riskLabel =
      totalRisk === 0 ? "Bajo" : totalRisk < 5 ? "Moderado" : totalRisk < 12 ? "Alto" : "Crítico";

    return [
      { metric: "Dominio", value: data.policy?.domain ?? "—" },
      { metric: "Fecha de recolección", value: data.timestamp ?? "—" },
      { metric: "Nivel de riesgo del dominio", value: riskLabel },
      { metric: "Puntuación de riesgo", value: totalRisk },
      { metric: "Total de hallazgos", value: data.findings.length },
      { metric: "Hallazgos críticos", value: sc.critical },
      { metric: "Hallazgos altos", value: sc.high },
      { metric: "Hallazgos medios", value: sc.medium },
      { metric: "Hallazgos bajos", value: sc.low },
      { metric: "Hallazgos informativos", value: sc.info },
      { metric: "Usuarios totales", value: st.total_users },
      { metric: "Usuarios activos", value: st.active_users },
      { metric: "Usuarios deshabilitados", value: st.disabled_users },
      { metric: "Usuarios privilegiados", value: st.privileged_users },
      { metric: "Equipos totales", value: st.total_computers },
      { metric: "Domain Controllers", value: st.domain_controllers },
      { metric: "Grupos totales", value: st.total_groups },
      { metric: "Puertos abiertos", value: st.ports_open },
      { metric: "Puertos filtrados", value: st.ports_filtered },
      { metric: "Credenciales crackeadas", value: attacks?.total_cracked ?? 0 },
    ];
  }, [data, attacks]);

  const dateStr = () => new Date().toISOString().slice(0, 10);

  const exportSummaryCsv = () => {
    const rows: (string | number)[][] = [
      ["Métrica", "Valor"],
      ...summaryRows.map((r) => [r.metric, r.value]),
    ];
    downloadCsv(`RESUMEN_AD_${dateStr()}.csv`, toCsv(rows));
  };

  const exportFindingsCsv = () => {
    if (!data?.findings?.length) return;
    const rows: (string | number)[][] = [
      ["ID", "Severidad", "Categoría", "Título", "MITRE", "Recomendación", "Descripción"],
      ...data.findings.map((f) => [
        f.id,
        SEV_LABEL[f.severity] ?? f.severity,
        f.category,
        f.title,
        f.mitre,
        f.recommendation,
        f.description,
      ]),
    ];
    downloadCsv(`HALLAZGOS_AD_${dateStr()}.csv`, toCsv(rows));
  };

  // ── Loading / empty states ──────────────────────────────────────────────

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-soc-dim flex items-center gap-2">
          <RefreshCw size={16} className="animate-spin" /> Cargando datos para exportar…
        </div>
      </div>
    );
  }

  if (!data?.available) {
    return (
      <div className="max-w-2xl">
        <div className="bg-soc-card border border-soc-border rounded-xl p-8 text-center">
          <Database size={40} className="text-soc-dim mx-auto mb-3" />
          <p className="text-soc-text font-medium">Sin datos de auditoría para exportar</p>
          <p className="text-soc-dim text-sm mt-1">
            {data?.message ?? "Ejecuta una auditoría desde el panel de Auditoría AD."}
          </p>
          <a
            href="/audit"
            className="mt-4 inline-block bg-soc-purple/80 hover:bg-soc-purple text-white text-sm px-4 py-2 rounded-lg transition-colors"
          >
            Ir a Auditoría →
          </a>
        </div>
      </div>
    );
  }

  const sc = data.severity_counts;
  const st = data.stats;

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <FileSpreadsheet className="w-6 h-6 text-soc-purple" />
          <div>
            <h1 className="text-lg font-bold text-soc-text">Exportar</h1>
            <p className="text-xs text-soc-dim">
              Genera un resumen de la auditoría y descárgalo en CSV.
            </p>
          </div>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 text-sm bg-soc-card hover:bg-soc-muted/30 border border-soc-border text-soc-dim px-3 py-2 rounded-lg transition-colors"
        >
          <RefreshCw size={14} /> Actualizar
        </button>
      </div>

      {/* Quick metric chips */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: "Usuarios", value: st.total_users, icon: <Users size={16} />, color: "text-blue-400" },
          { label: "Equipos", value: st.total_computers, icon: <Monitor size={16} />, color: "text-cyan-400" },
          { label: "Grupos", value: st.total_groups, icon: <Network size={16} />, color: "text-indigo-400" },
          { label: "Hallazgos", value: data.findings.length, icon: <AlertTriangle size={16} />, color: "text-yellow-400" },
          { label: "Críticos", value: sc.critical, icon: <Shield size={16} />, color: "text-red-400" },
          { label: "Crackeadas", value: attacks?.total_cracked ?? 0, icon: <Key size={16} />, color: "text-orange-400" },
        ].map((m) => (
          <div key={m.label} className="bg-soc-card border border-soc-border rounded-lg p-3 text-center">
            <div className={`flex justify-center mb-1 ${m.color}`}>{m.icon}</div>
            <div className={`text-xl font-bold ${m.color}`}>{m.value}</div>
            <div className="text-xs text-soc-dim">{m.label}</div>
          </div>
        ))}
      </div>

      {/* Resumen box */}
      <div className="bg-soc-card border border-soc-border rounded-xl overflow-hidden">
        <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-soc-border">
          <div className="flex items-center gap-2">
            <Table size={16} className="text-soc-purple" />
            <h2 className="text-sm font-semibold text-soc-text">Resumen de la auditoría</h2>
          </div>
          <button
            onClick={exportSummaryCsv}
            className="flex items-center gap-2 text-sm bg-soc-purple/80 hover:bg-soc-purple text-white px-3 py-1.5 rounded-lg transition-colors"
          >
            <Download size={14} /> Resumen (CSV)
          </button>
        </div>
        <dl className="divide-y divide-soc-border/50">
          {summaryRows.map((row) => (
            <div key={row.metric} className="flex justify-between items-center gap-4 px-4 py-2 text-sm">
              <dt className="text-soc-dim">{row.metric}</dt>
              <dd className="font-medium text-soc-text text-right">{row.value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Findings export */}
      <div className="bg-soc-card border border-soc-border rounded-xl p-4 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h2 className="text-sm font-semibold text-soc-text flex items-center gap-2">
            <AlertTriangle size={16} className="text-yellow-400" />
            Hallazgos detallados
          </h2>
          <p className="text-xs text-soc-dim mt-1">
            {data.findings.length} hallazgos con severidad, categoría, MITRE ATT&amp;CK y recomendación.
          </p>
        </div>
        <button
          onClick={exportFindingsCsv}
          disabled={data.findings.length === 0}
          className="flex items-center gap-2 text-sm bg-soc-card hover:bg-soc-muted/30 disabled:opacity-40 disabled:cursor-not-allowed border border-soc-border text-soc-text px-3 py-2 rounded-lg transition-colors"
        >
          <Download size={14} /> Hallazgos (CSV)
        </button>
      </div>
    </div>
  );
}
