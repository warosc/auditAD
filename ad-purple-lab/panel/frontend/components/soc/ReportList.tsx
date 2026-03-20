"use client";

import { api, type Report } from "@/lib/api";
import { formatDate, cn } from "@/lib/utils";
import { Download, FileText, Archive, Search } from "lucide-react";
import { useState } from "react";

const TYPE_COLOR: Record<string, string> = {
  audit:      "text-purple-400 bg-purple-400/10 border-purple-400/20",
  bloodhound: "text-red-400 bg-red-400/10 border-red-400/20",
  ldap:       "text-blue-400 bg-blue-400/10 border-blue-400/20",
  dns:        "text-green-400 bg-green-400/10 border-green-400/20",
  nmap:       "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
  export:     "text-orange-400 bg-orange-400/10 border-orange-400/20",
  report:     "text-gray-400 bg-gray-400/10 border-gray-400/20",
};

interface Props {
  reports: Report[];
  onRefresh: () => void;
}

export function ReportList({ reports, onRefresh }: Props) {
  const [filter, setFilter] = useState("");
  const [exporting, setExporting] = useState(false);

  const filtered = reports.filter(
    (r) =>
      r.filename.toLowerCase().includes(filter.toLowerCase()) ||
      r.type.toLowerCase().includes(filter.toLowerCase())
  );

  const handleExport = async () => {
    setExporting(true);
    try {
      const response = await fetch("/api/audit/export", { method: "POST" });
      if (!response.body) return;

      const reader  = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const text = decoder.decode(value);
        // Find done event
        if (text.includes('"done":true')) {
          onRefresh();
          break;
        }
      }
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-3">
      {/* Toolbar */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-soc-dim" />
          <input
            type="text"
            placeholder="Filtrar reportes…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs rounded border border-soc-border bg-soc-surface text-soc-text placeholder:text-soc-dim focus:outline-none focus:border-soc-accent"
          />
        </div>

        <button
          onClick={handleExport}
          disabled={exporting}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold bg-orange-500/20 text-orange-400 border border-orange-500/30 hover:bg-orange-500/30 disabled:opacity-50 transition-colors"
        >
          <Archive className="w-3.5 h-3.5" />
          {exporting ? "Exportando…" : "Export All"}
        </button>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-soc-border overflow-hidden">
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-soc-border bg-soc-surface/60">
              {["Archivo", "Tipo", "Tamaño", "Creado", ""].map((h) => (
                <th
                  key={h}
                  className="px-4 py-2.5 text-left font-semibold text-soc-dim uppercase tracking-wide text-[10px]"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-soc-dim">
                  {reports.length === 0
                    ? "No hay reportes. Ejecuta una auditoría primero."
                    : "Sin resultados para el filtro actual."}
                </td>
              </tr>
            ) : (
              filtered.map((r, i) => (
                <tr
                  key={r.path}
                  className={cn(
                    "border-b border-soc-border/50 hover:bg-soc-muted/10 transition-colors",
                    i % 2 === 0 ? "bg-soc-card" : "bg-soc-surface/30"
                  )}
                >
                  <td className="px-4 py-2.5 font-mono text-soc-text">
                    <div className="flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5 text-soc-dim shrink-0" />
                      <span className="truncate max-w-[280px]" title={r.filename}>
                        {r.filename}
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={cn(
                        "inline-block px-1.5 py-0.5 rounded border text-[10px] font-bold uppercase",
                        TYPE_COLOR[r.type] ?? TYPE_COLOR.report
                      )}
                    >
                      {r.type}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-soc-dim font-mono">{r.size_human}</td>
                  <td className="px-4 py-2.5 text-soc-dim">{formatDate(r.created)}</td>
                  <td className="px-4 py-2.5">
                    <a
                      href={api.downloadUrl(r.filename)}
                      download={r.filename}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium bg-soc-muted/20 text-soc-dim hover:text-soc-text hover:bg-soc-muted/40 transition-colors"
                    >
                      <Download className="w-3 h-3" />
                      Download
                    </a>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        <div className="px-4 py-2 bg-soc-surface/50 border-t border-soc-border text-[10px] text-soc-dim">
          {filtered.length} / {reports.length} archivos
        </div>
      </div>
    </div>
  );
}
