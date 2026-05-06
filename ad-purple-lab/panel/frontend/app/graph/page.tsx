"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import dynamic from "next/dynamic";
import {
  Search,
  Play,
  RefreshCw,
  Table2,
  Share2,
  AlertTriangle,
  ChevronRight,
  Copy,
  Terminal,
  Clock,
  Users,
  Shield,
  Server,
  Skull,
  Key,
} from "lucide-react";
import { api, type QueryDef, type QueryResult, type Neo4jStats } from "@/lib/api";
import { cn } from "@/lib/utils";

// Load GraphCanvas only on client (canvas API)
const GraphCanvas = dynamic(
  () => import("@/components/graph/GraphCanvas"),
  { ssr: false, loading: () => <CanvasPlaceholder text="Cargando visualizador…" /> },
);

// ── Risk badge ─────────────────────────────────────────────────────────────

const RISK_STYLE: Record<string, string> = {
  critical: "bg-red-900/40 text-red-400 border border-red-800",
  high:     "bg-orange-900/40 text-orange-400 border border-orange-800",
  medium:   "bg-yellow-900/40 text-yellow-400 border border-yellow-800",
  low:      "bg-green-900/40 text-green-400 border border-green-800",
  info:     "bg-blue-900/40 text-blue-400 border border-blue-800",
};

const RISK_LABEL: Record<string, string> = {
  critical: "CRÍTICO",
  high:     "ALTO",
  medium:   "MEDIO",
  low:      "BAJO",
  info:     "INFO",
};

function RiskBadge({ risk }: { risk: string }) {
  return (
    <span className={cn("text-[9px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wider", RISK_STYLE[risk] ?? RISK_STYLE.info)}>
      {RISK_LABEL[risk] ?? risk}
    </span>
  );
}

// ── Stat card ──────────────────────────────────────────────────────────────

function StatCard({
  label, value, icon: Icon, color, sub,
}: {
  label: string;
  value: number | null | undefined;
  icon:  React.ElementType;
  color: string;
  sub?:  string;
}) {
  return (
    <div className="bg-soc-card border border-soc-border rounded-lg p-3 flex items-center gap-3">
      <div className={cn("p-2 rounded-lg", color + "/10")}>
        <Icon className={cn("w-4 h-4", color)} />
      </div>
      <div className="min-w-0">
        <p className="text-xl font-bold text-soc-text font-mono leading-none">
          {value === null || value === undefined ? "—" : value}
        </p>
        <p className="text-[11px] text-soc-dim leading-tight mt-0.5">{label}</p>
        {sub && <p className="text-[9px] text-soc-dim opacity-60">{sub}</p>}
      </div>
    </div>
  );
}

// ── Canvas placeholder ─────────────────────────────────────────────────────

function CanvasPlaceholder({ text }: { text: string }) {
  return (
    <div className="flex items-center justify-center h-full text-soc-dim text-sm font-mono">
      {text}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function GraphExplorerPage() {
  const [queries,    setQueries]    = useState<QueryDef[]>([]);
  const [stats,      setStats]      = useState<Neo4jStats | null>(null);
  const [selected,   setSelected]   = useState<QueryDef | null>(null);
  const [params,     setParams]     = useState<Record<string, string>>({});
  const [result,     setResult]     = useState<QueryResult | null>(null);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState<string | null>(null);
  const [tab,        setTab]        = useState<"table" | "graph">("table");
  const [catFilter,  setCatFilter]  = useState("All");
  const [riskFilter, setRiskFilter] = useState("All");
  const [copied,     setCopied]     = useState(false);
  const [statsErr,   setStatsErr]   = useState(false);

  // Load catalog + stats on mount
  useEffect(() => {
    api.neo4jQueries()
      .then((q) => {
        setQueries(q);
        if (q.length > 0) setSelected(q[0]);
      })
      .catch(() => setError("No se pudo cargar el catálogo de queries."));

    api.neo4jStats()
      .then(setStats)
      .catch(() => setStatsErr(true));
  }, []);

  // Reset params when query changes
  useEffect(() => {
    setParams({});
    setResult(null);
    setError(null);
  }, [selected]);

  const execute = useCallback(async () => {
    if (!selected) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.neo4jExecute(selected.id, params);
      setResult(res);
      setTab(res.has_graph ? "graph" : "table");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [selected, params]);

  // Keyboard shortcut: Ctrl+Enter
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") execute();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [execute]);

  const copyQuery = () => {
    if (!selected) return;
    navigator.clipboard.writeText(selected.cypher);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  // ── Derived ─────────────────────────────────────────────────────────────

  const categories = ["All", ...Array.from(new Set(queries.map((q) => q.category)))];
  const risks      = ["All", "critical", "high", "medium", "low", "info"];

  const filtered = queries.filter(
    (q) =>
      (catFilter  === "All" || q.category === catFilter) &&
      (riskFilter === "All" || q.risk === riskFilter),
  );

  const s = stats?.stats ?? {};

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full gap-4 min-h-0">

      {/* ── Header ─────────────────────────────────────────────── */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <Share2 className="w-5 h-5 text-soc-purple" />
          <h1 className="text-lg font-bold text-soc-text">Graph Explorer</h1>
          <span className="text-[10px] text-soc-dim font-mono bg-soc-card border border-soc-border px-1.5 py-0.5 rounded">
            Neo4j / BloodHound
          </span>
          {!stats?.connected && !statsErr && (
            <span className="text-[10px] text-yellow-400 font-mono">⚠ Conectando…</span>
          )}
          {statsErr && (
            <span className="text-[10px] text-red-400 font-mono">⚠ Neo4j no disponible</span>
          )}
        </div>
        <p className="text-xs text-soc-dim">
          Queries Cypher predefinidas para análisis de Active Directory · Ctrl+Enter para ejecutar
        </p>
      </div>

      {/* ── Stats cards ────────────────────────────────────────── */}
      <div className="grid grid-cols-4 gap-3 shrink-0">
        <StatCard label="Usuarios totales"   value={s.total_users}    icon={Users}  color="text-indigo-400" />
        <StatCard label="Deshabilitados"     value={s.disabled_users} icon={Shield} color="text-yellow-400" />
        <StatCard label="Sin contraseña"     value={s.no_pwd_users}   icon={Skull}  color="text-red-400"    sub="PASSWD_NOTREQD" />
        <StatCard label="Kerberoasteables"   value={s.kerberoastable} icon={Key}    color="text-orange-400" />
        <StatCard label="AS-REP Roastables"  value={s.asrep_roast}    icon={Key}    color="text-orange-400" sub="no pre-auth" />
        <StatCard label="Computadoras"       value={s.total_computers} icon={Server} color="text-emerald-400" />
        <StatCard label="Grupos"             value={s.total_groups}   icon={Users}  color="text-purple-400" />
        <StatCard label="OS Legado (EOL)"    value={s.legacy_os}      icon={AlertTriangle} color="text-red-400" />
      </div>

      {/* ── Main workspace ─────────────────────────────────────── */}
      <div className="flex gap-4 flex-1 min-h-0">

        {/* ── Left: query selector ─────────────────────────────── */}
        <div className="w-72 shrink-0 flex flex-col gap-3 min-h-0">

          {/* Filters */}
          <div className="flex gap-2">
            <select
              value={catFilter}
              onChange={(e) => setCatFilter(e.target.value)}
              className="flex-1 text-[11px] bg-soc-card border border-soc-border rounded px-2 py-1.5 text-soc-text focus:outline-none focus:border-soc-purple"
            >
              {categories.map((c) => <option key={c}>{c}</option>)}
            </select>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="text-[11px] bg-soc-card border border-soc-border rounded px-2 py-1.5 text-soc-text focus:outline-none focus:border-soc-purple"
            >
              {risks.map((r) => <option key={r} value={r}>{r === "All" ? "Riesgo" : RISK_LABEL[r]}</option>)}
            </select>
          </div>

          {/* Query list */}
          <div className="flex-1 overflow-y-auto space-y-0.5 min-h-0 pr-0.5">
            {filtered.map((q) => (
              <button
                key={q.id}
                onClick={() => setSelected(q)}
                className={cn(
                  "w-full text-left px-2.5 py-2 rounded text-[11px] transition-colors",
                  selected?.id === q.id
                    ? "bg-soc-purple/10 border border-soc-purple/30 text-soc-text"
                    : "text-soc-dim hover:text-soc-text hover:bg-soc-card border border-transparent",
                )}
              >
                <div className="flex items-center gap-1.5 mb-0.5">
                  <ChevronRight className="w-3 h-3 shrink-0 opacity-50" />
                  <span className="font-medium truncate">{q.title}</span>
                </div>
                <div className="flex items-center gap-1.5 ml-4.5">
                  <RiskBadge risk={q.risk} />
                  <span className="text-[9px] text-soc-dim opacity-60">{q.category}</span>
                  {q.schema === "bloodhound" && (
                    <span className="text-[9px] text-violet-400 opacity-70">BH</span>
                  )}
                </div>
              </button>
            ))}
            {filtered.length === 0 && (
              <p className="text-center text-soc-dim text-[11px] py-4">Sin resultados</p>
            )}
          </div>

          {/* Query detail + params */}
          {selected && (
            <div className="shrink-0 space-y-2 border-t border-soc-border pt-2">
              <div>
                <p className="text-[11px] font-semibold text-soc-text">{selected.title}</p>
                <p className="text-[10px] text-soc-dim mt-0.5 leading-snug">{selected.description}</p>
              </div>

              {/* Params */}
              {selected.params.map((p) => (
                <div key={p.name}>
                  <label className="text-[10px] text-soc-dim block mb-0.5">
                    {p.label}{p.required && <span className="text-red-400 ml-0.5">*</span>}
                  </label>
                  <input
                    type="text"
                    placeholder={p.placeholder}
                    value={params[p.name] ?? ""}
                    onChange={(e) => setParams((prev) => ({ ...prev, [p.name]: e.target.value }))}
                    onKeyDown={(e) => e.key === "Enter" && execute()}
                    className="w-full text-[11px] bg-soc-bg border border-soc-border rounded px-2 py-1.5 text-soc-text font-mono placeholder-soc-dim/40 focus:outline-none focus:border-soc-purple"
                  />
                </div>
              ))}

              {/* Execute button */}
              <button
                onClick={execute}
                disabled={loading}
                className={cn(
                  "w-full flex items-center justify-center gap-2 py-2 rounded text-sm font-semibold transition-colors",
                  loading
                    ? "bg-soc-purple/30 text-soc-purple cursor-wait"
                    : "bg-soc-purple text-white hover:bg-purple-600 active:scale-95",
                )}
              >
                {loading ? (
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                {loading ? "Ejecutando…" : "Ejecutar"}
              </button>

              {/* Cypher preview */}
              <div className="relative group">
                <pre className="text-[9px] font-mono text-soc-dim bg-soc-bg border border-soc-border rounded p-2 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                  {selected.cypher}
                </pre>
                <button
                  onClick={copyQuery}
                  className="absolute top-1.5 right-1.5 opacity-0 group-hover:opacity-100 transition-opacity"
                  title="Copiar query"
                >
                  <Copy className={cn("w-3 h-3", copied ? "text-green-400" : "text-soc-dim")} />
                </button>
              </div>
            </div>
          )}
        </div>

        {/* ── Right: results ───────────────────────────────────── */}
        <div className="flex-1 flex flex-col min-h-0 min-w-0">

          {/* Error */}
          {error && (
            <div className="mb-3 flex items-start gap-2 bg-red-900/20 border border-red-800 rounded-lg p-3 text-red-400 text-xs font-mono">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span className="break-all">{error}</span>
            </div>
          )}

          {/* Empty state */}
          {!result && !loading && !error && (
            <div className="flex-1 flex flex-col items-center justify-center text-soc-dim gap-3">
              <Terminal className="w-10 h-10 opacity-20" />
              <div className="text-center">
                <p className="text-sm font-medium">Selecciona una query y ejecuta</p>
                <p className="text-xs opacity-60 mt-1">Ctrl+Enter para ejecutar rápidamente</p>
              </div>
            </div>
          )}

          {/* Results */}
          {result && (
            <div className="flex-1 flex flex-col min-h-0">
              {/* Result header */}
              <div className="flex items-center gap-3 mb-3 shrink-0">
                <div className="flex items-center gap-2 border border-soc-border rounded overflow-hidden">
                  <button
                    onClick={() => setTab("table")}
                    className={cn(
                      "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors",
                      tab === "table" ? "bg-soc-purple text-white" : "text-soc-dim hover:text-soc-text",
                    )}
                  >
                    <Table2 className="w-3 h-3" /> Tabla
                  </button>
                  <button
                    onClick={() => setTab("graph")}
                    disabled={!result.has_graph}
                    className={cn(
                      "flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors",
                      tab === "graph" ? "bg-soc-purple text-white" : "text-soc-dim hover:text-soc-text",
                      !result.has_graph && "opacity-30 cursor-not-allowed",
                    )}
                  >
                    <Share2 className="w-3 h-3" /> Grafo
                    {!result.has_graph && <span className="text-[9px]">(sin nodos)</span>}
                  </button>
                </div>

                <div className="flex items-center gap-1.5 text-xs text-soc-dim">
                  <Clock className="w-3 h-3" />
                  <span className="font-mono">{result.count} resultado{result.count !== 1 ? "s" : ""}</span>
                  {result.has_graph && (
                    <span className="font-mono">
                      · {result.graph.nodes.length} nodos · {result.graph.edges.length} rels
                    </span>
                  )}
                </div>

                <p className="ml-auto text-xs text-soc-dim font-mono truncate">{result.title}</p>
              </div>

              {/* Table view */}
              {tab === "table" && (
                <div className="flex-1 overflow-auto min-h-0 rounded-lg border border-soc-border">
                  {result.rows.length === 0 ? (
                    <div className="flex items-center justify-center h-full text-soc-dim text-sm">
                      Sin resultados para esta consulta
                    </div>
                  ) : (
                    <table className="w-full text-xs font-mono border-collapse">
                      <thead className="sticky top-0 bg-soc-surface z-10">
                        <tr>
                          {result.columns.map((col) => (
                            <th
                              key={col}
                              className="text-left px-3 py-2 text-soc-dim border-b border-soc-border font-semibold uppercase tracking-wider text-[10px]"
                            >
                              {col}
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {result.rows.map((row, i) => (
                          <tr
                            key={i}
                            className="border-b border-soc-border/50 hover:bg-soc-card/50 transition-colors"
                          >
                            {result.columns.map((col) => {
                              const val = row[col];
                              const str = val === null || val === undefined ? "" : String(val);
                              const isFlag = str === "true";
                              const isFalse = str === "false";
                              const isDanger =
                                col.includes("pwd_not_req") ||
                                col.includes("no_preauth") ||
                                col.includes("no_expire");
                              return (
                                <td
                                  key={col}
                                  className={cn(
                                    "px-3 py-1.5 text-soc-text max-w-[200px] truncate",
                                    isFlag && isDanger && "text-red-400 font-bold",
                                    isFlag && !isDanger && "text-green-400",
                                    isFalse && "text-soc-dim",
                                  )}
                                  title={str}
                                >
                                  {str}
                                </td>
                              );
                            })}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {/* Graph view */}
              {tab === "graph" && (
                <div className="flex-1 min-h-0 rounded-lg border border-soc-border bg-soc-bg overflow-hidden">
                  <GraphCanvas
                    nodes={result.graph.nodes}
                    edges={result.graph.edges}
                  />
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
