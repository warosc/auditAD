"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import dynamic from "next/dynamic";
import {
  FolderOpen, Upload, Copy, Check, Database, RefreshCw,
  ChevronRight, ChevronDown, Play, Trash2, AlertTriangle,
  Shield, Link2, Network, Filter,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { GraphNode, GraphEdge, QueryDef, QueryResult } from "@/lib/api";
import { neo4jQueries, neo4jExecute } from "@/lib/api";

const GraphCanvas = dynamic(() => import("@/components/graph/GraphCanvas"), { ssr: false });

// ── PowerShell scripts ─────────────────────────────────────────────────────

const PS_EXTRACT = `# Script 1 — Extract-NTFS.ps1
# Extrae ACLs NTFS de todas las carpetas bajo una ruta raíz.
# Ejecutar como Administrador en el servidor de archivos.
# Resultado: NTFS_Permissions.csv

param(
    [string]$RootPath = "C:\\Shares",
    [int]   $Depth    = 3
)

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

# Raíz misma
try {
    $acl = Get-Acl -Path $RootPath -ErrorAction Stop
    foreach ($ace in $acl.Access) {
        $results.Add([PSCustomObject]@{
            Folder    = $RootPath
            Identity  = $ace.IdentityReference.Value
            Rights    = $ace.FileSystemRights.ToString()
            Type      = $ace.AccessControlType.ToString()
            Inherited = $ace.IsInherited.ToString()
        })
    }
} catch { }

# Subdirectorios
Get-ChildItem -Path $RootPath -Recurse -Directory -Depth $Depth \\
    -ErrorAction SilentlyContinue | ForEach-Object {
    $folder = $_.FullName
    try {
        $acl = Get-Acl -Path $folder -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            $results.Add([PSCustomObject]@{
                Folder    = $folder
                Identity  = $ace.IdentityReference.Value
                Rights    = $ace.FileSystemRights.ToString()
                Type      = $ace.AccessControlType.ToString()
                Inherited = $ace.IsInherited.ToString()
            })
        }
    } catch { }
}

$results | Export-Csv -Path ".\\NTFS_Permissions.csv" \\
    -NoTypeInformation -Encoding UTF8
Write-Host "Exportadas $($results.Count) ACEs → NTFS_Permissions.csv"`;

const PS_EXPAND = `# Script 2 — Expand-Groups.ps1
# Lee NTFS_Permissions.csv y expande grupos a usuarios individuales.
# Requiere RSAT / módulo ActiveDirectory.
# Ejecutar como Administrador en equipo unido al dominio.
# Resultado: NTFS_User_Effective.csv

#Requires -Modules ActiveDirectory

$rows    = Import-Csv ".\\NTFS_Permissions.csv"
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$cache   = @{}

foreach ($row in $rows) {
    $raw      = $row.Identity
    $identity = ($raw -replace '^.*\\\\', '').Trim()   # strip domain prefix

    if (-not $cache.ContainsKey($identity)) {
        try {
            $obj = Get-ADObject -Filter { SamAccountName -eq $identity } \\
                   -Properties ObjectClass -ErrorAction Stop
            $cache[$identity] = $obj.ObjectClass
        } catch {
            $cache[$identity] = "unknown"
        }
    }

    if ($cache[$identity] -eq "group") {
        try {
            Get-ADGroupMember -Identity $identity -Recursive -ErrorAction Stop |
            ForEach-Object {
                $results.Add([PSCustomObject]@{
                    User      = $_.SamAccountName
                    Folder    = $row.Folder
                    Rights    = $row.Rights
                    Type      = $row.Type
                    Inherited = $row.Inherited
                    Via       = $identity
                })
            }
        } catch { }
    } else {
        $results.Add([PSCustomObject]@{
            User      = $identity
            Folder    = $row.Folder
            Rights    = $row.Rights
            Type      = $row.Type
            Inherited = $row.Inherited
            Via       = ""
        })
    }
}

$results | Export-Csv -Path ".\\NTFS_User_Effective.csv" \\
    -NoTypeInformation -Encoding UTF8
Write-Host "Exportadas $($results.Count) permisos efectivos → NTFS_User_Effective.csv"`;

// ── Helpers ────────────────────────────────────────────────────────────────

const RISK_BADGE: Record<string, string> = {
  critical: "bg-red-900/60 text-red-300 border border-red-700",
  high:     "bg-orange-900/60 text-orange-300 border border-orange-700",
  medium:   "bg-yellow-900/60 text-yellow-300 border border-yellow-700",
  low:      "bg-green-900/60 text-green-300 border border-green-700",
  info:     "bg-blue-900/60 text-blue-300 border border-blue-700",
};

const RISK_LABEL: Record<string, string> = {
  critical: "CRÍTICO", high: "ALTO", medium: "MEDIO", low: "BAJO", info: "INFO",
};

function RiskBadge({ risk }: { risk: string }) {
  return (
    <span className={cn("px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider shrink-0", RISK_BADGE[risk] ?? RISK_BADGE.info)}>
      {RISK_LABEL[risk] ?? risk}
    </span>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
      className="flex items-center gap-1 text-[10px] text-soc-dim hover:text-soc-text transition-colors"
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
      {copied ? "Copiado" : "Copiar"}
    </button>
  );
}

function ScriptBlock({ label, code }: { label: string; code: string }) {
  return (
    <div className="rounded border border-soc-border overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 bg-soc-surface border-b border-soc-border">
        <span className="text-[11px] font-mono text-soc-accent">{label}</span>
        <CopyButton text={code} />
      </div>
      <pre className="text-[10px] font-mono text-green-300 bg-[#080810] px-3 py-2 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-[320px] overflow-y-auto">
        {code}
      </pre>
    </div>
  );
}

// ── Status card ────────────────────────────────────────────────────────────

interface NtfsStatus { connected: boolean; folders: number; has_access_rels: number; error?: string; }

function StatusBar({ status, onRefresh }: { status: NtfsStatus | null; onRefresh: () => void }) {
  if (!status) return null;
  return (
    <div className={cn(
      "flex items-center gap-4 px-3 py-2 rounded border text-[11px] font-mono",
      status.connected ? "border-green-800 bg-green-950/30 text-green-300" : "border-red-800 bg-red-950/30 text-red-400",
    )}>
      <Database className="w-3.5 h-3.5 shrink-0" />
      {status.connected ? (
        <>
          <span>Neo4j <span className="text-green-400 font-bold">conectado</span></span>
          <span className="text-soc-dim">·</span>
          <span><span className="text-orange-300 font-bold">{status.folders.toLocaleString()}</span> Folder</span>
          <span className="text-soc-dim">·</span>
          <span><span className="text-blue-300 font-bold">{status.has_access_rels.toLocaleString()}</span> HAS_ACCESS</span>
        </>
      ) : (
        <span>Neo4j desconectado: {status.error}</span>
      )}
      <button onClick={onRefresh} className="ml-auto hover:text-white transition-colors">
        <RefreshCw className="w-3 h-3" />
      </button>
    </div>
  );
}

// ── Query list ─────────────────────────────────────────────────────────────

function QueryItem({
  q, selected, onSelect,
}: { q: QueryDef; selected: boolean; onSelect: () => void }) {
  return (
    <button
      onClick={onSelect}
      className={cn(
        "w-full text-left px-2.5 py-2 rounded border text-[11px] transition-colors",
        selected
          ? "border-soc-accent/50 bg-soc-accent/10 text-soc-accent"
          : "border-soc-border bg-soc-card hover:border-soc-accent/30 hover:text-soc-text text-soc-dim",
      )}
    >
      <div className="flex items-start gap-2">
        <RiskBadge risk={q.risk} />
        <span className="font-semibold leading-tight">{q.title}</span>
      </div>
      <p className="mt-0.5 text-[10px] text-soc-dim leading-tight line-clamp-2">{q.description}</p>
    </button>
  );
}

// ── Result table ───────────────────────────────────────────────────────────

const DANGER_CELLS = new Set(["true", "fullcontrol", "modify", "write", "genericsall"]);

function ResultTable({ columns, rows }: { columns: string[]; rows: Record<string, unknown>[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-[10.5px] font-mono border-collapse">
        <thead>
          <tr className="border-b border-soc-border">
            {columns.map(c => (
              <th key={c} className="px-2 py-1.5 text-left text-[10px] text-soc-dim uppercase tracking-wider whitespace-nowrap">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-soc-border/40 hover:bg-soc-card/50">
              {columns.map(c => {
                const val = String(row[c] ?? "");
                const isDanger = DANGER_CELLS.has(val.toLowerCase()) || val.toLowerCase().includes("fullcontrol");
                return (
                  <td
                    key={c}
                    className={cn("px-2 py-1.5 max-w-[240px] truncate", isDanger ? "text-red-400 font-bold" : "text-soc-text")}
                    title={val}
                  >
                    {val || <span className="text-soc-dim/40">—</span>}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

type MainTab = "scripts" | "import" | "queries";
type ResultTab = "table" | "graph";

export default function NtfsAnalysis() {
  const [mainTab, setMainTab] = useState<MainTab>("scripts");
  const [ntfsStatus, setNtfsStatus] = useState<NtfsStatus | null>(null);
  const [importing, setImporting]   = useState(false);
  const [importMsg, setImportMsg]   = useState<{ ok: boolean; msg: string } | null>(null);
  const [queries, setQueries]       = useState<QueryDef[]>([]);
  const [selected, setSelected]     = useState<QueryDef | null>(null);
  const [params, setParams]         = useState<Record<string, string>>({});
  const [running, setRunning]       = useState(false);
  const [result, setResult]         = useState<QueryResult | null>(null);
  const [resultTab, setResultTab]   = useState<ResultTab>("table");
  const [riskFilter, setRiskFilter] = useState("all");
  const [purging, setPurging]       = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const fetchStatus = useCallback(async () => {
    try {
      const r = await fetch("/api/ntfs/status");
      if (r.ok) setNtfsStatus(await r.json());
    } catch {}
  }, []);

  const fetchQueries = useCallback(async () => {
    try {
      const data = await neo4jQueries();
      setQueries(data.filter(q => q.category === "NTFS / File Server"));
    } catch {}
  }, []);

  useEffect(() => {
    fetchStatus();
    fetchQueries();
  }, [fetchStatus, fetchQueries]);

  // ── Import ────────────────────────────────────────────────────────────────

  const onImport = useCallback(async (files: FileList | null) => {
    if (!files || !files.length) return;
    const file = files[0];
    if (!file.name.toLowerCase().endsWith(".csv")) {
      setImportMsg({ ok: false, msg: "Selecciona un archivo .csv" });
      return;
    }
    setImporting(true);
    setImportMsg(null);
    const fd = new FormData();
    fd.append("file", file);
    try {
      const res = await fetch("/api/ntfs/import", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok) {
        setImportMsg({ ok: false, msg: data.detail || `Error ${res.status}` });
      } else {
        setImportMsg({
          ok: true,
          msg: `Importado: ${data.rows_parsed} filas, ${data.folders} carpetas, ${data.relationships} relaciones HAS_ACCESS`,
        });
        fetchStatus();
      }
    } catch (e: unknown) {
      setImportMsg({ ok: false, msg: e instanceof Error ? e.message : String(e) });
    } finally {
      setImporting(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }, [fetchStatus]);

  const doPurge = useCallback(async () => {
    if (!confirm("¿Eliminar todos los nodos Folder y relaciones HAS_ACCESS de Neo4j?")) return;
    setPurging(true);
    try {
      await fetch("/api/ntfs/purge", { method: "DELETE" });
      fetchStatus();
      setImportMsg({ ok: true, msg: "Datos NTFS eliminados de Neo4j" });
    } catch {}
    setPurging(false);
  }, [fetchStatus]);

  // ── Query execution ───────────────────────────────────────────────────────

  const runQuery = useCallback(async () => {
    if (!selected) return;
    setRunning(true);
    try {
      const res = await neo4jExecute(selected.id, params);
      setResult(res);
      setResultTab(res.has_graph ? "graph" : "table");
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }, [selected, params]);

  const onSelectQuery = (q: QueryDef) => {
    setSelected(q);
    setParams({});
    setResult(null);
  };

  const filteredQueries = queries.filter(q => riskFilter === "all" || q.risk === riskFilter);

  // ── Render ────────────────────────────────────────────────────────────────

  const mainTabs: { id: MainTab; label: string; icon: React.ElementType }[] = [
    { id: "scripts", label: "Scripts PowerShell", icon: Copy },
    { id: "import",  label: "Importar en Neo4j",  icon: Database },
    { id: "queries", label: `Consultas NTFS (${queries.length})`, icon: Network },
  ];

  return (
    <div className="flex flex-col h-full font-mono overflow-hidden">

      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-soc-border shrink-0">
        <Network className="w-4 h-4 text-orange-400" />
        <span className="text-sm font-semibold text-soc-text">NTFS File Server Analysis — Neo4j</span>
        <span className="ml-auto text-[10px] text-soc-dim px-2 py-0.5 rounded bg-orange-950/40 border border-orange-800 text-orange-300">
          IAM + File Server
        </span>
      </div>

      {/* Main tabs */}
      <div className="flex gap-1 px-4 pt-2 border-b border-soc-border shrink-0">
        {mainTabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setMainTab(id)}
            className={cn(
              "flex items-center gap-1.5 px-3 py-1.5 rounded-t text-[11px] transition-colors",
              mainTab === id
                ? "bg-soc-accent/10 text-soc-accent border border-b-0 border-soc-accent/30"
                : "text-soc-dim hover:text-soc-text",
            )}
          >
            <Icon className="w-3 h-3" />
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-4 py-3">

        {/* ── Scripts tab ── */}
        {mainTab === "scripts" && (
          <div className="space-y-4">
            <div className="rounded border border-blue-800 bg-blue-950/30 px-3 py-2 text-[12px] text-blue-300 leading-relaxed">
              <strong>Flujo de extracción:</strong>
              <ol className="list-decimal list-inside mt-1 space-y-0.5 text-[11px]">
                <li>Ejecuta <strong>Script 1</strong> en el servidor de archivos → genera <code>NTFS_Permissions.csv</code></li>
                <li>Ejecuta <strong>Script 2</strong> en un equipo con RSAT → genera <code>NTFS_User_Effective.csv</code></li>
                <li>Ve a <strong>"Importar en Neo4j"</strong> y sube el CSV que desees importar</li>
                <li>Usa las <strong>"Consultas NTFS"</strong> para analizar el grafo</li>
              </ol>
            </div>
            <ScriptBlock label="Script 1: Extract-NTFS.ps1 — Extrae ACLs de carpetas" code={PS_EXTRACT} />
            <ScriptBlock label="Script 2: Expand-Groups.ps1 — Expande grupos a usuarios individuales" code={PS_EXPAND} />

            <div className="rounded border border-soc-border bg-soc-card p-3 text-[11px] text-soc-dim space-y-1.5">
              <p className="text-soc-text font-semibold text-[12px]">Formato esperado de los CSV</p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-soc-accent mb-1">NTFS_Permissions.csv</p>
                  <code className="text-[10px] text-green-300">Folder, Identity, Rights, Type, Inherited</code>
                </div>
                <div>
                  <p className="text-soc-accent mb-1">NTFS_User_Effective.csv</p>
                  <code className="text-[10px] text-green-300">User, Folder, Rights, Type, Inherited[, Via]</code>
                </div>
              </div>
              <p className="text-[10px] mt-2">
                El backend detecta automáticamente el tipo de CSV por las cabeceras.
                Importar <strong>NTFS_User_Effective.csv</strong> da resultados más precisos porque los grupos
                ya están expandidos a usuarios reales.
              </p>
            </div>
          </div>
        )}

        {/* ── Import tab ── */}
        {mainTab === "import" && (
          <div className="space-y-4">
            <StatusBar status={ntfsStatus} onRefresh={fetchStatus} />

            {/* Cypher for manual import */}
            <details className="rounded border border-soc-border">
              <summary className="px-3 py-2 text-[11px] text-soc-dim cursor-pointer hover:text-soc-text flex items-center gap-1.5">
                <ChevronRight className="w-3 h-3" />
                Importación manual vía Cypher (LOAD CSV)
              </summary>
              <div className="px-3 pb-3 space-y-2">
                <p className="text-[11px] text-soc-dim mt-2">
                  Si prefieres importar directamente desde Neo4j Browser, copia el CSV al
                  directorio <code>import/</code> del contenedor y ejecuta:
                </p>
                {[
                  {
                    label: "1. Crear índice en Folder.path",
                    code: "CREATE INDEX folder_path IF NOT EXISTS FOR (f:Folder) ON (f.path);",
                  },
                  {
                    label: "2. Importar NTFS_User_Effective.csv",
                    code: `LOAD CSV WITH HEADERS FROM 'file:///NTFS_User_Effective.csv' AS row
MERGE (u:ADUser {sam: toLower(row.User)})
MERGE (f:Folder {path: row.Folder})
MERGE (u)-[r:HAS_ACCESS]->(f)
SET r.rights    = row.Rights,
    r.inherited = row.Inherited,
    r.via       = coalesce(row.Via, ""),
    r.acc_type  = coalesce(row.Type, "Allow");`,
                  },
                  {
                    label: "3. Relacionar con grupos AD existentes (raw ACL)",
                    code: `LOAD CSV WITH HEADERS FROM 'file:///NTFS_Permissions.csv' AS row
WITH row, split(row.Identity,'\\\\')[-1] AS identity
MATCH (g:ADGroup) WHERE g.sam = identity OR g.name = identity
MERGE (f:Folder {path: row.Folder})
MERGE (g)-[r:HAS_ACCESS]->(f)
SET r.rights = row.Rights, r.inherited = row.Inherited;`,
                  },
                ].map(({ label, code }) => (
                  <div key={label} className="rounded border border-soc-border overflow-hidden">
                    <div className="flex justify-between items-center px-2 py-1 bg-soc-surface border-b border-soc-border">
                      <span className="text-[10px] text-soc-dim">{label}</span>
                      <CopyButton text={code} />
                    </div>
                    <pre className="text-[10px] text-green-300 bg-[#080810] px-2 py-1.5 overflow-x-auto">{code}</pre>
                  </div>
                ))}
              </div>
            </details>

            {/* Upload zone */}
            <div className="rounded border border-soc-border p-4">
              <p className="text-[12px] text-soc-text mb-3 font-semibold flex items-center gap-1.5">
                <Upload className="w-3.5 h-3.5 text-soc-accent" />
                Importar CSV en Neo4j
              </p>
              <div
                className="border-2 border-dashed border-soc-border rounded p-6 text-center cursor-pointer hover:border-soc-accent/50 transition-colors"
                onClick={() => fileRef.current?.click()}
              >
                <Upload className="w-6 h-6 text-soc-dim mx-auto mb-2" />
                <p className="text-[11px] text-soc-text">Arrastra o haz clic</p>
                <p className="text-[10px] text-soc-dim mt-0.5">NTFS_Permissions.csv o NTFS_User_Effective.csv</p>
              </div>
              <input
                ref={fileRef}
                type="file"
                accept=".csv"
                className="hidden"
                onChange={e => onImport(e.target.files)}
              />

              {importing && (
                <div className="mt-3 flex items-center gap-2 text-[11px] text-soc-dim">
                  <div className="w-3 h-3 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
                  Importando en Neo4j…
                </div>
              )}

              {importMsg && (
                <div className={cn(
                  "mt-3 rounded px-3 py-2 text-[11px]",
                  importMsg.ok ? "bg-green-950/40 border border-green-800 text-green-300" : "bg-red-950/40 border border-red-800 text-red-400",
                )}>
                  {importMsg.msg}
                </div>
              )}
            </div>

            {/* Purge */}
            <div className="flex items-center justify-between rounded border border-red-900/40 bg-red-950/20 px-3 py-2">
              <div>
                <p className="text-[11px] text-red-400 font-semibold">Eliminar datos NTFS</p>
                <p className="text-[10px] text-soc-dim">Borra todos los nodos Folder y relaciones HAS_ACCESS de Neo4j</p>
              </div>
              <button
                onClick={doPurge}
                disabled={purging}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-red-800 text-[11px] text-red-400 hover:bg-red-900/30 transition-colors disabled:opacity-50"
              >
                <Trash2 className="w-3 h-3" />
                {purging ? "Eliminando…" : "Purgar"}
              </button>
            </div>
          </div>
        )}

        {/* ── Queries tab ── */}
        {mainTab === "queries" && (
          <div className="flex gap-3 h-full" style={{ minHeight: "600px" }}>

            {/* Left: query list */}
            <div className="w-72 shrink-0 flex flex-col gap-2">
              {/* Risk filter */}
              <div className="flex flex-wrap gap-1">
                {["all","critical","high","medium","low","info"].map(r => (
                  <button
                    key={r}
                    onClick={() => setRiskFilter(r)}
                    className={cn(
                      "px-2 py-0.5 rounded text-[9px] font-bold uppercase transition-colors",
                      riskFilter === r
                        ? r === "all" ? "bg-soc-accent text-black" : RISK_BADGE[r]
                        : "bg-soc-card border border-soc-border text-soc-dim hover:text-soc-text",
                    )}
                  >
                    {r === "all" ? "Todos" : RISK_LABEL[r]}
                  </button>
                ))}
              </div>

              <div className="overflow-y-auto space-y-1.5 pr-1" style={{ maxHeight: "560px" }}>
                {filteredQueries.length === 0 ? (
                  <p className="text-[11px] text-soc-dim py-4 text-center">Sin consultas NTFS cargadas</p>
                ) : (
                  filteredQueries.map(q => (
                    <QueryItem key={q.id} q={q} selected={selected?.id === q.id} onSelect={() => onSelectQuery(q)} />
                  ))
                )}
              </div>
            </div>

            {/* Right: query detail + result */}
            <div className="flex-1 flex flex-col gap-3 overflow-hidden">
              {!selected ? (
                <div className="flex items-center justify-center h-48 text-[12px] text-soc-dim border border-dashed border-soc-border rounded">
                  Selecciona una consulta de la lista
                </div>
              ) : (
                <>
                  {/* Query header */}
                  <div className="rounded border border-soc-border bg-soc-card p-3 space-y-2">
                    <div className="flex items-center gap-2">
                      <RiskBadge risk={selected.risk} />
                      <span className="text-[12px] font-semibold text-soc-text">{selected.title}</span>
                    </div>
                    <p className="text-[11px] text-soc-dim">{selected.description}</p>

                    {/* Params */}
                    {selected.params.length > 0 && (
                      <div className="flex flex-wrap gap-2 pt-1">
                        {selected.params.map(p => (
                          <div key={p.name} className="flex flex-col gap-0.5">
                            <label className="text-[9px] text-soc-dim uppercase">{p.label}</label>
                            <input
                              value={params[p.name] ?? ""}
                              onChange={e => setParams(prev => ({ ...prev, [p.name]: e.target.value }))}
                              placeholder={p.placeholder}
                              onKeyDown={e => e.key === "Enter" && runQuery()}
                              className="bg-soc-surface border border-soc-border rounded px-2 py-1 text-[11px] font-mono text-soc-text focus:border-soc-accent outline-none w-48"
                            />
                          </div>
                        ))}
                      </div>
                    )}

                    {/* Cypher preview */}
                    <div className="rounded border border-soc-border overflow-hidden">
                      <div className="flex items-center justify-between px-2 py-1 bg-soc-surface border-b border-soc-border">
                        <span className="text-[9px] text-soc-dim uppercase tracking-wider">Cypher</span>
                        <CopyButton text={selected.cypher} />
                      </div>
                      <pre className="text-[10px] text-green-300 bg-[#080810] px-2 py-1.5 overflow-x-auto whitespace-pre-wrap max-h-[120px] overflow-y-auto">
                        {selected.cypher}
                      </pre>
                    </div>

                    <button
                      onClick={runQuery}
                      disabled={running}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-soc-accent text-black text-[11px] font-semibold hover:brightness-110 transition disabled:opacity-50"
                    >
                      <Play className="w-3 h-3" />
                      {running ? "Ejecutando…" : "Ejecutar"}
                      <span className="text-[9px] font-normal ml-1 opacity-70">Ctrl+Enter</span>
                    </button>
                  </div>

                  {/* Result */}
                  {result && (
                    <div className="flex-1 flex flex-col border border-soc-border rounded overflow-hidden">
                      <div className="flex items-center gap-2 px-3 py-2 border-b border-soc-border bg-soc-surface shrink-0">
                        <span className="text-[11px] text-soc-dim">{result.count} resultado(s)</span>
                        <div className="flex gap-1 ml-auto">
                          {(["table","graph"] as ResultTab[]).map(t => (
                            <button
                              key={t}
                              onClick={() => setResultTab(t)}
                              className={cn(
                                "px-2.5 py-1 rounded text-[10px] transition-colors capitalize",
                                resultTab === t
                                  ? "bg-soc-accent/10 text-soc-accent border border-soc-accent/30"
                                  : "text-soc-dim hover:text-soc-text",
                              )}
                            >
                              {t === "table" ? "Tabla" : "Grafo"}
                            </button>
                          ))}
                        </div>
                      </div>
                      <div className="flex-1 overflow-auto">
                        {resultTab === "table" ? (
                          result.columns.length > 0 ? (
                            <ResultTable columns={result.columns} rows={result.rows} />
                          ) : (
                            <p className="text-[11px] text-soc-dim p-4">Sin resultados</p>
                          )
                        ) : (
                          <div className="w-full h-full min-h-[300px]">
                            <GraphCanvas
                              nodes={result.graph.nodes}
                              edges={result.graph.edges}
                            />
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
