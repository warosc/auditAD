"use client";

import { useState, useRef, useCallback, useMemo, useEffect } from "react";
import {
  Upload, FileText, X, Shield, Users, Monitor, Network,
  AlertTriangle, XCircle, Info, ChevronDown, ChevronUp,
  Search, RefreshCw, Lock, FolderOpen, CheckCircle, Activity,
  Download, GitBranch, Trash2, ExternalLink, Zap, ArrowRight,
  TrendingUp,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────

interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  description: string;
  recommendation: string;
  mitre: string;
}

interface ADUser {
  sam: string; dn: string; ou: string; ou_path: string; canonical: string;
  uac: number; uac_flags: string[];
  disabled: boolean; no_expire: boolean; no_preauth: boolean; pwd_not_req: boolean;
  spn: string[]; last_logon: string; pwd_last_set: string; upn: string;
  display_name: string; department: string; company: string;
  risk_score: number;
}

interface AttackPath {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  chain: string[];
  accounts: string[];
  mitre: string;
  impact: string;
  fix: string;
}

interface ADComputer {
  name: string; dn: string; sam: string; os: string; os_ver: string;
  uac: number; is_dc: boolean; enabled: boolean; last_logon: string;
  os_risk: string | null; ou: string; ip: string;
}

interface ADGroup {
  name: string; sam: string; dn: string; scope: string; category: string;
  member_count: number; members: string[]; description: string;
}

interface ADOU {
  name: string; dn: string; canonical: string; description: string;
  managed_by: string; gpo_count: number; gpos: string[];
  protected: boolean; created: string; modified: string;
}

interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number; }

interface CsvStats {
  total_users: number; active_users: number; disabled_users: number; privileged_users: number;
  total_computers: number; domain_controllers: number;
  total_groups: number; total_ous: number; empty_ous: number;
}

interface CsvResult {
  available: boolean;
  source: string;
  timestamp: string;
  files_detected: string[];
  files_skipped: string[];
  findings: Finding[];
  severity_counts: SeverityCounts;
  stats: CsvStats;
  users: ADUser[];
  computers: ADComputer[];
  groups: ADGroup[];
  ous: ADOU[];
  policy: Record<string, unknown>;
  attack_paths: AttackPath[];
}

// ── Severity styling ────────────────────────────────────────────────────────

const SEV: Record<string, { bg: string; text: string; border: string; label: string }> = {
  critical: { bg: "bg-red-950",    text: "text-red-300",    border: "border-red-700",    label: "CRÍTICO" },
  high:     { bg: "bg-orange-950", text: "text-orange-300", border: "border-orange-700", label: "ALTO"    },
  medium:   { bg: "bg-yellow-950", text: "text-yellow-300", border: "border-yellow-700", label: "MEDIO"   },
  low:      { bg: "bg-blue-950",   text: "text-blue-300",   border: "border-blue-700",   label: "BAJO"    },
  info:     { bg: "bg-zinc-900",   text: "text-zinc-300",   border: "border-zinc-700",   label: "INFO"    },
};

const SevBadge = ({ s }: { s: string }) => {
  const st = SEV[s] ?? SEV.info;
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded ${st.bg} ${st.text} border ${st.border}`}>
      {st.label}
    </span>
  );
};

// ── Sub-components ──────────────────────────────────────────────────────────

function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const st = SEV[f.severity] ?? SEV.info;
  return (
    <div className={`rounded-lg border ${st.border} ${st.bg} mb-2`}>
      <button className="w-full flex items-center gap-3 p-3 text-left" onClick={() => setOpen(!open)}>
        <SevBadge s={f.severity} />
        <span className="text-xs text-zinc-500 font-mono">{f.id}</span>
        <span className={`flex-1 text-sm font-medium ${st.text}`}>{f.title}</span>
        <span className="text-xs text-zinc-500 hidden sm:block">{f.category}</span>
        {open ? <ChevronUp size={14} className="text-zinc-500 shrink-0" /> : <ChevronDown size={14} className="text-zinc-500 shrink-0" />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2 text-sm text-zinc-300">
          <p>{f.description}</p>
          <div className="flex gap-2 flex-wrap mt-2">
            <span className="bg-zinc-800 text-green-400 text-xs px-2 py-1 rounded">✓ {f.recommendation}</span>
            <span className="bg-zinc-800 text-purple-400 text-xs px-2 py-1 rounded font-mono">{f.mitre}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function Tab({ label, active, onClick, count }: { label: string; active: boolean; onClick: () => void; count?: number }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors whitespace-nowrap ${
        active
          ? "border-purple-500 text-purple-300 bg-zinc-800"
          : "border-transparent text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50"
      }`}
    >
      {label}
      {count !== undefined && (
        <span className={`ml-1.5 text-xs px-1.5 py-0.5 rounded-full ${active ? "bg-purple-700 text-purple-200" : "bg-zinc-700 text-zinc-400"}`}>
          {count}
        </span>
      )}
    </button>
  );
}

function FilterSelect({ value, onChange, options }: {
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <select
      value={value}
      onChange={e => onChange(e.target.value)}
      className="bg-zinc-900 border border-zinc-700 text-zinc-300 text-sm rounded-lg px-3 py-2 outline-none cursor-pointer hover:border-zinc-500 transition-colors"
    >
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
}

// ── File type detection (client-side, by filename) ─────────────────────────

const TYPE_COLOR: Record<string, string> = {
  "Usuarios":     "bg-blue-900/40 text-blue-300 border-blue-700",
  "Computadoras": "bg-cyan-900/40 text-cyan-300 border-cyan-700",
  "Grupos":       "bg-indigo-900/40 text-indigo-300 border-indigo-700",
  "OUs":          "bg-purple-900/40 text-purple-300 border-purple-700",
  "Política":     "bg-yellow-900/40 text-yellow-300 border-yellow-700",
  "Desconocido":  "bg-zinc-800 text-zinc-400 border-zinc-600",
};

function detectFileType(name: string): string {
  const n = name.toLowerCase();
  if (n.includes("usuario") || n.includes("user"))        return "Usuarios";
  if (n.includes("computadora") || n.includes("computer")) return "Computadoras";
  if (n.includes("grupo") || n.includes("group"))         return "Grupos";
  if (n.includes("ous") || n.includes("_ou_") || n.endsWith("_ous.csv")) return "OUs";
  if (n.includes("policy") || n.includes("politica"))     return "Política";
  return "Desconocido";
}

// ── Stat card ───────────────────────────────────────────────────────────────

function StatCard({ label, value, color, icon }: { label: string; value: number; color: string; icon: React.ReactNode }) {
  return (
    <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-3 text-center">
      <div className={`flex justify-center mb-1 ${color}`}>{icon}</div>
      <div className={`text-xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-zinc-500">{label}</div>
    </div>
  );
}

// ── Main component ──────────────────────────────────────────────────────────

export function CsvImportPanel() {
  const [files,      setFiles]      = useState<File[]>([]);
  const [loading,    setLoading]    = useState(false);
  const [pdfLoading, setPdfLoading] = useState(false);
  const [error,      setError]      = useState<string | null>(null);
  const [result,     setResult]     = useState<CsvResult | null>(null);
  const [activeTab,  setActiveTab]  = useState("findings");
  const [search,     setSearch]     = useState("");
  const [filters, setFilters] = useState({
    findings:  { sev: "all", category: "all" },
    users:     { status: "all", flag: "all" },
    computers: { role: "all", osRisk: "all", os: "all", logon: "all", enabled: "all", ouSearch: "", ipSearch: "" },
    groups:    { type: "all", hasMembers: "all" },
    ous:       { hasGpo: "all", prot: "all" },
    risk:      { minScore: "0", flag: "all" },
    paths:     { sev: "all" },
  });
  const setF = (tab: string, key: string, val: string) =>
    setFilters(f => ({ ...f, [tab]: { ...(f as Record<string, Record<string, string>>)[tab], [key]: val } }));
  const [dragging,   setDragging]   = useState(false);

  // Baseline state
  const [baselineLoading,   setBaselineLoading]   = useState(false);
  const [baselineError,     setBaselineError]     = useState<string | null>(null);
  const [showBaselineModal, setShowBaselineModal] = useState(false);
  const [baselineName,      setBaselineName]      = useState("");
  const [baselineTags,      setBaselineTags]      = useState("");

  // Neo4j state
  const [neo4jStatus,    setNeo4jStatus]    = useState<{connected: boolean; counts?: Record<string,number>; error?: string} | null>(null);
  const [neo4jLoading,   setNeo4jLoading]   = useState(false);
  const [neo4jResult,    setNeo4jResult]    = useState<{purged: number; imported: {nodes:number; relationships:number}; purge_mode: string} | null>(null);
  const [neo4jError,     setNeo4jError]     = useState<string | null>(null);
  const [purgeMode,      setPurgeMode]      = useState<"csv"|"all"|"none">("csv");

  const inputRef = useRef<HTMLInputElement>(null);

  // Rehidratar desde el caché del backend al montar (sobrevive la navegación entre menús)
  useEffect(() => {
    fetch("/api/csv/result", { cache: "no-store" })
      .then(r => r.ok ? r.json() as Promise<CsvResult> : Promise.reject())
      .then(data => {
        if (data?.available) {
          setResult(data);
          setActiveTab("findings");
          checkNeo4j();
        }
      })
      .catch(() => {}); // sin caché previo → pantalla de upload normal
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const addFiles = useCallback((incoming: FileList | File[]) => {
    const csvs = Array.from(incoming).filter(f => f.name.toLowerCase().endsWith(".csv"));
    setFiles(prev => {
      const existing = new Set(prev.map(f => f.name));
      return [...prev, ...csvs.filter(f => !existing.has(f.name))];
    });
  }, []);

  const removeFile = (name: string) => setFiles(prev => prev.filter(f => f.name !== name));

  const onDragOver  = (e: React.DragEvent) => { e.preventDefault(); setDragging(true); };
  const onDragLeave = () => setDragging(false);
  const onDrop      = (e: React.DragEvent) => {
    e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files);
  };

  const checkNeo4j = async () => {
    try {
      const res = await fetch("/api/csv/neo4j-status", { cache: "no-store" });
      setNeo4jStatus(await res.json());
    } catch {
      setNeo4jStatus({ connected: false, error: "No se pudo conectar" });
    }
  };

  const importToNeo4j = async () => {
    setNeo4jLoading(true); setNeo4jError(null); setNeo4jResult(null);
    try {
      const res = await fetch(`/api/csv/neo4j-import?purge=${purgeMode}`, {
        method: "POST", cache: "no-store",
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(d.detail || `Error ${res.status}`);
      }
      const data = await res.json();
      setNeo4jResult(data);
      // Refresh status counts
      await checkNeo4j();
    } catch (e) {
      setNeo4jError(String(e));
    } finally {
      setNeo4jLoading(false);
    }
  };

  const purgeNeo4j = async (mode: "csv" | "all") => {
    if (!confirm(mode === "all"
      ? "⚠ Esto eliminará TODOS los datos de Neo4j incluyendo BloodHound. ¿Continuar?"
      : "Eliminar los datos CSV anteriores (ADUser, ADComputer, ADGroup, ADOU). ¿Continuar?"
    )) return;
    setNeo4jLoading(true); setNeo4jError(null);
    try {
      await fetch(`/api/csv/neo4j-purge?mode=${mode}`, { method: "DELETE", cache: "no-store" });
      await checkNeo4j();
      setNeo4jResult(null);
    } catch (e) {
      setNeo4jError(String(e));
    } finally {
      setNeo4jLoading(false);
    }
  };

  const analyze = async () => {
    if (files.length === 0) return;
    setLoading(true); setError(null); setResult(null);
    try {
      const fd = new FormData();
      for (const f of files) fd.append("files", f, f.name);
      const res = await fetch("/api/csv/analyze", { method: "POST", body: fd, cache: "no-store" });
      if (!res.ok) {
        const detail = await res.text().catch(() => res.statusText);
        throw new Error(`Error ${res.status}: ${detail}`);
      }
      const data: CsvResult = await res.json();
      setResult(data);
      setActiveTab("findings");
      setNeo4jResult(null);
      // Auto-check Neo4j status after analysis
      checkNeo4j();
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const reset = () => { setFiles([]); setResult(null); setError(null); };

  const exportJson = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `ad_csv_analysis_${result.timestamp}.json`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  const exportPdf = async () => {
    if (!result || pdfLoading) return;
    setPdfLoading(true);
    try {
      const res = await fetch("/api/csv/report/pdf");
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail ?? "Error generando PDF");
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href     = url;
      a.download = `REPORTE_RC_AD_${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (e: unknown) {
      alert(`Error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setPdfLoading(false);
    }
  };

  const saveBaseline = async () => {
    if (!result || !baselineName.trim()) {
      setBaselineError("El nombre del baseline es requerido");
      return;
    }
    setBaselineLoading(true);
    setBaselineError(null);
    try {
      const res = await fetch("/api/audit/baselines/save", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: baselineName.trim(),
          source: "csv",
          tags: baselineTags.trim(),
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error(err.detail ?? `Error ${res.status}`);
      }
      const data = await res.json();
      setShowBaselineModal(false);
      setBaselineName("");
      setBaselineTags("");
      alert(`✓ Baseline guardado: ${data.name}`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setBaselineError(msg);
      alert(`Error: ${msg}`);
    } finally {
      setBaselineLoading(false);
    }
  };

  const exportComputersCsv = (data: ADComputer[], filename: string) => {
    const cols = ["Nombre","Rol","OS","Versión OS","Riesgo OS","OU","IP","Último logon","Habilitado","DN"];
    const rows = data.map(c => [
      c.name, c.is_dc ? "DC" : "Equipo", c.os ?? "", c.os_ver ?? "",
      c.os_risk?.toUpperCase() ?? "OK", c.ou ?? "", c.ip ?? "",
      c.last_logon?.slice(0, 10) ?? "", c.enabled ? "Sí" : "No", c.dn ?? "",
    ]);
    const bom = "﻿";
    const csv = bom + [cols, ...rows]
      .map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(","))
      .join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  // ── Filtered lists ──────────────────────────────────────────────────────

  const uniqueCategories = useMemo<string[]>(() => {
    if (!result?.findings) return [];
    const cats = result.findings.map((f: Finding) => f.category as string);
    return Array.from(new Set(cats)).sort();
  }, [result?.findings]);

  const filteredFindings = useMemo(() => {
    if (!result?.findings) return [];
    const q   = search.toLowerCase();
    const { sev, category } = filters.findings;
    return result.findings.filter((f: Finding) => {
      if (sev !== "all"      && f.severity !== sev)       return false;
      if (category !== "all" && f.category !== category)  return false;
      if (q && !f.title.toLowerCase().includes(q) && !f.description.toLowerCase().includes(q) && !f.id.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [result?.findings, filters.findings, search]);

  const filteredUsers = useMemo(() => {
    if (!result?.users) return [];
    const q = search.toLowerCase();
    const { status, flag } = filters.users;
    return [...result.users]
      .sort((a: ADUser, b: ADUser) => b.risk_score - a.risk_score)
      .filter((u: ADUser) => {
        if (status === "active"   &&  u.disabled) return false;
        if (status === "disabled" && !u.disabled) return false;
        if (flag === "asrep"    && !u.no_preauth)    return false;
        if (flag === "kerb"     && !u.spn?.length)   return false;
        if (flag === "noexpire" && !u.no_expire)     return false;
        if (flag === "nopwd"    && !u.pwd_not_req)   return false;
        if (q && !u.sam.toLowerCase().includes(q) && !u.ou.toLowerCase().includes(q) &&
            !u.display_name?.toLowerCase().includes(q) && !u.department?.toLowerCase().includes(q)) return false;
        return true;
      });
  }, [result?.users, filters.users, search]);

  const filteredComps = useMemo(() => {
    if (!result?.computers) return [];
    const q   = search.toLowerCase();
    const now = Date.now();
    const { role, osRisk, os, logon, enabled, ouSearch, ipSearch } = filters.computers;
    return result.computers.filter((c: ADComputer) => {
      if (role === "dc"          && !c.is_dc) return false;
      if (role === "workstation" &&  c.is_dc) return false;
      if (osRisk === "critical"  && c.os_risk !== "critical") return false;
      if (osRisk === "high"      && c.os_risk !== "high")     return false;
      if (osRisk === "medium"    && c.os_risk !== "medium")   return false;
      if (osRisk === "ok"        && c.os_risk !== null)       return false;
      if (os !== "all"           && c.os !== os)              return false;
      if (enabled === "yes"      && !c.enabled)               return false;
      if (enabled === "no"       &&  c.enabled)               return false;
      if (ouSearch && !c.ou?.toLowerCase().includes(ouSearch.toLowerCase())) return false;
      if (ipSearch && !c.ip?.startsWith(ipSearch))            return false;
      if (logon !== "all") {
        const ll = c.last_logon ? new Date(c.last_logon).getTime() : 0;
        const d  = (days: number) => now - days * 86_400_000;
        if (logon === "active30"   && (!ll || ll < d(30)))    return false;
        if (logon === "inactive90" && ll >= d(90))            return false;
        if (logon === "inactive180"&& ll >= d(180))           return false;
        if (logon === "never"      && ll > 0)                 return false;
      }
      if (q && !c.name.toLowerCase().includes(q) && !c.os?.toLowerCase().includes(q) && !c.ou?.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [result?.computers, filters.computers, search]);

  const osChipsData = useMemo(() => {
    if (!result?.computers) return [] as { os: string; count: number; maxRisk: number }[];
    const rLvl: Record<string, number> = { critical: 3, high: 2, medium: 1 };
    const map = new Map<string, { count: number; maxRisk: number }>();
    for (const c of result.computers) {
      const key  = c.os || "Desconocido";
      const prev = map.get(key) ?? { count: 0, maxRisk: 0 };
      map.set(key, { count: prev.count + 1, maxRisk: Math.max(prev.maxRisk, rLvl[c.os_risk ?? ""] ?? 0) });
    }
    return Array.from(map.entries())
      .map(([os, d]) => ({ os, count: d.count, maxRisk: d.maxRisk }))
      .sort((a, b) => b.count - a.count);
  }, [result?.computers]);

  const filteredGroups = useMemo(() => {
    if (!result?.groups) return [];
    const q = search.toLowerCase();
    const { type, hasMembers } = filters.groups;
    const privKw = ["domain admin", "enterprise admin", "schema admin", "administrators"];
    return result.groups.filter((g: ADGroup) => {
      const isPriv = privKw.some(x => g.name.toLowerCase().includes(x));
      if (type === "priv"   && !isPriv) return false;
      if (type === "normal" &&  isPriv) return false;
      if (hasMembers === "yes"   && g.member_count === 0) return false;
      if (hasMembers === "empty" && g.member_count > 0)   return false;
      if (q && !g.name.toLowerCase().includes(q) && !g.description?.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [result?.groups, filters.groups, search]);

  const filteredOus = useMemo(() => {
    if (!result?.ous) return [];
    const q = search.toLowerCase();
    const { hasGpo, prot } = filters.ous;
    return result.ous.filter((o: ADOU) => {
      if (hasGpo === "yes" && o.gpo_count === 0) return false;
      if (hasGpo === "no"  && o.gpo_count > 0)  return false;
      if (prot === "yes"   && !o.protected)      return false;
      if (prot === "no"    &&  o.protected)      return false;
      if (q && !o.name.toLowerCase().includes(q) && !o.description?.toLowerCase().includes(q) && !o.canonical?.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [result?.ous, filters.ous, search]);

  // ── Render ──────────────────────────────────────────────────────────────

  const sc = result?.severity_counts;
  const totalRisk    = sc ? sc.critical * 4 + sc.high * 3 + sc.medium * 2 + sc.low : 0;
  const riskLabel    = totalRisk === 0 ? "Bajo" : totalRisk < 6 ? "Moderado" : totalRisk < 15 ? "Alto" : "Crítico";
  const riskColor    = totalRisk === 0 ? "text-green-400" : totalRisk < 6 ? "text-yellow-400" : totalRisk < 15 ? "text-orange-400" : "text-red-400";
  const riskBorder   = totalRisk === 0 ? "border-green-700" : totalRisk < 15 ? "border-orange-700" : "border-red-700";

  return (
    <div className="p-6 space-y-6 max-w-7xl">

      {/* ── Header ── */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Upload size={22} className="text-purple-400" />
            Análisis Offline — Importar CSV de AD
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Sube los exports de PowerShell (AD_Usuarios, AD_Computadoras, AD_Grupos, AD_OUs)
            para análisis de seguridad sin conexión al DC.
          </p>
        </div>
        <div className="flex gap-2">
          {result && (
            <>
              <button onClick={exportJson} className="flex items-center gap-1.5 text-sm bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-3 py-2 rounded-lg transition-colors">
                <Download size={14} /> JSON
              </button>
              <button onClick={reset} className="flex items-center gap-1.5 text-sm bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-3 py-2 rounded-lg transition-colors">
                <Upload size={14} /> Nuevo análisis
              </button>
            </>
          )}
          <button
            onClick={exportPdf}
            disabled={pdfLoading || !result}
            title={!result ? "Analiza un CSV primero para exportar el PDF" : "Exportar reporte PDF"}
            className="flex items-center gap-1.5 text-sm bg-purple-900 hover:bg-purple-800 disabled:opacity-40 disabled:cursor-not-allowed text-purple-200 px-3 py-2 rounded-lg border border-purple-700 transition-colors"
          >
            {pdfLoading ? <RefreshCw size={14} className="animate-spin" /> : <FileText size={14} />}
            {pdfLoading ? "Generando PDF…" : "Reporte R&C (PDF)"}
          </button>
          <button
            onClick={() => setShowBaselineModal(true)}
            disabled={baselineLoading || !result}
            title={!result ? "Analiza un CSV primero para guardar baseline" : "Guardar análisis como baseline para comparación"}
            className="flex items-center gap-1.5 text-sm bg-blue-900 hover:bg-blue-800 disabled:opacity-40 disabled:cursor-not-allowed text-blue-200 px-3 py-2 rounded-lg border border-blue-700 transition-colors"
          >
            {baselineLoading ? <RefreshCw size={14} className="animate-spin" /> : <GitBranch size={14} />}
            {baselineLoading ? "Guardando…" : "Guardar Baseline"}
          </button>
        </div>
      </div>

      {/* ── Upload zone (visible when no result yet) ── */}
      {!result && (
        <div className="space-y-4">
          {/* Drop area */}
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={onDragOver}
            onDragLeave={onDragLeave}
            onDrop={onDrop}
            className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${
              dragging
                ? "border-purple-500 bg-purple-900/10"
                : "border-zinc-600 hover:border-zinc-500 bg-zinc-900/50"
            }`}
          >
            <Upload size={36} className={`mx-auto mb-3 ${dragging ? "text-purple-400" : "text-zinc-500"}`} />
            <p className="text-zinc-300 font-medium">Arrastra los archivos CSV aquí</p>
            <p className="text-zinc-500 text-sm mt-1">o haz clic para seleccionar</p>
            <p className="text-zinc-600 text-xs mt-3">
              AD_Usuarios_*.csv · AD_Computadoras_*.csv · AD_Grupos_*.csv · AD_OUs_*.csv
            </p>
            <input
              ref={inputRef}
              type="file"
              accept=".csv"
              multiple
              className="hidden"
              onChange={e => e.target.files && addFiles(e.target.files)}
            />
          </div>

          {/* File list */}
          {files.length > 0 && (
            <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-4 space-y-2">
              <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider mb-3">
                Archivos seleccionados ({files.length})
              </p>
              {files.map(f => {
                const type  = detectFileType(f.name);
                const color = TYPE_COLOR[type] ?? TYPE_COLOR["Desconocido"];
                const kb    = (f.size / 1024).toFixed(0);
                return (
                  <div key={f.name} className="flex items-center gap-3 p-2 rounded-lg bg-zinc-800/50 hover:bg-zinc-800">
                    <FileText size={16} className="text-zinc-400 shrink-0" />
                    <span className="flex-1 text-sm text-zinc-200 font-mono truncate">{f.name}</span>
                    <span className="text-xs text-zinc-500">{kb} KB</span>
                    <span className={`text-xs font-medium px-2 py-0.5 rounded border ${color}`}>{type}</span>
                    <button onClick={() => removeFile(f.name)} className="text-zinc-600 hover:text-zinc-300 transition-colors">
                      <X size={14} />
                    </button>
                  </div>
                );
              })}

              {/* Analyze button */}
              <div className="pt-2">
                {error && (
                  <p className="text-red-400 text-sm mb-2 flex items-center gap-1.5">
                    <XCircle size={14} /> {error}
                  </p>
                )}
                <button
                  onClick={analyze}
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-2 bg-purple-700 hover:bg-purple-600 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors"
                >
                  {loading
                    ? <><RefreshCw size={16} className="animate-spin" /> Analizando…</>
                    : <><Shield size={16} /> Analizar archivos AD</>}
                </button>
              </div>
            </div>
          )}

          {/* Helper: generate commands */}
          <details className="bg-zinc-900 border border-zinc-700 rounded-xl">
            <summary className="px-4 py-3 text-sm text-zinc-400 cursor-pointer hover:text-zinc-200 select-none">
              ¿Cómo exportar los CSV desde PowerShell?
            </summary>
            <div className="px-4 pb-4 space-y-3 text-xs font-mono text-zinc-400">
              {[
                ["Usuarios",     `Get-ADUser -Filter * -Properties * | Export-Csv -Path AD_Usuarios_$(Get-Date -f yyyyMMdd).csv -NoTypeInformation -Encoding UTF8`],
                ["Computadoras", `Get-ADComputer -Filter * -Properties * | Export-Csv -Path AD_Computadoras_$(Get-Date -f yyyyMMdd).csv -NoTypeInformation -Encoding UTF8`],
                ["Grupos",       `Get-ADGroup -Filter * -Properties * | Export-Csv -Path AD_Grupos_$(Get-Date -f yyyyMMdd).csv -NoTypeInformation -Encoding UTF8`],
                ["OUs",          `Get-ADOrganizationalUnit -Filter * -Properties * | Export-Csv -Path AD_OUs_$(Get-Date -f yyyyMMdd).csv -NoTypeInformation -Encoding UTF8`],
              ].map(([label, cmd]) => (
                <div key={label}>
                  <p className="text-zinc-500 mb-0.5"># {label}</p>
                  <p className="bg-zinc-800 rounded px-3 py-2 text-green-400 break-all">{cmd}</p>
                </div>
              ))}
            </div>
          </details>
        </div>
      )}

      {/* ── Results ── */}
      {result && (<>
        <div className="space-y-6">
          {/* Files banner */}
          <div className="flex flex-wrap gap-2 text-xs">
            {result.files_detected.map(t => (
              <span key={t} className={`px-2 py-1 rounded border font-medium ${TYPE_COLOR[
                t === "users" ? "Usuarios" : t === "computers" ? "Computadoras" :
                t === "groups" ? "Grupos" : t === "ous" ? "OUs" : "Política"
              ] ?? TYPE_COLOR["Desconocido"]}`}>
                ✓ {t}
              </span>
            ))}
            {result.files_skipped.map(f => (
              <span key={f} className="px-2 py-1 rounded border bg-zinc-800 text-zinc-500 border-zinc-600">
                ✗ {f} (omitido)
              </span>
            ))}
          </div>

          {/* Stat cards */}
          <div className="grid grid-cols-3 sm:grid-cols-5 lg:grid-cols-9 gap-3">
            <StatCard label="Usuarios"   value={result.stats.total_users}        color="text-blue-400"   icon={<Users   size={16}/>} />
            <StatCard label="Activos"    value={result.stats.active_users}        color="text-green-400"  icon={<CheckCircle size={16}/>} />
            <StatCard label="Equipos"    value={result.stats.total_computers}     color="text-cyan-400"   icon={<Monitor size={16}/>} />
            <StatCard label="Grupos"     value={result.stats.total_groups}        color="text-indigo-400" icon={<Network size={16}/>} />
            <StatCard label="OUs"        value={result.stats.total_ous}           color="text-violet-400" icon={<FolderOpen size={16}/>} />
            <StatCard label="Críticos"   value={result.severity_counts.critical}  color="text-red-400"    icon={<XCircle size={16}/>} />
            <StatCard label="Altos"      value={result.severity_counts.high}      color="text-orange-400" icon={<AlertTriangle size={16}/>} />
            <StatCard label="Medios"     value={result.severity_counts.medium}    color="text-yellow-400" icon={<AlertTriangle size={16}/>} />
            <StatCard label="Info"       value={result.severity_counts.info}      color="text-zinc-400"   icon={<Info size={16}/>} />
          </div>

          {/* Risk banner */}
          <div className={`flex items-center gap-4 bg-zinc-900 border rounded-lg p-4 ${riskBorder}`}>
            <Shield size={28} className={riskColor} />
            <div className="flex-1">
              <span className="text-zinc-400 text-sm">Nivel de riesgo del dominio: </span>
              <span className={`font-bold text-lg ${riskColor}`}>{riskLabel}</span>
              <span className="text-zinc-500 text-sm ml-2">
                ({sc?.critical} críticos · {sc?.high} altos · {sc?.medium} medios · {result.stats.total_ous} OUs · {result.stats.total_computers} equipos)
              </span>
            </div>
          </div>

          {/* Search + per-tab advanced filters */}
          <div className="flex gap-2 flex-wrap items-center">
            <div className="flex items-center gap-2 flex-1 min-w-48 bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2">
              <Search size={14} className="text-zinc-500" />
              <input
                type="text"
                placeholder="Buscar..."
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="bg-transparent text-sm text-zinc-300 outline-none flex-1 placeholder-zinc-600"
              />
              {search && (
                <button onClick={() => setSearch("")} className="text-zinc-600 hover:text-zinc-400">
                  <X size={13} />
                </button>
              )}
            </div>

            {activeTab === "findings" && (<>
              <FilterSelect value={filters.findings.sev} onChange={v => setF("findings","sev",v)} options={[
                ["all","Todas las severidades"],["critical","🔴 Crítico"],["high","🟠 Alto"],
                ["medium","🟡 Medio"],["low","🟢 Bajo"],["info","⚪ Info"],
              ]} />
              <FilterSelect value={filters.findings.category} onChange={v => setF("findings","category",v)} options={[
                ["all","Todas las categorías"], ...uniqueCategories.map((c: string) => [c, c] as [string,string]),
              ]} />
            </>)}

            {activeTab === "users" && (<>
              <FilterSelect value={filters.users.status} onChange={v => setF("users","status",v)} options={[
                ["all","Todos los usuarios"],["active","Solo activos"],["disabled","Solo deshabilitados"],
              ]} />
              <FilterSelect value={filters.users.flag} onChange={v => setF("users","flag",v)} options={[
                ["all","Todos los flags"],["asrep","AS-REP Roastable"],["kerb","Kerberoastable"],
                ["noexpire","Sin expiración"],["nopwd","Pwd no requerida"],
              ]} />
            </>)}


            {activeTab === "groups" && (<>
              <FilterSelect value={filters.groups.type} onChange={v => setF("groups","type",v)} options={[
                ["all","Todos los grupos"],["priv","Solo privilegiados"],["normal","No privilegiados"],
              ]} />
              <FilterSelect value={filters.groups.hasMembers} onChange={v => setF("groups","hasMembers",v)} options={[
                ["all","Todos"],["yes","Con miembros"],["empty","Vacíos"],
              ]} />
            </>)}

            {activeTab === "ous" && (<>
              <FilterSelect value={filters.ous.hasGpo} onChange={v => setF("ous","hasGpo",v)} options={[
                ["all","Todas las OUs"],["yes","Con GPO"],["no","Sin GPO"],
              ]} />
              <FilterSelect value={filters.ous.prot} onChange={v => setF("ous","prot",v)} options={[
                ["all","Toda protección"],["yes","Protegidas"],["no","Sin protección"],
              ]} />
            </>)}

            {activeTab === "risk" && (<>
              <FilterSelect value={filters.risk.minScore} onChange={v => setF("risk","minScore",v)} options={[
                ["0","Todos los scores"],["30","Score ≥ 30"],["50","Score ≥ 50 (Alto)"],["80","Score ≥ 80 (Crítico)"],
              ]} />
              <FilterSelect value={filters.risk.flag} onChange={v => setF("risk","flag",v)} options={[
                ["all","Todos los flags"],["asrep","AS-REP"],["kerb","Kerberoast"],
                ["noexpire","NoExpira"],["nopwd","NoPwd"],
              ]} />
            </>)}

            {activeTab === "paths" && (
              <FilterSelect value={filters.paths.sev} onChange={v => setF("paths","sev",v)} options={[
                ["all","Todas las severidades"],["critical","🔴 Crítico"],["high","🟠 Alto"],["medium","🟡 Medio"],
              ]} />
            )}
          </div>

          {/* Tabs */}
          <div>
            <div className="flex gap-1 border-b border-zinc-700 mb-4 overflow-x-auto">
              <Tab label="Hallazgos"      active={activeTab === "findings"}   onClick={() => setActiveTab("findings")}   count={result.findings.length} />
              <Tab label="Top Riesgo"     active={activeTab === "risk"}       onClick={() => setActiveTab("risk")}       count={result.users.filter(u => u.risk_score >= 50).length} />
              <Tab label="Rutas de Ataque" active={activeTab === "paths"}     onClick={() => setActiveTab("paths")}      count={result.attack_paths?.length} />
              <Tab label="Usuarios"       active={activeTab === "users"}      onClick={() => setActiveTab("users")}      count={result.stats.total_users} />
              <Tab label="Computadoras"   active={activeTab === "computers"}  onClick={() => setActiveTab("computers")}  count={filteredComps.length} />
              <Tab label="Grupos"         active={activeTab === "groups"}     onClick={() => setActiveTab("groups")}     count={result.stats.total_groups} />
              <Tab label="OUs"            active={activeTab === "ous"}        onClick={() => setActiveTab("ous")}        count={result.stats.total_ous} />
              <Tab label="Política"       active={activeTab === "policy"}     onClick={() => setActiveTab("policy")} />
            </div>

            {/* ── Hallazgos ── */}
            {activeTab === "findings" && (
              <div>
                {filteredFindings.length === 0 ? (
                  <p className="text-zinc-500 text-sm p-4">No hay hallazgos con los filtros aplicados.</p>
                ) : (
                  filteredFindings.map(f => <FindingCard key={f.id} f={f} />)
                )}
              </div>
            )}

            {/* ── Top Riesgo ── */}
            {activeTab === "risk" && (
              <div className="space-y-3">
                <p className="text-xs text-zinc-500">
                  Puntuación de riesgo (0-100): AS-REP (+30), Kerberoast (+25), DA (+35), sin expiración (+15), pwd no requerida (+20), OU de baja (+10), sin logon (+5).
                </p>
                {(() => {
                  const minScore = parseInt(filters.risk.minScore);
                  const { flag } = filters.risk;
                  const q = search.toLowerCase();
                  return result.users
                    .filter((u: ADUser) => {
                      if (u.disabled) return false;
                      if ((u.risk_score ?? 0) < minScore) return false;
                      if (flag === "asrep"    && !u.no_preauth)   return false;
                      if (flag === "kerb"     && !u.spn?.length)  return false;
                      if (flag === "noexpire" && !u.no_expire)    return false;
                      if (flag === "nopwd"    && !u.pwd_not_req)  return false;
                      if (q && !u.sam.toLowerCase().includes(q))  return false;
                      return true;
                    })
                    .sort((a: ADUser, b: ADUser) => b.risk_score - a.risk_score)
                    .slice(0, 50)
                    .map((u: ADUser) => {
                    const score = u.risk_score ?? 0;
                    const scoreCls = score >= 80 ? "bg-red-600 text-white" : score >= 50 ? "bg-orange-600 text-white" : score >= 30 ? "bg-yellow-600 text-zinc-900" : "bg-zinc-700 text-zinc-300";
                    const chips: { label: string; cls: string }[] = [];
                    if (u.no_preauth) chips.push({ label: "AS-REP", cls: "text-red-400 border-red-800 bg-red-950/50" });
                    if (u.spn?.length > 0) chips.push({ label: "Kerberoast", cls: "text-orange-400 border-orange-800 bg-orange-950/50" });
                    if (u.no_expire)  chips.push({ label: "NoExpira", cls: "text-yellow-400 border-yellow-800 bg-yellow-950/50" });
                    if (u.pwd_not_req) chips.push({ label: "NoPwd", cls: "text-red-400 border-red-800 bg-red-950/50" });
                    return (
                      <div key={u.sam} className="flex items-center gap-3 bg-zinc-900 border border-zinc-700 rounded-lg px-4 py-2.5">
                        <span className={`text-sm font-bold px-2 py-0.5 rounded min-w-[2.5rem] text-center ${scoreCls}`}>{score}</span>
                        <TrendingUp size={14} className={score >= 80 ? "text-red-400" : score >= 50 ? "text-orange-400" : "text-zinc-500"} />
                        <span className="font-mono text-sm text-zinc-200 w-36 truncate">{u.sam}</span>
                        <span className="text-xs text-zinc-500 flex-1 truncate">{u.ou}</span>
                        <div className="flex gap-1 flex-wrap">
                          {chips.map(c => (
                            <span key={c.label} className={`text-xs border px-1.5 py-0.5 rounded font-medium ${c.cls}`}>{c.label}</span>
                          ))}
                        </div>
                        <span className="text-xs text-zinc-600 hidden md:block whitespace-nowrap">{u.last_logon?.slice(0, 10) || "—"}</span>
                      </div>
                    );
                  });
                })()}
              </div>
            )}

            {/* ── Rutas de Ataque ── */}
            {activeTab === "paths" && (
              <div className="space-y-4">
                {(!result.attack_paths || result.attack_paths.length === 0) ? (
                  <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-8 text-center">
                    <CheckCircle size={32} className="text-green-500 mx-auto mb-3" />
                    <p className="text-zinc-300 font-medium">No se detectaron rutas de ataque críticas</p>
                    <p className="text-zinc-500 text-sm mt-1">No se encontraron combinaciones de riesgo que formen cadenas de ataque viables.</p>
                  </div>
                ) : (
                  result.attack_paths.map((ap: AttackPath) => {
                    const st = SEV[ap.severity] ?? SEV.info;
                    return (
                      <div key={ap.id} className={`rounded-xl border ${st.border} ${st.bg} p-4 space-y-3`}>
                        <div className="flex items-start gap-3">
                          <Zap size={18} className={`${st.text} shrink-0 mt-0.5`} />
                          <div className="flex-1">
                            <div className="flex items-center gap-2 flex-wrap mb-1">
                              <span className="text-xs font-mono text-zinc-500">{ap.id}</span>
                              <SevBadge s={ap.severity} />
                              <span className={`text-sm font-semibold ${st.text}`}>{ap.title}</span>
                            </div>
                            {/* Attack chain */}
                            <div className="flex flex-wrap items-center gap-1 text-xs mt-2">
                              {ap.chain.map((step: string, i: number) => (
                                <span key={i} className="flex items-center gap-1">
                                  <span className="bg-zinc-800 border border-zinc-600 text-zinc-300 px-2 py-1 rounded max-w-xs">{step}</span>
                                  {i < ap.chain.length - 1 && <ArrowRight size={12} className="text-zinc-500 shrink-0" />}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                        {/* Accounts + MITRE + Impact */}
                        <div className="flex flex-wrap gap-2 items-center pl-7">
                          <div className="flex flex-wrap gap-1">
                            {ap.accounts.slice(0, 6).map((acc: string) => (
                              <span key={acc} className="text-xs font-mono bg-zinc-800 text-zinc-300 px-1.5 py-0.5 rounded">{acc}</span>
                            ))}
                            {ap.accounts.length > 6 && <span className="text-xs text-zinc-500">+{ap.accounts.length - 6}</span>}
                          </div>
                          <span className="text-xs bg-purple-900/40 border border-purple-700 text-purple-300 px-2 py-0.5 rounded font-mono ml-auto">{ap.mitre}</span>
                        </div>
                        {/* Impact + Fix */}
                        <details className="pl-7">
                          <summary className="text-xs text-zinc-500 cursor-pointer hover:text-zinc-300 select-none">Impacto y remediación</summary>
                          <div className="mt-2 space-y-1">
                            <p className="text-xs text-zinc-400"><span className="text-red-400 font-semibold">Impacto:</span> {ap.impact}</p>
                            <p className="text-xs text-zinc-400"><span className="text-green-400 font-semibold">Fix:</span> {ap.fix}</p>
                          </div>
                        </details>
                      </div>
                    );
                  })
                )}
              </div>
            )}

            {/* ── Usuarios ── */}
            {activeTab === "users" && (
              <div className="overflow-x-auto">
                <div className="flex flex-wrap gap-2 mb-3 text-xs">
                  {[
                    { label: `${result.stats.active_users} activos`,                        cls: "bg-green-900/40 border-green-700 text-green-400" },
                    { label: `${result.stats.disabled_users} deshabilitados`,               cls: "bg-zinc-800 border-zinc-700 text-zinc-400" },
                    { label: `${result.users.filter(u => u.no_expire && !u.disabled).length} sin expiración`, cls: "bg-orange-900/40 border-orange-700 text-orange-400" },
                    { label: `${result.users.filter(u => u.no_preauth).length} AS-REP Roastable`, cls: "bg-red-900/40 border-red-700 text-red-400" },
                    { label: `${result.users.filter(u => u.spn.length > 0).length} con SPN`, cls: "bg-yellow-900/40 border-yellow-700 text-yellow-400" },
                  ].map(b => (
                    <span key={b.label} className={`px-2 py-0.5 rounded border ${b.cls}`}>{b.label}</span>
                  ))}
                </div>
                <table className="w-full text-sm text-left">
                  <thead>
                    <tr className="border-b border-zinc-700 text-zinc-500 text-xs">
                      <th className="py-2 pr-3">Score</th>
                      <th className="py-2 pr-3">Usuario</th>
                      <th className="py-2 pr-3">Nombre</th>
                      <th className="py-2 pr-3">OU</th>
                      <th className="py-2 pr-3">Estado</th>
                      <th className="py-2 pr-3">Riesgo</th>
                      <th className="py-2 pr-3">Dpto</th>
                      <th className="py-2">Pwd Set</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredUsers.map(u => {
                      const risks: { label: string; c: string }[] = [];
                      if (u.no_expire  && !u.disabled) risks.push({ label: "No expira",   c: "text-yellow-400" });
                      if (u.no_preauth)                risks.push({ label: "AS-REP",       c: "text-red-400"    });
                      if (u.spn.length > 0)            risks.push({ label: "Kerberoast",   c: "text-orange-400" });
                      if (u.pwd_not_req)               risks.push({ label: "NoReqPwd",     c: "text-red-500"    });
                      if (u.ou === "Honeypots")        risks.push({ label: "Honeypot",     c: "text-purple-400" });
                      const score = u.risk_score ?? 0;
                      const scoreCls = score >= 80 ? "bg-red-600 text-white" : score >= 50 ? "bg-orange-600 text-white" : score >= 30 ? "bg-yellow-600 text-zinc-900" : "bg-zinc-800 text-zinc-500";
                      return (
                        <tr key={u.sam} className={`border-b border-zinc-800 hover:bg-zinc-800/30 ${u.disabled ? "opacity-40" : ""}`}>
                          <td className="py-1.5 pr-3">
                            <span className={`text-xs font-bold px-1.5 py-0.5 rounded ${scoreCls}`}>{score}</span>
                          </td>
                          <td className="py-1.5 pr-3 font-mono text-zinc-200 text-xs">{u.sam}</td>
                          <td className="py-1.5 pr-3 text-zinc-400 text-xs">{u.display_name || "—"}</td>
                          <td className="py-1.5 pr-3 text-zinc-500 text-xs max-w-32 truncate" title={u.ou_path}>{u.ou}</td>
                          <td className="py-1.5 pr-3">
                            {u.disabled
                              ? <span className="text-xs text-zinc-500">DISABLED</span>
                              : <span className="text-xs text-green-500">ACTIVO</span>}
                          </td>
                          <td className="py-1.5 pr-3">
                            <div className="flex flex-wrap gap-1">
                              {risks.map(r => <span key={r.label} className={`text-xs font-medium ${r.c}`}>{r.label}</span>)}
                              {risks.length === 0 && <span className="text-xs text-zinc-600">—</span>}
                            </div>
                          </td>
                          <td className="py-1.5 pr-3 text-zinc-500 text-xs">{u.department || "—"}</td>
                          <td className="py-1.5 text-zinc-500 text-xs">{u.pwd_last_set?.slice(0, 10) || "—"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* ── Computadoras ── */}
            {activeTab === "computers" && (
              <div className="space-y-3">

                {/* Resumen estático */}
                <div className="flex flex-wrap gap-2 text-xs">
                  {[
                    { label: `${result.stats.domain_controllers} DCs`,                                          cls: "bg-purple-900/40 border-purple-700 text-purple-300" },
                    { label: `${result.computers.filter((c: ADComputer) => c.os_risk === "critical").length} OS crítico`, cls: "bg-red-900/40 border-red-700 text-red-400" },
                    { label: `${result.computers.filter((c: ADComputer) => c.os_risk === "high").length} OS EOL`,     cls: "bg-orange-900/40 border-orange-700 text-orange-400" },
                    { label: `${result.computers.filter((c: ADComputer) => !c.is_dc && c.os_risk === null).length} actualizados`, cls: "bg-green-900/40 border-green-700 text-green-400" },
                  ].map(b => (
                    <span key={b.label} className={`px-2 py-0.5 rounded border ${b.cls}`}>{b.label}</span>
                  ))}
                  {filteredComps.length !== result.stats.total_computers && (
                    <span className="px-2 py-0.5 rounded border bg-purple-900/40 border-purple-700 text-purple-300">
                      {filteredComps.length} de {result.stats.total_computers} mostrando
                    </span>
                  )}
                </div>

                {/* Chips de OS clickables (Fase 2) */}
                <div className="flex flex-wrap gap-1.5">
                  {osChipsData.map(({ os: osName, count, maxRisk }) => {
                    const active = filters.computers.os === osName;
                    const color  = maxRisk === 3 ? "border-red-700 text-red-300 bg-red-950/40"
                                 : maxRisk === 2 ? "border-orange-700 text-orange-300 bg-orange-950/40"
                                 : maxRisk === 1 ? "border-yellow-700 text-yellow-300 bg-yellow-950/40"
                                 : "border-green-700 text-green-300 bg-green-950/40";
                    const icon   = maxRisk === 3 ? "🔴" : maxRisk === 2 ? "🟠" : maxRisk === 1 ? "🟡" : "✅";
                    return (
                      <button key={osName}
                        onClick={() => setF("computers", "os", active ? "all" : osName)}
                        className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                          active ? "border-purple-500 bg-purple-900/60 text-purple-200" : `${color} hover:opacity-80`
                        }`}
                      >
                        {icon} {osName} <span className="opacity-60">×{count}</span>
                      </button>
                    );
                  })}
                  {filters.computers.os !== "all" && (
                    <button onClick={() => setF("computers","os","all")}
                      className="text-xs px-2 py-1 rounded-full border border-zinc-600 text-zinc-500 hover:text-zinc-300 transition-colors">
                      ✕ limpiar OS
                    </button>
                  )}
                </div>

                {/* Barra de exportaciones (Fase 4) */}
                {(() => {
                  const today   = new Date().toISOString().slice(0,10);
                  const d90     = Date.now() - 90 * 86_400_000;
                  const zombies = result.computers.filter((c: ADComputer) =>
                    !c.last_logon || new Date(c.last_logon).getTime() < d90
                  );
                  const crits = result.computers.filter((c: ADComputer) =>
                    c.os_risk === "critical" || c.os_risk === "high"
                  );
                  return (
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => exportComputersCsv(filteredComps, `AD_Comps_Vista_${today}.csv`)}
                        className="flex items-center gap-1.5 text-xs bg-purple-900/50 hover:bg-purple-800/60 border border-purple-700 text-purple-200 px-3 py-1.5 rounded-lg transition-colors"
                      >
                        <Download size={12} /> Exportar vista ({filteredComps.length})
                      </button>
                      <button
                        onClick={() => exportComputersCsv(crits, `AD_Comps_Criticos_${today}.csv`)}
                        className="flex items-center gap-1.5 text-xs bg-red-950/50 hover:bg-red-900/60 border border-red-800 text-red-300 px-3 py-1.5 rounded-lg transition-colors"
                      >
                        <AlertTriangle size={12} /> Críticos &amp; EOL ({crits.length})
                      </button>
                      <button
                        onClick={() => exportComputersCsv(result.computers.filter((c: ADComputer) => c.is_dc), `AD_Comps_DCs_${today}.csv`)}
                        className="flex items-center gap-1.5 text-xs bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 text-zinc-300 px-3 py-1.5 rounded-lg transition-colors"
                      >
                        <Monitor size={12} /> Solo DCs ({result.stats.domain_controllers})
                      </button>
                      <button
                        onClick={() => exportComputersCsv(zombies, `AD_Comps_Zombies_${today}.csv`)}
                        className="flex items-center gap-1.5 text-xs bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 text-zinc-400 px-3 py-1.5 rounded-lg transition-colors"
                      >
                        <Activity size={12} /> Zombies &gt;90d ({zombies.length})
                      </button>
                      <button
                        onClick={() => exportComputersCsv(result.computers, `AD_Comps_Inventario_${today}.csv`)}
                        className="flex items-center gap-1.5 text-xs bg-zinc-800 hover:bg-zinc-700 border border-zinc-600 text-zinc-400 px-3 py-1.5 rounded-lg transition-colors"
                      >
                        <FileText size={12} /> Inventario ({result.stats.total_computers})
                      </button>
                    </div>
                  );
                })()}

                {/* Tabla con filtros inline en cabeceras (Fase 3) */}
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead>
                      <tr className="border-b border-zinc-700 text-xs align-top">

                        {/* Nombre */}
                        <th className="py-2 pr-3 font-normal">
                          <div className="text-zinc-500 mb-1">Nombre</div>
                        </th>

                        {/* Rol */}
                        <th className="py-2 pr-3 font-normal">
                          <div className={`mb-1 ${filters.computers.role !== "all" ? "text-purple-400" : "text-zinc-500"}`}>Rol</div>
                          <div className="flex gap-0.5">
                            {([["all","Todos"],["dc","DC"],["workstation","PC"]] as [string,string][]).map(([v,l]) => (
                              <button key={v} onClick={() => setF("computers","role",v)}
                                className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${
                                  filters.computers.role === v
                                    ? "bg-purple-700 border-purple-600 text-white"
                                    : "bg-zinc-800 border-zinc-700 text-zinc-400 hover:border-zinc-500"
                                }`}>{l}</button>
                            ))}
                          </div>
                        </th>

                        {/* OS */}
                        <th className="py-2 pr-3 font-normal min-w-[140px]">
                          <div className={`mb-1 ${filters.computers.os !== "all" ? "text-purple-400" : "text-zinc-500"}`}>OS</div>
                          <select value={filters.computers.os} onChange={e => setF("computers","os",e.target.value)}
                            className="w-full bg-zinc-800 border border-zinc-700 text-zinc-300 text-[10px] rounded px-1 py-0.5 outline-none">
                            <option value="all">Todos</option>
                            {osChipsData.map(d => <option key={d.os} value={d.os}>{d.os} ({d.count})</option>)}
                          </select>
                        </th>

                        {/* Riesgo OS */}
                        <th className="py-2 pr-3 font-normal">
                          <div className={`mb-1 ${filters.computers.osRisk !== "all" ? "text-purple-400" : "text-zinc-500"}`}>Riesgo OS</div>
                          <select value={filters.computers.osRisk} onChange={e => setF("computers","osRisk",e.target.value)}
                            className="w-full bg-zinc-800 border border-zinc-700 text-zinc-300 text-[10px] rounded px-1 py-0.5 outline-none">
                            <option value="all">Todos</option>
                            <option value="critical">Crítico</option>
                            <option value="high">Alto</option>
                            <option value="medium">Medio</option>
                            <option value="ok">OK</option>
                          </select>
                        </th>

                        {/* OU */}
                        <th className="py-2 pr-3 font-normal min-w-[110px]">
                          <div className={`mb-1 ${filters.computers.ouSearch ? "text-purple-400" : "text-zinc-500"}`}>OU</div>
                          <input type="text" value={filters.computers.ouSearch}
                            onChange={e => setF("computers","ouSearch",e.target.value)}
                            placeholder="filtrar…"
                            className="w-full bg-zinc-800 border border-zinc-700 text-zinc-300 text-[10px] rounded px-1.5 py-0.5 outline-none placeholder-zinc-600"
                          />
                        </th>

                        {/* IP */}
                        <th className="py-2 pr-3 font-normal min-w-[90px]">
                          <div className={`mb-1 ${filters.computers.ipSearch ? "text-purple-400" : "text-zinc-500"}`}>IP</div>
                          <input type="text" value={filters.computers.ipSearch}
                            onChange={e => setF("computers","ipSearch",e.target.value)}
                            placeholder="192.168…"
                            className="w-full bg-zinc-800 border border-zinc-700 text-zinc-300 text-[10px] rounded px-1.5 py-0.5 outline-none placeholder-zinc-600"
                          />
                        </th>

                        {/* Último logon */}
                        <th className="py-2 font-normal min-w-[120px]">
                          <div className={`mb-1 ${filters.computers.logon !== "all" ? "text-purple-400" : "text-zinc-500"}`}>Último logon</div>
                          <select value={filters.computers.logon} onChange={e => setF("computers","logon",e.target.value)}
                            className="w-full bg-zinc-800 border border-zinc-700 text-zinc-300 text-[10px] rounded px-1 py-0.5 outline-none">
                            <option value="all">Todos</option>
                            <option value="active30">Activo ≤30d</option>
                            <option value="inactive90">Inactivo &gt;90d</option>
                            <option value="inactive180">Inactivo &gt;180d</option>
                            <option value="never">Sin logon</option>
                          </select>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredComps.length === 0 ? (
                        <tr><td colSpan={7} className="py-8 text-center text-zinc-500 text-sm">Sin equipos con los filtros aplicados</td></tr>
                      ) : filteredComps.map((c: ADComputer) => {
                        const osRiskStyle =
                          c.os_risk === "critical" ? "text-red-400 font-semibold" :
                          c.os_risk === "high"     ? "text-orange-400" :
                          c.os_risk === "medium"   ? "text-yellow-400" : "text-zinc-600";
                        return (
                          <tr key={c.name} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                            <td className="py-1.5 pr-3 font-mono text-zinc-200 text-xs font-medium">{c.name}</td>
                            <td className="py-1.5 pr-3">
                              {c.is_dc
                                ? <span className="text-xs bg-purple-900 border border-purple-700 text-purple-300 px-1.5 py-0.5 rounded">DC</span>
                                : <span className="text-xs text-zinc-500">Equipo</span>}
                            </td>
                            <td className="py-1.5 pr-3 text-zinc-400 text-xs">{c.os || "—"}</td>
                            <td className={`py-1.5 pr-3 text-xs ${osRiskStyle}`}>{c.os_risk ? c.os_risk.toUpperCase() : "—"}</td>
                            <td className="py-1.5 pr-3 text-zinc-500 text-xs max-w-[120px] truncate" title={c.ou}>{c.ou || "—"}</td>
                            <td className="py-1.5 pr-3 text-zinc-500 text-xs font-mono">{c.ip || "—"}</td>
                            <td className="py-1.5 text-zinc-500 text-xs">{c.last_logon?.slice(0, 10) || "—"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* ── Grupos ── */}
            {activeTab === "groups" && (
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead>
                    <tr className="border-b border-zinc-700 text-zinc-500 text-xs">
                      <th className="py-2 pr-3">Grupo</th>
                      <th className="py-2 pr-3">Ámbito</th>
                      <th className="py-2 pr-3">Tipo</th>
                      <th className="py-2 pr-3">Miembros</th>
                      <th className="py-2 pr-3">Top miembros</th>
                      <th className="py-2">Descripción</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredGroups.map(g => {
                      const isPriv = ["domain admin", "enterprise admin", "schema admin", "administrators"].some(
                        x => g.name.toLowerCase().includes(x)
                      );
                      return (
                        <tr key={g.sam || g.name} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                          <td className="py-1.5 pr-3 font-medium text-zinc-200 text-sm">
                            {g.name}
                            {isPriv && <span className="ml-1.5 text-xs bg-red-900/40 text-red-400 border border-red-700 px-1 py-0.5 rounded">PRIV</span>}
                          </td>
                          <td className="py-1.5 pr-3 text-zinc-500 text-xs">{g.scope || "—"}</td>
                          <td className="py-1.5 pr-3 text-zinc-500 text-xs">{g.category || "—"}</td>
                          <td className="py-1.5 pr-3">
                            <span className={`text-xs px-2 py-0.5 rounded ${g.member_count > 0 ? "bg-blue-900/40 text-blue-300" : "text-zinc-600"}`}>
                              {g.member_count}
                            </span>
                          </td>
                          <td className="py-1.5 pr-3 text-zinc-500 text-xs max-w-xs truncate">
                            {g.members.slice(0, 4).join(", ") || "—"}
                            {g.members.length > 4 && <span className="text-zinc-600"> +{g.members.length - 4}</span>}
                          </td>
                          <td className="py-1.5 text-zinc-600 text-xs max-w-xs truncate" title={g.description}>
                            {g.description?.slice(0, 60) || "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* ── OUs ── */}
            {activeTab === "ous" && (
              <div className="space-y-4">
                <div className="flex flex-wrap gap-2 text-xs">
                  {[
                    { label: `${result.stats.total_ous} OUs totales`,                  cls: "bg-violet-900/40 border-violet-700 text-violet-300" },
                    { label: `${result.ous.filter(o => o.gpo_count > 0).length} con GPO`, cls: "bg-green-900/40 border-green-700 text-green-400" },
                    { label: `${result.ous.filter(o => o.gpo_count === 0).length} sin GPO`, cls: "bg-yellow-900/40 border-yellow-700 text-yellow-400" },
                    { label: `${result.stats.empty_ous} vacías`,                       cls: "bg-zinc-800 border-zinc-600 text-zinc-400" },
                    { label: `${result.ous.filter(o => o.protected).length} protegidas`, cls: "bg-blue-900/40 border-blue-700 text-blue-300" },
                  ].map(b => (
                    <span key={b.label} className={`px-2 py-0.5 rounded border ${b.cls}`}>{b.label}</span>
                  ))}
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead>
                      <tr className="border-b border-zinc-700 text-zinc-500 text-xs">
                        <th className="py-2 pr-3">Nombre</th>
                        <th className="py-2 pr-3">GPOs</th>
                        <th className="py-2 pr-3">Protegida</th>
                        <th className="py-2 pr-3">Gestionada por</th>
                        <th className="py-2 pr-3">Descripción</th>
                        <th className="py-2">Creada</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredOus.map(o => (
                        <tr key={o.dn || o.name} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                          <td className="py-1.5 pr-3 font-medium text-zinc-200 text-sm max-w-xs">
                            <span title={o.canonical}>{o.name}</span>
                          </td>
                          <td className="py-1.5 pr-3">
                            <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                              o.gpo_count > 0
                                ? "bg-green-900/40 text-green-400"
                                : "bg-yellow-900/40 text-yellow-400"
                            }`}>
                              {o.gpo_count} GPO{o.gpo_count !== 1 ? "s" : ""}
                            </span>
                          </td>
                          <td className="py-1.5 pr-3">
                            {o.protected
                              ? <span className="text-xs text-green-400">✓ Sí</span>
                              : <span className="text-xs text-zinc-500">No</span>}
                          </td>
                          <td className="py-1.5 pr-3 text-zinc-500 text-xs">{o.managed_by || "—"}</td>
                          <td className="py-1.5 pr-3 text-zinc-600 text-xs max-w-xs truncate" title={o.description}>
                            {o.description?.slice(0, 50) || "—"}
                          </td>
                          <td className="py-1.5 text-zinc-600 text-xs">{o.created?.slice(0, 10) || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* ── Política ── */}
            {activeTab === "policy" && (
              <div>
                {Object.keys(result.policy).length === 0 ? (
                  <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-8 text-center">
                    <Lock size={32} className="text-zinc-600 mx-auto mb-3" />
                    <p className="text-zinc-400 font-medium">No se cargó archivo de política de contraseñas</p>
                    <p className="text-zinc-500 text-sm mt-1">
                      Exporta con: <span className="font-mono text-zinc-300">Get-ADDefaultDomainPasswordPolicy | Export-Csv policy.csv</span>
                    </p>
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {[
                      {
                        title: "Política de Contraseñas",
                        icon: <Lock size={16} className="text-purple-400" />,
                        items: [
                          { label: "Longitud mínima",    value: `${result.policy.minPwdLength} caracteres`, warn: (result.policy.minPwdLength as number) < 12 },
                          { label: "Historial",           value: `${result.policy.pwdHistoryLength} anteriores` },
                          { label: "Edad máxima",         value: String(result.policy.maxPwdAge) },
                          { label: "Complejidad",         value: result.policy.pwdProperties === 1 ? "Habilitada ✓" : "Deshabilitada ✗", warn: result.policy.pwdProperties !== 1 },
                        ],
                      },
                      {
                        title: "Bloqueo de Cuentas",
                        icon: <XCircle size={16} className="text-red-400" />,
                        items: [
                          { label: "Umbral",    value: result.policy.lockoutThreshold === 0 ? "DESHABILITADO ✗" : `${result.policy.lockoutThreshold} intentos`, warn: result.policy.lockoutThreshold === 0 },
                          { label: "Duración",  value: String(result.policy.lockoutDuration) },
                        ],
                      },
                    ].map(card => (
                      <div key={card.title} className="bg-zinc-900 border border-zinc-700 rounded-xl p-4">
                        <div className="flex items-center gap-2 mb-3">
                          {card.icon}
                          <h3 className="font-medium text-zinc-200">{card.title}</h3>
                        </div>
                        <dl className="space-y-2">
                          {card.items.map(item => (
                            <div key={item.label} className="flex justify-between items-start gap-2 text-sm">
                              <dt className="text-zinc-500 shrink-0">{item.label}</dt>
                              <dd className={`text-right font-medium ${item.warn ? "text-red-400" : "text-zinc-200"}`}>{item.value}</dd>
                            </div>
                          ))}
                        </dl>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

          </div>
        </div>

        {/* ── Neo4j Panel ── */}
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <GitBranch size={18} className="text-green-400" />
              <h2 className="text-base font-semibold text-zinc-100">Importar a Neo4j</h2>
              <span className="text-xs text-zinc-500 font-mono">:ADUser · :ADComputer · :ADGroup · :ADOU</span>
            </div>
            <div className="flex items-center gap-2">
              {neo4jStatus && (
                <span className={`text-xs px-2 py-0.5 rounded border flex items-center gap-1 ${
                  neo4jStatus.connected
                    ? "bg-green-900/40 text-green-400 border-green-700"
                    : "bg-red-900/40 text-red-400 border-red-700"
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${neo4jStatus.connected ? "bg-green-400" : "bg-red-400"}`} />
                  {neo4jStatus.connected ? "Conectado" : "Sin conexión"}
                </span>
              )}
              <button onClick={checkNeo4j} className="text-zinc-500 hover:text-zinc-300 transition-colors">
                <RefreshCw size={14} />
              </button>
            </div>
          </div>

          {neo4jStatus?.connected && neo4jStatus.counts && (
            <div className="flex flex-wrap gap-2 text-xs">
              {Object.entries(neo4jStatus.counts).map(([lbl, cnt]) => (
                <span key={lbl} className={`px-2 py-0.5 rounded border font-mono ${
                  cnt > 0 ? "bg-green-900/20 text-green-400 border-green-800" : "bg-zinc-800 text-zinc-500 border-zinc-700"
                }`}>:{lbl} ({cnt})</span>
              ))}
            </div>
          )}
          {neo4jStatus?.connected === false && (
            <p className="text-xs text-red-400">{neo4jStatus.error}</p>
          )}

          <div className="space-y-2">
            <p className="text-xs text-zinc-500 font-semibold uppercase tracking-wider">Purga antes de importar</p>
            {([
              { value: "csv",  label: "Solo datos CSV anteriores", sub: "Elimina :AD* — preserva BloodHound", color: "text-yellow-400" },
              { value: "all",  label: "Todo (incluye BloodHound)",  sub: "Base de datos completamente limpia",  color: "text-red-400"    },
              { value: "none", label: "No purgar (agregar)",        sub: "Puede crear duplicados si ya hay datos", color: "text-zinc-400" },
            ] as const).map(opt => (
              <label key={opt.value} className="flex items-start gap-2.5 cursor-pointer">
                <input type="radio" name="purge_mode" value={opt.value}
                  checked={purgeMode === opt.value} onChange={() => setPurgeMode(opt.value)}
                  className="mt-0.5 accent-purple-500" />
                <span className="text-xs">
                  <span className={`font-medium ${opt.color}`}>{opt.label}</span>
                  <span className="text-zinc-500"> — {opt.sub}</span>
                </span>
              </label>
            ))}
          </div>

          {neo4jResult && (
            <div className="bg-green-900/20 border border-green-700 rounded-lg px-4 py-3 text-xs">
              <p className="text-green-400 font-semibold flex items-center gap-1.5 mb-1">
                <CheckCircle size={13} /> Importación completada
              </p>
              <p className="text-zinc-300">
                {neo4jResult.purged > 0 && <>Purgados: <span className="font-medium">{neo4jResult.purged}</span> · </>}
                Nodos: <span className="text-green-300 font-medium">{neo4jResult.imported.nodes}</span>{" · "}
                Relaciones: <span className="text-green-300 font-medium">{neo4jResult.imported.relationships}</span>
              </p>
            </div>
          )}
          {neo4jError && (
            <p className="text-red-400 text-xs flex items-center gap-1.5"><XCircle size={13} /> {neo4jError}</p>
          )}

          <div className="flex flex-wrap gap-2">
            <button onClick={importToNeo4j} disabled={neo4jLoading || !neo4jStatus?.connected}
              className="flex items-center gap-1.5 bg-green-800 hover:bg-green-700 disabled:opacity-40 disabled:cursor-not-allowed text-green-100 text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
              {neo4jLoading
                ? <><RefreshCw size={14} className="animate-spin" /> Importando…</>
                : <><GitBranch size={14} /> Importar {result.stats.total_users + result.stats.total_computers + result.stats.total_groups + result.stats.total_ous} nodos</>}
            </button>
            <button onClick={() => purgeNeo4j("csv")} disabled={neo4jLoading || !neo4jStatus?.connected}
              className="flex items-center gap-1.5 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-40 text-zinc-300 text-sm px-3 py-2 rounded-lg transition-colors">
              <Trash2 size={14} /> Purgar CSV
            </button>
            <button onClick={() => purgeNeo4j("all")} disabled={neo4jLoading || !neo4jStatus?.connected}
              className="flex items-center gap-1.5 bg-red-900/30 hover:bg-red-900/50 disabled:opacity-40 text-red-400 text-sm px-3 py-2 rounded-lg border border-red-900 transition-colors">
              <Trash2 size={14} /> Purgar todo
            </button>
            <a href="http://localhost:7474" target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-400 text-sm px-3 py-2 rounded-lg transition-colors">
              <ExternalLink size={14} /> Neo4j Browser
            </a>
          </div>

          <details className="text-xs">
            <summary className="text-zinc-500 cursor-pointer hover:text-zinc-300 select-none py-1">
              Consultas Cypher útiles
            </summary>
            <div className="mt-2 space-y-2 font-mono">
              {([
                ["Usuarios activos con riesgo",           "MATCH (u:ADUser {disabled: false}) WHERE u.no_expire = true OR u.no_preauth = true RETURN u.sam, u.ou, u.no_expire, u.no_preauth"],
                ["Domain Admins",                         "MATCH (u:ADUser)-[:MEMBER_OF]->(g:ADGroup) WHERE g.name CONTAINS 'Admin' RETURN u.sam, u.display_name, u.no_expire, u.last_logon"],
                ["Equipos EOL crítico",                   "MATCH (c:ADComputer {os_risk: 'critical'}) RETURN c.name, c.os, c.ou ORDER BY c.os"],
                ["OUs sin GPO con usuarios",              "MATCH (u:ADUser)-[:IN_OU]->(o:ADOU {gpo_count: 0}) RETURN o.name, count(u) AS usuarios ORDER BY usuarios DESC"],
                ["Árbol de OUs",                          "MATCH p=(:ADOU)-[:CHILD_OF*1..3]->(:ADOU) RETURN p LIMIT 100"],
                ["Ruta usuario → grupo admin",            "MATCH p=(u:ADUser)-[:MEMBER_OF*1..3]->(g:ADGroup) WHERE g.name CONTAINS 'Admin' RETURN p LIMIT 25"],
              ] as [string, string][]).map(([label, cypher]) => (
                <div key={label} className="bg-zinc-800 rounded px-3 py-2">
                  <p className="text-zinc-500 mb-0.5">{label}</p>
                  <p className="text-green-400 break-all select-all">{cypher}</p>
                </div>
              ))}
            </div>
          </details>
        </div>

        {/* Modal: Save Baseline */}
        {showBaselineModal && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
            <div className="bg-zinc-900 rounded-lg border border-zinc-700 w-full max-w-md">
              <div className="flex items-center justify-between p-4 border-b border-zinc-700">
                <div className="flex items-center gap-2">
                  <GitBranch size={18} className="text-blue-400" />
                  <h2 className="text-lg font-bold text-zinc-100">Guardar Baseline</h2>
                </div>
                <button
                  onClick={() => {
                    setShowBaselineModal(false);
                    setBaselineError(null);
                  }}
                  className="text-zinc-500 hover:text-zinc-300"
                >
                  <X size={18} />
                </button>
              </div>
              <div className="p-4 space-y-4">
                {baselineError && (
                  <div className="bg-red-900/30 border border-red-700 rounded px-3 py-2 text-sm text-red-200">
                    {baselineError}
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-zinc-300 mb-2">
                    Nombre del baseline
                  </label>
                  <input
                    type="text"
                    value={baselineName}
                    onChange={(e) => setBaselineName(e.target.value)}
                    placeholder="p.ej. AD Snapshot 2024-08-03"
                    className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-zinc-100 text-sm focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-zinc-300 mb-2">
                    Tags (opcional)
                  </label>
                  <input
                    type="text"
                    value={baselineTags}
                    onChange={(e) => setBaselineTags(e.target.value)}
                    placeholder="p.ej. producción, octubre2024"
                    className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-zinc-100 text-sm focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>
              <div className="flex gap-2 p-4 border-t border-zinc-700">
                <button
                  onClick={() => {
                    setShowBaselineModal(false);
                    setBaselineError(null);
                  }}
                  className="flex-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-3 py-2 rounded transition-colors"
                >
                  Cancelar
                </button>
                <button
                  onClick={saveBaseline}
                  disabled={baselineLoading || !baselineName.trim()}
                  className="flex-1 flex items-center justify-center gap-2 bg-blue-900 hover:bg-blue-800 disabled:opacity-40 disabled:cursor-not-allowed text-blue-200 px-3 py-2 rounded transition-colors"
                >
                  {baselineLoading ? (
                    <>
                      <RefreshCw size={14} className="animate-spin" />
                      Guardando…
                    </>
                  ) : (
                    <>
                      <CheckCircle size={14} />
                      Guardar
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        )}

      </>)}
    </div>
  );
}
