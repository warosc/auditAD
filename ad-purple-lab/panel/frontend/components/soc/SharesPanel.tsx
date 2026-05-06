"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import {
  Upload,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  FolderOpen,
  Lock,
  Unlock,
  Eye,
  EyeOff,
  Server,
  KeyRound,
  Users,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────────────────

interface ShareEntry {
  name: string;
  path: string;
  description: string;
  encrypt: boolean;
  is_hidden: boolean;
  is_admin: boolean;
  is_root_path: boolean;
  is_sensitive: boolean;
  current_users: number;
}

interface ShareAcl {
  share: string;
  account: string;
  access_right: string;
  access_type: string;
  is_deny: boolean;
  is_dangerous: boolean;
  has_write: boolean;
  is_orphaned_sid: boolean;
}

interface NtfsAce {
  share: string;
  path: string;
  identity: string;
  rights: string;
  access_type: string;
  is_deny: boolean;
  is_inherited: boolean;
  is_dangerous: boolean;
  has_write: boolean;
  is_orphaned_sid: boolean;
  is_sensitive: boolean;
}

interface Finding {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  title: string;
  mitre: string;
  description: string;
  recommendation: string;
  affected: string[];
  count: number;
}

interface Stats {
  total_shares: number;
  admin_shares: number;
  encrypted: number;
  unencrypted: number;
  hidden_shares: number;
  total_share_acl: number;
  total_ntfs_ace: number;
  risky_shares: number;
  orphaned_sids: number;
}

interface SharesResult {
  available: boolean;
  analyzed_at: string;
  stats: Stats;
  severity_counts: Record<string, number>;
  risk_score: number;
  findings: Finding[];
  shares: ShareEntry[];
  share_acls: ShareAcl[];
  ntfs: NtfsAce[];
}

// ── Helpers ────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: "text-red-400 border-red-800 bg-red-950/40",
  high:     "text-orange-400 border-orange-800 bg-orange-950/40",
  medium:   "text-yellow-400 border-yellow-800 bg-yellow-950/40",
  low:      "text-green-400 border-green-800 bg-green-950/40",
  info:     "text-blue-400 border-blue-800 bg-blue-950/40",
};

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-900/60 text-red-300 border border-red-700",
  high:     "bg-orange-900/60 text-orange-300 border border-orange-700",
  medium:   "bg-yellow-900/60 text-yellow-300 border border-yellow-700",
  low:      "bg-green-900/60 text-green-300 border border-green-700",
  info:     "bg-blue-900/60 text-blue-300 border border-blue-700",
};

const SEV_LABEL: Record<string, string> = {
  critical: "CRÍTICO",
  high:     "ALTO",
  medium:   "MEDIO",
  low:      "BAJO",
  info:     "INFO",
};

function SevBadge({ sev }: { sev: string }) {
  return (
    <span className={cn("px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider", SEV_BADGE[sev] ?? SEV_BADGE.info)}>
      {SEV_LABEL[sev] ?? sev}
    </span>
  );
}

function StatCard({ label, value, icon: Icon, color = "text-soc-accent" }: {
  label: string;
  value: number | string;
  icon: React.ElementType;
  color?: string;
}) {
  return (
    <div className="bg-soc-card border border-soc-border rounded p-3 flex flex-col gap-1">
      <div className="flex items-center gap-1.5">
        <Icon className={cn("w-3.5 h-3.5", color)} />
        <span className="text-[10px] text-soc-dim uppercase tracking-wider">{label}</span>
      </div>
      <span className={cn("text-xl font-bold font-mono", color)}>{value}</span>
    </div>
  );
}

// ── PowerShell scripts ─────────────────────────────────────────────────────

const PS_SHARES = `# Script 1 — Exportar recursos compartidos SMB
# Ejecutar como Administrador en el servidor de archivos o DC
Get-SmbShare | Select-Object Name, Path, Description, CurrentUsers,
  EncryptData, CachingMode, FolderEnumerationMode |
  Export-Csv -Path ".\\AD_Shares.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Listo: AD_Shares.csv"`;

const PS_SHARE_ACL = `# Script 2 — Exportar ACLs de nivel de compartición SMB
# Ejecutar como Administrador en el servidor de archivos o DC
Get-SmbShare | ForEach-Object {
    $share = $_.Name
    Get-SmbShareAccess -Name $share -ErrorAction SilentlyContinue |
      Select-Object @{n='ShareName';e={$share}},
                    AccountName, AccessControlType, AccessRight
} | Export-Csv -Path ".\\AD_ShareACL.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Listo: AD_ShareACL.csv"`;

const PS_NTFS = `# Script 3 — Exportar ACLs NTFS de cada recurso compartido
# Ejecutar como Administrador en el servidor de archivos o DC
Get-SmbShare |
  Where-Object { $_.Path -and (Test-Path $_.Path -ErrorAction SilentlyContinue) } |
  ForEach-Object {
    $shareName = $_.Name
    $sharePath = $_.Path
    try {
      (Get-Acl -Path $sharePath).Access | ForEach-Object {
        [PSCustomObject]@{
          ShareName         = $shareName
          Path              = $sharePath
          IdentityReference = $_.IdentityReference
          FileSystemRights  = $_.FileSystemRights
          AccessControlType = $_.AccessControlType
          IsInherited       = $_.IsInherited
          InheritanceFlags  = $_.InheritanceFlags
        }
      }
    } catch { }
  } |
  Export-Csv -Path ".\\AD_NTFS.csv" -NoTypeInformation -Encoding UTF8
Write-Host "Listo: AD_NTFS.csv"`;

function ScriptBlock({ label, code }: { label: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <div className="rounded border border-soc-border overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 bg-soc-surface border-b border-soc-border">
        <span className="text-[11px] font-mono text-soc-accent">{label}</span>
        <button onClick={copy} className="flex items-center gap-1 text-[10px] text-soc-dim hover:text-soc-text transition-colors">
          {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
          {copied ? "Copiado" : "Copiar"}
        </button>
      </div>
      <pre className="text-[10.5px] font-mono text-green-300 bg-[#0a0a0f] px-3 py-2 overflow-x-auto whitespace-pre-wrap leading-relaxed">
        {code}
      </pre>
    </div>
  );
}

// ── Finding card ───────────────────────────────────────────────────────────

function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={cn("rounded border text-sm", SEV_COLOR[f.severity])}>
      <button
        className="w-full flex items-center gap-2 px-3 py-2 text-left hover:brightness-110 transition"
        onClick={() => setOpen(!open)}
      >
        {open ? <ChevronDown className="w-3.5 h-3.5 shrink-0" /> : <ChevronRight className="w-3.5 h-3.5 shrink-0" />}
        <SevBadge sev={f.severity} />
        <span className="font-mono text-[11px] text-soc-dim mr-1">{f.id}</span>
        <span className="font-semibold text-[12px] flex-1">{f.title}</span>
        <span className="text-[10px] text-soc-dim font-mono hidden sm:block">{f.mitre}</span>
      </button>
      {open && (
        <div className="px-4 pb-3 pt-1 space-y-2 border-t border-current/20">
          <p className="text-[12px] text-soc-text leading-relaxed">
            {f.description.split(/\*\*([^*]+)\*\*/g).map((part, i) =>
              i % 2 === 1 ? <strong key={i} className="text-white">{part}</strong> : part
            )}
          </p>
          <div className="rounded bg-black/30 px-3 py-2">
            <p className="text-[10px] text-soc-dim uppercase tracking-wider mb-1">Recomendación</p>
            <p className="text-[12px] text-soc-text">{f.recommendation}</p>
          </div>
          {f.affected.length > 0 && (
            <div>
              <p className="text-[10px] text-soc-dim uppercase tracking-wider mb-1">
                Afectados ({f.affected.length})
              </p>
              <div className="flex flex-wrap gap-1">
                {f.affected.slice(0, 20).map((a) => (
                  <span key={a} className="px-1.5 py-0.5 rounded bg-black/40 text-[10px] font-mono text-soc-dim border border-current/20">
                    {a}
                  </span>
                ))}
                {f.affected.length > 20 && (
                  <span className="px-1.5 py-0.5 rounded bg-black/40 text-[10px] font-mono text-soc-dim">
                    +{f.affected.length - 20} más
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Risk gauge ─────────────────────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const color = score >= 70 ? "text-red-400" : score >= 40 ? "text-orange-400" : score >= 20 ? "text-yellow-400" : "text-green-400";
  const label = score >= 70 ? "CRÍTICO" : score >= 40 ? "ALTO" : score >= 20 ? "MEDIO" : "BAJO";
  return (
    <div className="flex items-center gap-3">
      <div className="relative w-16 h-16">
        <svg viewBox="0 0 36 36" className="w-16 h-16 -rotate-90">
          <circle cx="18" cy="18" r="15.9" fill="none" stroke="#1f2937" strokeWidth="3" />
          <circle
            cx="18" cy="18" r="15.9" fill="none"
            stroke="currentColor"
            strokeWidth="3"
            strokeDasharray={`${score} ${100 - score}`}
            className={color}
            strokeLinecap="round"
          />
        </svg>
        <span className={cn("absolute inset-0 flex items-center justify-center text-sm font-bold font-mono", color)}>
          {score}
        </span>
      </div>
      <div>
        <p className="text-[10px] text-soc-dim uppercase tracking-wider">Riesgo Global</p>
        <p className={cn("text-lg font-bold", color)}>{label}</p>
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

type Tab = "scripts" | "findings" | "shares" | "acls" | "ntfs";

export default function SharesPanel() {
  const [tab, setTab]       = useState<Tab>("scripts");
  const [result, setResult] = useState<SharesResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]   = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [sevFilter, setSevFilter] = useState<string>("all");
  const fileRef = useRef<HTMLInputElement>(null);

  // Hydrate from backend cache on mount
  useEffect(() => {
    fetch("/api/shares/result", { cache: "no-store" })
      .then(r => r.ok ? r.json() as Promise<SharesResult> : Promise.reject())
      .then(data => {
        if (data?.available) {
          setResult(data);
          setTab("findings");
        }
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const analyze = useCallback(async (files: FileList | File[]) => {
    const csvFiles = Array.from(files).filter(f => f.name.toLowerCase().endsWith(".csv"));
    if (!csvFiles.length) {
      setError("Selecciona archivos CSV exportados con los scripts de PowerShell.");
      return;
    }
    setLoading(true);
    setError("");
    const fd = new FormData();
    csvFiles.forEach(f => fd.append("files", f));
    try {
      const res = await fetch("/api/shares/analyze", { method: "POST", body: fd });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.detail || `Error ${res.status}`);
      }
      const data: SharesResult = await res.json();
      setResult(data);
      setTab("findings");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files) analyze(e.dataTransfer.files);
  }, [analyze]);

  const onFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) analyze(e.target.files);
  }, [analyze]);

  const tabs: { id: Tab; label: string }[] = [
    { id: "scripts",  label: "Scripts PS" },
    { id: "findings", label: `Hallazgos${result ? ` (${result.findings.length})` : ""}` },
    { id: "shares",   label: `Recursos${result ? ` (${result.shares.length})` : ""}` },
    { id: "acls",     label: `ACL Share${result ? ` (${result.share_acls.length})` : ""}` },
    { id: "ntfs",     label: `ACL NTFS${result ? ` (${result.ntfs.length})` : ""}` },
  ];

  const filteredFindings = result?.findings.filter(
    f => sevFilter === "all" || f.severity === sevFilter
  ) ?? [];

  return (
    <div className="flex flex-col h-full font-mono">

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border">
        <div className="flex items-center gap-2">
          <FolderOpen className="w-4 h-4 text-soc-purple" />
          <span className="text-sm font-semibold text-soc-text">Permisos de Carpetas y Recursos Compartidos</span>
        </div>
        {result && (
          <span className="text-[10px] text-soc-dim">
            Analizado: {new Date(result.analyzed_at).toLocaleString()}
          </span>
        )}
      </div>

      {/* Upload zone (only if no result yet) */}
      {!result && (
        <div
          className={cn(
            "mx-4 mt-4 border-2 border-dashed rounded p-6 text-center cursor-pointer transition-colors",
            dragOver ? "border-soc-accent bg-soc-accent/5" : "border-soc-border hover:border-soc-accent/50",
          )}
          onClick={() => fileRef.current?.click()}
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
        >
          <Upload className="w-8 h-8 text-soc-dim mx-auto mb-2" />
          <p className="text-sm text-soc-text mb-1">Arrastra los 3 CSV aquí o haz clic</p>
          <p className="text-[11px] text-soc-dim">AD_Shares.csv · AD_ShareACL.csv · AD_NTFS.csv</p>
          <input ref={fileRef} type="file" multiple accept=".csv" className="hidden" onChange={onFileChange} />
        </div>
      )}

      {/* Re-upload button if result exists */}
      {result && (
        <div className="px-4 pt-3 flex items-center gap-3">
          <button
            className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-soc-border text-[11px] text-soc-dim hover:text-soc-text hover:border-soc-accent/50 transition-colors"
            onClick={() => fileRef.current?.click()}
            disabled={loading}
          >
            <Upload className="w-3 h-3" />
            {loading ? "Analizando…" : "Re-analizar"}
          </button>
          <input ref={fileRef} type="file" multiple accept=".csv" className="hidden" onChange={onFileChange} />
          {error && <span className="text-[11px] text-red-400">{error}</span>}
        </div>
      )}

      {error && !result && (
        <p className="mx-4 mt-2 text-[11px] text-red-400">{error}</p>
      )}

      {loading && (
        <div className="mx-4 mt-4 flex items-center gap-2 text-[12px] text-soc-dim">
          <div className="w-3 h-3 border-2 border-soc-accent border-t-transparent rounded-full animate-spin" />
          Analizando permisos…
        </div>
      )}

      {/* Summary cards */}
      {result && (
        <div className="px-4 pt-3 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-2">
          <StatCard label="Recursos"      value={result.stats.total_shares}   icon={FolderOpen} />
          <StatCard label="Cifrados"      value={result.stats.encrypted}       icon={Lock}       color="text-green-400" />
          <StatCard label="Sin cifrar"    value={result.stats.unencrypted}     icon={Unlock}     color={result.stats.unencrypted > 0 ? "text-orange-400" : "text-green-400"} />
          <StatCard label="Ocultos"       value={result.stats.hidden_shares}   icon={EyeOff}     color="text-yellow-400" />
          <StatCard label="ACE Share"     value={result.stats.total_share_acl} icon={Users}      />
          <StatCard label="ACE NTFS"      value={result.stats.total_ntfs_ace}  icon={KeyRound}   />
          <StatCard label="SIDs huérfanos" value={result.stats.orphaned_sids} icon={AlertTriangle} color={result.stats.orphaned_sids > 0 ? "text-yellow-400" : "text-green-400"} />
          <StatCard label="Con riesgo"    value={result.stats.risky_shares}    icon={ShieldAlert} color={result.stats.risky_shares > 0 ? "text-red-400" : "text-green-400"} />
        </div>
      )}

      {/* Risk gauge + severity summary */}
      {result && (
        <div className="px-4 pt-3 flex flex-wrap items-center gap-4">
          <RiskGauge score={result.risk_score} />
          <div className="flex flex-wrap gap-2">
            {["critical","high","medium","low","info"].map(s => (
              <div key={s} className={cn("flex items-center gap-1.5 px-2 py-1 rounded border text-[11px]", SEV_COLOR[s])}>
                <span className="font-bold">{result.severity_counts[s] ?? 0}</span>
                <span className="text-soc-dim">{SEV_LABEL[s]}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 px-4 pt-3 border-b border-soc-border">
        {tabs.map(({ id, label }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={cn(
              "px-3 py-1.5 text-[11px] rounded-t transition-colors",
              tab === id
                ? "bg-soc-accent/10 text-soc-accent border border-b-0 border-soc-accent/30"
                : "text-soc-dim hover:text-soc-text",
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">

        {/* ── Scripts ── */}
        {tab === "scripts" && (
          <div className="space-y-4">
            <div className="rounded border border-blue-800 bg-blue-950/30 px-3 py-2 text-[12px] text-blue-300">
              <strong>Instrucciones para el Administrador de AD:</strong> Ejecuta los siguientes 3 scripts de PowerShell
              como <strong>Administrador</strong> en el servidor de archivos o en el Controlador de Dominio.
              Luego sube los 3 CSV generados aquí para el análisis de seguridad.
            </div>
            <ScriptBlock label="AD_Shares.csv — Lista de recursos compartidos SMB" code={PS_SHARES} />
            <ScriptBlock label="AD_ShareACL.csv — ACLs a nivel de compartición" code={PS_SHARE_ACL} />
            <ScriptBlock label="AD_NTFS.csv — ACLs NTFS de cada recurso" code={PS_NTFS} />
            <div className="rounded border border-soc-border bg-soc-card p-3 text-[11px] text-soc-dim space-y-1">
              <p className="text-soc-text font-semibold text-[12px] mb-2">¿Qué analiza este módulo?</p>
              <p>• Recursos sin cifrado SMB (captura de tráfico)</p>
              <p>• Everyone/Authenticated Users con permisos de escritura o control total</p>
              <p>• Recursos apuntando a raíces de unidad (C:\, D:\, etc.)</p>
              <p>• Rutas sensibles (backup, passwords, scripts, RRHH, finanzas) con permisos excesivos</p>
              <p>• SIDs huérfanos (cuentas eliminadas que aún tienen permisos)</p>
              <p>• Recursos ocultos ($) no administrativos</p>
              <p>• Recursos sin documentación (descripción vacía)</p>
            </div>
          </div>
        )}

        {/* ── Findings ── */}
        {tab === "findings" && (
          <div className="space-y-2">
            {!result && (
              <p className="text-[12px] text-soc-dim py-8 text-center">
                Sube los CSV para ver hallazgos de seguridad
              </p>
            )}
            {result && (
              <>
                {/* Severity filter */}
                <div className="flex gap-1 flex-wrap">
                  {["all","critical","high","medium","low","info"].map(s => (
                    <button
                      key={s}
                      onClick={() => setSevFilter(s)}
                      className={cn(
                        "px-2.5 py-1 rounded text-[10px] font-semibold uppercase transition-colors",
                        sevFilter === s
                          ? s === "all" ? "bg-soc-accent text-black" : SEV_BADGE[s]
                          : "bg-soc-card text-soc-dim border border-soc-border hover:text-soc-text",
                      )}
                    >
                      {s === "all" ? "Todos" : SEV_LABEL[s]}
                      {s !== "all" && ` (${result.severity_counts[s] ?? 0})`}
                    </button>
                  ))}
                </div>

                {filteredFindings.length === 0 ? (
                  <div className="flex items-center gap-2 py-6 justify-center text-[12px] text-green-400">
                    <ShieldCheck className="w-4 h-4" /> Sin hallazgos para el filtro seleccionado
                  </div>
                ) : (
                  filteredFindings.map(f => <FindingCard key={f.id} f={f} />)
                )}
              </>
            )}
          </div>
        )}

        {/* ── Shares table ── */}
        {tab === "shares" && (
          <div className="overflow-x-auto">
            {!result ? (
              <p className="text-[12px] text-soc-dim py-8 text-center">Sin datos</p>
            ) : (
              <table className="w-full text-[11px] font-mono border-collapse">
                <thead>
                  <tr className="border-b border-soc-border text-left">
                    {["Nombre","Ruta","Descripción","Cifrado","Oculto","Admin","Raíz","Sensible"].map(h => (
                      <th key={h} className="px-2 py-1.5 text-[10px] text-soc-dim uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.shares.map((s, i) => (
                    <tr key={i} className={cn("border-b border-soc-border/50 hover:bg-soc-card/50", s.is_sensitive && "bg-orange-950/20")}>
                      <td className="px-2 py-1.5 text-soc-text font-semibold">{s.name}</td>
                      <td className="px-2 py-1.5 text-soc-dim max-w-[200px] truncate">{s.path || "—"}</td>
                      <td className="px-2 py-1.5 text-soc-dim max-w-[180px] truncate">{s.description || <span className="text-soc-dim/40">sin descripción</span>}</td>
                      <td className="px-2 py-1.5">
                        {s.encrypt
                          ? <span className="text-green-400 flex items-center gap-0.5"><Lock className="w-3 h-3"/> Sí</span>
                          : <span className="text-orange-400 flex items-center gap-0.5"><Unlock className="w-3 h-3"/> No</span>
                        }
                      </td>
                      <td className="px-2 py-1.5">{s.is_hidden ? <span className="text-yellow-400">Sí</span> : "—"}</td>
                      <td className="px-2 py-1.5">{s.is_admin  ? <span className="text-blue-400">Sí</span>  : "—"}</td>
                      <td className="px-2 py-1.5">{s.is_root_path ? <span className="text-red-400">SÍ</span> : "—"}</td>
                      <td className="px-2 py-1.5">{s.is_sensitive ? <span className="text-orange-400">SÍ</span> : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ── Share ACLs table ── */}
        {tab === "acls" && (
          <div className="overflow-x-auto">
            {!result ? (
              <p className="text-[12px] text-soc-dim py-8 text-center">Sin datos</p>
            ) : (
              <table className="w-full text-[11px] font-mono border-collapse">
                <thead>
                  <tr className="border-b border-soc-border text-left">
                    {["Recurso","Cuenta","Tipo","Derecho","Escritura","Riesgo","SID Huérf."].map(h => (
                      <th key={h} className="px-2 py-1.5 text-[10px] text-soc-dim uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.share_acls.map((a, i) => (
                    <tr key={i} className={cn(
                      "border-b border-soc-border/50 hover:bg-soc-card/50",
                      a.is_dangerous && a.has_write && "bg-red-950/20",
                      a.is_dangerous && !a.has_write && "bg-yellow-950/10",
                    )}>
                      <td className="px-2 py-1.5 text-soc-text font-semibold">{a.share}</td>
                      <td className="px-2 py-1.5 text-soc-dim">{a.account}</td>
                      <td className="px-2 py-1.5">
                        <span className={a.is_deny ? "text-red-400" : "text-green-400"}>
                          {a.is_deny ? "Deny" : "Allow"}
                        </span>
                      </td>
                      <td className="px-2 py-1.5 text-soc-dim">{a.access_right}</td>
                      <td className="px-2 py-1.5">{a.has_write ? <span className="text-red-400 font-bold">SÍ</span> : <span className="text-soc-dim/40">No</span>}</td>
                      <td className="px-2 py-1.5">{a.is_dangerous ? <span className="text-orange-400">ALTO</span> : "—"}</td>
                      <td className="px-2 py-1.5">{a.is_orphaned_sid ? <span className="text-yellow-400">SÍ</span> : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* ── NTFS ACLs table ── */}
        {tab === "ntfs" && (
          <div className="overflow-x-auto">
            {!result ? (
              <p className="text-[12px] text-soc-dim py-8 text-center">Sin datos</p>
            ) : (
              <table className="w-full text-[11px] font-mono border-collapse">
                <thead>
                  <tr className="border-b border-soc-border text-left">
                    {["Recurso","Ruta","Identidad","Derechos","Tipo","Heredado","Escritura","Riesgo","Sensible"].map(h => (
                      <th key={h} className="px-2 py-1.5 text-[10px] text-soc-dim uppercase tracking-wider whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.ntfs.map((n, i) => (
                    <tr key={i} className={cn(
                      "border-b border-soc-border/50 hover:bg-soc-card/50",
                      n.is_dangerous && n.has_write && "bg-red-950/20",
                      n.is_sensitive && "bg-orange-950/10",
                    )}>
                      <td className="px-2 py-1.5 text-soc-text font-semibold">{n.share || "—"}</td>
                      <td className="px-2 py-1.5 text-soc-dim max-w-[150px] truncate">{n.path || "—"}</td>
                      <td className="px-2 py-1.5 text-soc-dim">{n.identity}</td>
                      <td className="px-2 py-1.5 text-soc-dim max-w-[120px] truncate">{n.rights}</td>
                      <td className="px-2 py-1.5">
                        <span className={n.is_deny ? "text-red-400" : "text-green-400"}>
                          {n.is_deny ? "Deny" : "Allow"}
                        </span>
                      </td>
                      <td className="px-2 py-1.5">{n.is_inherited ? <span className="text-soc-dim/60">Sí</span> : <span className="text-yellow-300">No</span>}</td>
                      <td className="px-2 py-1.5">{n.has_write ? <span className="text-red-400 font-bold">SÍ</span> : <span className="text-soc-dim/40">No</span>}</td>
                      <td className="px-2 py-1.5">{n.is_dangerous ? <span className="text-orange-400">ALTO</span> : "—"}</td>
                      <td className="px-2 py-1.5">{n.is_sensitive ? <span className="text-orange-400">SÍ</span> : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
