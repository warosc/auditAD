"use client";

import { useEffect, useState, useMemo } from "react";
import {
  AlertTriangle, CheckCircle, XCircle, Info, Shield, Users, Monitor,
  Network, Lock, Search, RefreshCw, ChevronDown, ChevronUp,
  Database, Activity, Zap, Key
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
  sam: string; dn: string; ou: string; uac: number; uac_flags: string[];
  disabled: boolean; no_expire: boolean; no_preauth: boolean; spn: string[];
  last_logon: string; pwd_last_set: string; upn: string;
}

interface ADComputer {
  name: string; dn: string; sam: string; os: string; os_ver: string;
  uac: number; is_dc: boolean; last_logon: string;
}

interface ADGroup { name: string; sam: string; dn: string; member_count: number; members: string[]; }

interface Policy {
  domain: string; dn: string; minPwdLength: number; maxPwdAge: string;
  pwdHistoryLength: number; pwdProperties: number; lockoutThreshold: number;
  lockoutDuration: string; behaviorVersion: number; machineAccountQuota: number;
  objectSid: string;
}

interface Port { port: number; state: string; service: string; }

interface SeverityCounts { critical: number; high: number; medium: number; low: number; info: number; }

interface Stats {
  total_users: number; active_users: number; disabled_users: number;
  privileged_users: number; total_computers: number; domain_controllers: number;
  total_groups: number; ports_open: number; ports_filtered: number;
}

interface CrackedCred { user: string; password: string; }
interface AttackModule {
  run: boolean; hashes: number; cracked: CrackedCred[]; vulnerable_accounts: string[];
}
interface AttackResults {
  available: boolean; total_cracked: number;
  asrep: AttackModule; kerberoast: AttackModule;
}

interface Results {
  available: boolean; message?: string; timestamp: string; dump_dir: string;
  findings: Finding[]; severity_counts: SeverityCounts; stats: Stats;
  users: ADUser[]; computers: ADComputer[]; groups: ADGroup[];
  policy: Policy; ports: Port[]; bloodhound_available: boolean;
  summary: { errors: number; warnings: number; timestamp: string };
}

// ── Severity styling ────────────────────────────────────────────────────────

const SEV_STYLE: Record<string, { bg: string; text: string; border: string; label: string }> = {
  critical: { bg: "bg-red-950",    text: "text-red-300",    border: "border-red-700",    label: "CRÍTICO"  },
  high:     { bg: "bg-orange-950", text: "text-orange-300", border: "border-orange-700", label: "ALTO"     },
  medium:   { bg: "bg-yellow-950", text: "text-yellow-300", border: "border-yellow-700", label: "MEDIO"    },
  low:      { bg: "bg-blue-950",   text: "text-blue-300",   border: "border-blue-700",   label: "BAJO"     },
  info:     { bg: "bg-zinc-900",   text: "text-zinc-300",   border: "border-zinc-700",   label: "INFO"     },
};

const SevBadge = ({ s }: { s: string }) => {
  const st = SEV_STYLE[s] ?? SEV_STYLE.info;
  return (
    <span className={`text-xs font-bold px-2 py-0.5 rounded ${st.bg} ${st.text} border ${st.border}`}>
      {st.label}
    </span>
  );
};

// ── Finding card ─────────────────────────────────────────────────────────────

function FindingCard({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const st = SEV_STYLE[f.severity] ?? SEV_STYLE.info;
  return (
    <div className={`rounded-lg border ${st.border} ${st.bg} mb-2`}>
      <button
        className="w-full flex items-center gap-3 p-3 text-left"
        onClick={() => setOpen(!open)}
      >
        <SevBadge s={f.severity} />
        <span className="text-xs text-zinc-500 font-mono">{f.id}</span>
        <span className={`flex-1 text-sm font-medium ${st.text}`}>{f.title}</span>
        <span className="text-xs text-zinc-500">{f.category}</span>
        {open ? <ChevronUp size={14} className="text-zinc-500" /> : <ChevronDown size={14} className="text-zinc-500" />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2 text-sm text-zinc-300">
          <p>{f.description}</p>
          <div className="flex gap-2 flex-wrap mt-2">
            <span className="bg-zinc-800 text-green-400 text-xs px-2 py-1 rounded">
              ✓ {f.recommendation}
            </span>
            <span className="bg-zinc-800 text-purple-400 text-xs px-2 py-1 rounded font-mono">
              {f.mitre}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Tab button ───────────────────────────────────────────────────────────────

function Tab({ label, active, onClick, count }: { label: string; active: boolean; onClick: () => void; count?: number }) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-sm font-medium rounded-t-lg border-b-2 transition-colors ${
        active
          ? "border-purple-500 text-purple-300 bg-zinc-800"
          : "border-transparent text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50"
      }`}
    >
      {label}
      {count !== undefined && (
        <span className={`ml-2 text-xs px-1.5 py-0.5 rounded-full ${active ? "bg-purple-700 text-purple-200" : "bg-zinc-700 text-zinc-400"}`}>
          {count}
        </span>
      )}
    </button>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function ResultsPage() {
  const [data, setData] = useState<Results | null>(null);
  const [attacks, setAttacks] = useState<AttackResults | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("findings");
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState<string>("all");

  const load = async () => {
    setLoading(true);
    try {
      const [r, a] = await Promise.all([
        fetch("/api/audit/results/latest"),
        fetch("/api/audit/results/attacks"),
      ]);
      setData(await r.json());
      setAttacks(await a.json());
    } catch {
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const filteredFindings = useMemo(() => {
    if (!data?.findings) return [];
    return data.findings.filter(f => {
      const matchSev = sevFilter === "all" || f.severity === sevFilter;
      const matchQ   = !search || f.title.toLowerCase().includes(search.toLowerCase())
                      || f.description.toLowerCase().includes(search.toLowerCase());
      return matchSev && matchQ;
    });
  }, [data?.findings, sevFilter, search]);

  const filteredUsers = useMemo(() => {
    if (!data?.users) return [];
    const q = search.toLowerCase();
    return data.users.filter(u =>
      !search || u.sam.toLowerCase().includes(q) || u.ou.toLowerCase().includes(q)
    );
  }, [data?.users, search]);

  const filteredGroups = useMemo(() => {
    if (!data?.groups) return [];
    const q = search.toLowerCase();
    return data.groups.filter(g => !search || g.name.toLowerCase().includes(q));
  }, [data?.groups, search]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-zinc-400 flex items-center gap-2">
          <RefreshCw size={16} className="animate-spin" /> Cargando resultados...
        </div>
      </div>
    );
  }

  if (!data?.available) {
    return (
      <div className="p-8">
        <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-8 text-center">
          <Database size={40} className="text-zinc-600 mx-auto mb-3" />
          <p className="text-zinc-300 font-medium">Sin datos de auditoría disponibles</p>
          <p className="text-zinc-500 text-sm mt-1">
            {data?.message ?? "Ejecuta una auditoría desde el panel de Auditoría AD."}
          </p>
          <a href="/audit" className="mt-4 inline-block bg-purple-700 hover:bg-purple-600 text-white text-sm px-4 py-2 rounded-lg transition-colors">
            Ir a Auditoría →
          </a>
        </div>
      </div>
    );
  }

  const sc = data.severity_counts;
  const totalRisk = sc.critical * 4 + sc.high * 3 + sc.medium * 2 + sc.low;
  const riskLabel = totalRisk === 0 ? "Bajo" : totalRisk < 5 ? "Moderado" : totalRisk < 12 ? "Alto" : "Crítico";
  const riskColor = totalRisk === 0 ? "text-green-400" : totalRisk < 5 ? "text-yellow-400" : totalRisk < 12 ? "text-orange-400" : "text-red-400";

  return (
    <div className="p-6 space-y-6 max-w-7xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Shield size={24} className="text-purple-400" />
            Resultados de Auditoría
          </h1>
          <p className="text-sm text-zinc-500 mt-1">
            Datos recopilados: {data.timestamp} · {data.dump_dir}
          </p>
        </div>
        <button onClick={load} className="flex items-center gap-2 text-sm bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-3 py-2 rounded-lg transition-colors">
          <RefreshCw size={14} /> Actualizar
        </button>
      </div>

      {/* Summary metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        {[
          { label: "Usuarios", value: data.stats.total_users, icon: <Users size={16}/>, color: "text-blue-400" },
          { label: "Activos",  value: data.stats.active_users, icon: <CheckCircle size={16}/>, color: "text-green-400" },
          { label: "Equipos",  value: data.stats.total_computers, icon: <Monitor size={16}/>, color: "text-cyan-400" },
          { label: "Grupos",   value: data.stats.total_groups, icon: <Network size={16}/>, color: "text-indigo-400" },
          { label: "Críticos", value: sc.critical, icon: <XCircle size={16}/>, color: "text-red-400" },
          { label: "Altos",    value: sc.high, icon: <AlertTriangle size={16}/>, color: "text-orange-400" },
          { label: "Medios",   value: sc.medium, icon: <AlertTriangle size={16}/>, color: "text-yellow-400" },
          { label: "Info",     value: sc.info, icon: <Info size={16}/>, color: "text-zinc-400" },
        ].map(m => (
          <div key={m.label} className="bg-zinc-900 border border-zinc-700 rounded-lg p-3 text-center">
            <div className={`flex justify-center mb-1 ${m.color}`}>{m.icon}</div>
            <div className={`text-xl font-bold ${m.color}`}>{m.value}</div>
            <div className="text-xs text-zinc-500">{m.label}</div>
          </div>
        ))}
      </div>

      {/* Risk score banner */}
      <div className={`flex items-center gap-4 bg-zinc-900 border rounded-lg p-4 ${
        totalRisk === 0 ? "border-green-700" : totalRisk < 12 ? "border-orange-700" : "border-red-700"
      }`}>
        <Shield size={28} className={riskColor} />
        <div className="flex-1">
          <span className="text-zinc-400 text-sm">Nivel de riesgo del dominio: </span>
          <span className={`font-bold text-lg ${riskColor}`}>{riskLabel}</span>
          <span className="text-zinc-500 text-sm ml-2">({sc.critical} críticos · {sc.high} altos · {sc.medium} medios)</span>
        </div>
        {data.bloodhound_available && (
          <a href="http://localhost:7474" target="_blank" className="text-xs bg-purple-900 border border-purple-700 text-purple-300 px-3 py-1.5 rounded-lg hover:bg-purple-800 transition-colors">
            Ver en Neo4j →
          </a>
        )}
      </div>

      {/* Search + filter bar */}
      <div className="flex gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-1 min-w-48 bg-zinc-900 border border-zinc-700 rounded-lg px-3 py-2">
          <Search size={14} className="text-zinc-500" />
          <input
            type="text"
            placeholder="Buscar en resultados..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="bg-transparent text-sm text-zinc-300 outline-none flex-1 placeholder-zinc-600"
          />
        </div>
        {activeTab === "findings" && (
          <select
            value={sevFilter}
            onChange={e => setSevFilter(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 text-zinc-300 text-sm rounded-lg px-3 py-2 outline-none"
          >
            <option value="all">Todas las severidades</option>
            <option value="critical">Crítico</option>
            <option value="high">Alto</option>
            <option value="medium">Medio</option>
            <option value="low">Bajo</option>
            <option value="info">Info</option>
          </select>
        )}
      </div>

      {/* Tabs */}
      <div>
        <div className="flex gap-1 border-b border-zinc-700 mb-4">
          <Tab label="Hallazgos" active={activeTab === "findings"} onClick={() => setActiveTab("findings")} count={data.findings.length} />
          <Tab label="Ataques" active={activeTab === "attacks"} onClick={() => setActiveTab("attacks")} count={attacks?.total_cracked ?? undefined} />
          <Tab label="Usuarios" active={activeTab === "users"} onClick={() => setActiveTab("users")} count={data.stats.total_users} />
          <Tab label="Computadoras" active={activeTab === "computers"} onClick={() => setActiveTab("computers")} count={data.stats.total_computers} />
          <Tab label="Grupos" active={activeTab === "groups"} onClick={() => setActiveTab("groups")} count={data.stats.total_groups} />
          <Tab label="Política" active={activeTab === "policy"} onClick={() => setActiveTab("policy")} />
          <Tab label="Puertos" active={activeTab === "ports"} onClick={() => setActiveTab("ports")} count={data.ports.length} />
        </div>

        {/* ── Findings tab ── */}
        {activeTab === "findings" && (
          <div>
            {filteredFindings.length === 0 ? (
              <p className="text-zinc-500 text-sm p-4">No hay hallazgos con los filtros aplicados.</p>
            ) : (
              filteredFindings.map(f => <FindingCard key={f.id} f={f} />)
            )}
          </div>
        )}

        {/* ── Attacks tab ── */}
        {activeTab === "attacks" && (
          <div className="space-y-4">
            {!attacks?.available ? (
              <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-6 text-center">
                <Zap size={32} className="text-zinc-600 mx-auto mb-2" />
                <p className="text-zinc-400 font-medium">Módulos de ataque no ejecutados aún</p>
                <p className="text-zinc-500 text-sm mt-1">Ejecuta AS-REP Roasting y Kerberoasting desde la página de Auditoría AD.</p>
                <a href="/audit" className="mt-3 inline-block bg-orange-800 hover:bg-orange-700 text-orange-200 text-sm px-4 py-2 rounded-lg transition-colors">
                  Ir a Auditoría →
                </a>
              </div>
            ) : (
              <>
                {/* AS-REP Roasting */}
                <div className={`rounded-xl border p-5 ${(attacks.asrep.cracked.length > 0) ? "border-red-700 bg-red-950/30" : "border-orange-700 bg-orange-950/20"}`}>
                  <div className="flex items-center gap-3 mb-3">
                    <Key size={18} className="text-orange-400" />
                    <h3 className="font-bold text-orange-300">AS-REP Roasting — T1558.004</h3>
                    <span className={`ml-auto text-xs px-2 py-0.5 rounded font-medium ${attacks.asrep.run ? "bg-orange-900 text-orange-300 border border-orange-700" : "bg-zinc-800 text-zinc-500"}`}>
                      {attacks.asrep.run ? "Ejecutado" : "No ejecutado"}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    <div className="bg-zinc-900/60 rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-orange-400">{attacks.asrep.hashes}</div>
                      <div className="text-xs text-zinc-500">Hashes AS-REP</div>
                    </div>
                    <div className={`rounded-lg p-3 text-center ${attacks.asrep.cracked.length > 0 ? "bg-red-900/40" : "bg-zinc-900/60"}`}>
                      <div className={`text-xl font-bold ${attacks.asrep.cracked.length > 0 ? "text-red-400" : "text-zinc-500"}`}>{attacks.asrep.cracked.length}</div>
                      <div className="text-xs text-zinc-500">Crackeados</div>
                    </div>
                    <div className="bg-zinc-900/60 rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-yellow-400">{attacks.asrep.vulnerable_accounts.length || 1}</div>
                      <div className="text-xs text-zinc-500">Vulnerables</div>
                    </div>
                  </div>
                  {attacks.asrep.cracked.length > 0 && (
                    <div className="mt-3 p-3 bg-red-900/40 border border-red-700 rounded-lg">
                      <p className="text-red-300 font-bold text-sm mb-2">⚠ Contraseñas comprometidas:</p>
                      {attacks.asrep.cracked.map(c => (
                        <div key={c.user} className="flex items-center gap-3 text-sm font-mono">
                          <span className="text-red-400">{c.user}</span>
                          <span className="text-zinc-500">→</span>
                          <span className="text-yellow-300 bg-yellow-900/40 px-2 py-0.5 rounded">{c.password}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <p className="text-xs text-zinc-500 mt-3">
                    <span className="text-orange-400 font-medium">svc-backup</span> tiene DONT_REQ_PREAUTH activo.
                    Un atacante sin credenciales puede solicitar su AS-REP y crackear offline.
                  </p>
                </div>

                {/* Kerberoasting */}
                <div className={`rounded-xl border p-5 ${attacks.kerberoast.cracked.length > 0 ? "border-red-700 bg-red-950/30" : "border-red-800 bg-red-950/10"}`}>
                  <div className="flex items-center gap-3 mb-3">
                    <Zap size={18} className="text-red-400" />
                    <h3 className="font-bold text-red-300">Kerberoasting — T1558.003</h3>
                    <span className={`ml-auto text-xs px-2 py-0.5 rounded font-medium ${attacks.kerberoast.run ? "bg-red-900 text-red-300 border border-red-700" : "bg-zinc-800 text-zinc-500"}`}>
                      {attacks.kerberoast.run ? "Ejecutado" : "No ejecutado"}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-3 mb-4">
                    <div className="bg-zinc-900/60 rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-red-400">{attacks.kerberoast.hashes}</div>
                      <div className="text-xs text-zinc-500">Hashes TGS</div>
                    </div>
                    <div className={`rounded-lg p-3 text-center ${attacks.kerberoast.cracked.length > 0 ? "bg-red-900/40" : "bg-zinc-900/60"}`}>
                      <div className={`text-xl font-bold ${attacks.kerberoast.cracked.length > 0 ? "text-red-400" : "text-zinc-500"}`}>{attacks.kerberoast.cracked.length}</div>
                      <div className="text-xs text-zinc-500">Crackeados</div>
                    </div>
                    <div className="bg-zinc-900/60 rounded-lg p-3 text-center">
                      <div className="text-xl font-bold text-yellow-400">2</div>
                      <div className="text-xs text-zinc-500">Con SPN</div>
                    </div>
                  </div>
                  {attacks.kerberoast.cracked.length > 0 && (
                    <div className="mt-3 p-3 bg-red-900/40 border border-red-700 rounded-lg">
                      <p className="text-red-300 font-bold text-sm mb-2">⚠ Contraseñas de servicio comprometidas:</p>
                      {attacks.kerberoast.cracked.map(c => (
                        <div key={c.user} className="flex items-center gap-3 text-sm font-mono">
                          <span className="text-red-400">{c.user}</span>
                          <span className="text-zinc-500">→</span>
                          <span className="text-yellow-300 bg-yellow-900/40 px-2 py-0.5 rounded">{c.password}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <p className="text-xs text-zinc-500 mt-3">
                    <span className="text-red-400 font-medium">svc-web</span> (HTTP/webserver) y{" "}
                    <span className="text-red-400 font-medium">svc-sql</span> (MSSQLSvc/sqlserver:1433)
                    tienen SPNs. Cualquier usuario autenticado puede obtener sus TGS y crackear offline.
                  </p>
                </div>

                {/* Attack summary */}
                <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-4 text-sm">
                  <p className="text-zinc-400 font-medium mb-2">Pasos para reproducir el ataque (sin DC necesario para configuración):</p>
                  <ol className="space-y-1 text-zinc-500 list-decimal list-inside">
                    <li>Ir a <span className="text-zinc-300">Auditoría AD → AS-REP Roasting</span></li>
                    <li>Ver los hashes capturados en <span className="font-mono text-zinc-300">/workspace/reports/asrep_roast/</span></li>
                    <li>Correr Kerberoasting para obtener TGS de svc-web y svc-sql</li>
                    <li>Ver contraseñas crackeadas aquí en el tab Ataques</li>
                    <li>Remediar: <span className="text-green-400">Set-ADUser -DoesNotRequirePreAuth $false</span> + migrar a gMSA</li>
                  </ol>
                </div>
              </>
            )}
          </div>
        )}

        {/* ── Users tab ── */}
        {activeTab === "users" && (
          <div className="overflow-x-auto">
            <div className="flex gap-3 mb-3 text-xs text-zinc-500">
              <span className="bg-green-900/40 border border-green-700 px-2 py-0.5 rounded text-green-400">
                {data.stats.active_users} activos
              </span>
              <span className="bg-zinc-800 border border-zinc-700 px-2 py-0.5 rounded">
                {data.stats.disabled_users} deshabilitados
              </span>
              <span className="bg-orange-900/40 border border-orange-700 px-2 py-0.5 rounded text-orange-400">
                {data.users.filter(u => u.no_expire && !u.disabled).length} sin expiración
              </span>
              <span className="bg-red-900/40 border border-red-700 px-2 py-0.5 rounded text-red-400">
                {data.users.filter(u => u.no_preauth).length} AS-REP Roastable
              </span>
            </div>
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="border-b border-zinc-700 text-zinc-500 text-xs">
                  <th className="py-2 pr-4">Usuario</th>
                  <th className="py-2 pr-4">OU</th>
                  <th className="py-2 pr-4">UAC</th>
                  <th className="py-2 pr-4">SPN</th>
                  <th className="py-2 pr-4">Riesgo</th>
                  <th className="py-2">Pwd Set</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.map(u => {
                  const risks = [];
                  if (u.no_expire && !u.disabled) risks.push({ label: "No expira", c: "text-yellow-400" });
                  if (u.no_preauth)               risks.push({ label: "AS-REP",    c: "text-red-400"    });
                  if (u.spn.length > 0)           risks.push({ label: "Kerberoast",c: "text-orange-400" });
                  if (u.ou === "Honeypots")        risks.push({ label: "Honeypot",  c: "text-purple-400" });
                  return (
                    <tr key={u.sam} className={`border-b border-zinc-800 hover:bg-zinc-800/30 ${u.disabled ? "opacity-40" : ""}`}>
                      <td className="py-2 pr-4 font-mono text-zinc-200">{u.sam}</td>
                      <td className="py-2 pr-4 text-zinc-400 text-xs">{u.ou}</td>
                      <td className="py-2 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {u.disabled && <span className="text-xs text-zinc-500">DISABLED</span>}
                          {!u.disabled && <span className="text-xs text-green-600">ACTIVO</span>}
                        </div>
                      </td>
                      <td className="py-2 pr-4 text-xs text-zinc-500">{u.spn.length > 0 ? `${u.spn.length} SPN` : "—"}</td>
                      <td className="py-2 pr-4">
                        <div className="flex flex-wrap gap-1">
                          {risks.map(r => (
                            <span key={r.label} className={`text-xs font-medium ${r.c}`}>{r.label}</span>
                          ))}
                          {risks.length === 0 && <span className="text-xs text-zinc-600">—</span>}
                        </div>
                      </td>
                      <td className="py-2 text-xs text-zinc-500">{u.pwd_last_set?.slice(0, 10) ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Computers tab ── */}
        {activeTab === "computers" && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="border-b border-zinc-700 text-zinc-500 text-xs">
                  <th className="py-2 pr-4">Nombre</th>
                  <th className="py-2 pr-4">Rol</th>
                  <th className="py-2 pr-4">OS</th>
                  <th className="py-2 pr-4">OU</th>
                  <th className="py-2">Último logon</th>
                </tr>
              </thead>
              <tbody>
                {data.computers.map(c => (
                  <tr key={c.name} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                    <td className="py-2 pr-4 font-mono text-zinc-200 font-medium">{c.name}</td>
                    <td className="py-2 pr-4">
                      {c.is_dc
                        ? <span className="text-xs bg-purple-900 border border-purple-700 text-purple-300 px-2 py-0.5 rounded">DC</span>
                        : <span className="text-xs text-zinc-500">Workstation</span>}
                    </td>
                    <td className="py-2 pr-4 text-zinc-400 text-xs">{c.os || "Desconocido"} {c.os_ver}</td>
                    <td className="py-2 pr-4 text-xs text-zinc-500">{c.dn.split(",").find(p => p.startsWith("OU="))?.replace("OU=","") ?? "—"}</td>
                    <td className="py-2 text-xs text-zinc-500">{c.last_logon?.slice(0,10) ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Groups tab ── */}
        {activeTab === "groups" && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm text-left">
              <thead>
                <tr className="border-b border-zinc-700 text-zinc-500 text-xs">
                  <th className="py-2 pr-4">Grupo</th>
                  <th className="py-2 pr-4">Miembros</th>
                  <th className="py-2">DN</th>
                </tr>
              </thead>
              <tbody>
                {filteredGroups.map(g => (
                  <tr key={g.sam} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                    <td className="py-2 pr-4 font-medium text-zinc-200">{g.name}</td>
                    <td className="py-2 pr-4">
                      <span className={`text-xs px-2 py-0.5 rounded ${g.member_count > 0 ? "bg-blue-900/40 text-blue-300" : "text-zinc-600"}`}>
                        {g.member_count}
                      </span>
                    </td>
                    <td className="py-2 text-xs text-zinc-500 font-mono">{g.dn}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* ── Policy tab ── */}
        {activeTab === "policy" && data.policy && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {[
              {
                title: "Política de Contraseñas",
                icon: <Lock size={16} className="text-purple-400" />,
                items: [
                  { label: "Longitud mínima",    value: `${data.policy.minPwdLength} caracteres`, warn: data.policy.minPwdLength < 12 },
                  { label: "Historial",           value: `${data.policy.pwdHistoryLength} contraseñas anteriores` },
                  { label: "Edad máxima",         value: data.policy.maxPwdAge },
                  { label: "Complejidad",         value: data.policy.pwdProperties === 1 ? "Habilitada ✓" : "Deshabilitada ✗", warn: data.policy.pwdProperties !== 1 },
                ],
              },
              {
                title: "Bloqueo de Cuentas",
                icon: <XCircle size={16} className="text-red-400" />,
                items: [
                  { label: "Umbral de bloqueo",  value: data.policy.lockoutThreshold === 0 ? "Deshabilitado ✗ (SIN BLOQUEO)" : `${data.policy.lockoutThreshold} intentos`, warn: data.policy.lockoutThreshold === 0 },
                  { label: "Duración bloqueo",   value: data.policy.lockoutDuration },
                ],
              },
              {
                title: "Configuración del Dominio",
                icon: <Activity size={16} className="text-cyan-400" />,
                items: [
                  { label: "Dominio",             value: data.policy.domain },
                  { label: "SID del dominio",     value: data.policy.objectSid },
                  { label: "Nivel funcional",     value: `Windows Server ${[2008,2008,2012,2012,2016,2019,2022][data.policy.behaviorVersion] ?? data.policy.behaviorVersion}` },
                  { label: "MachineAccountQuota", value: `${data.policy.machineAccountQuota} (usuarios pueden agregar equipos)`, warn: data.policy.machineAccountQuota > 0 },
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

        {/* ── Ports tab ── */}
        {activeTab === "ports" && (
          <div>
            {data.ports.length === 0 ? (
              <p className="text-zinc-500 text-sm p-4">No hay datos de escaneo de puertos. Ejecuta una auditoría con DC activo.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm text-left">
                  <thead>
                    <tr className="border-b border-zinc-700 text-zinc-500 text-xs">
                      <th className="py-2 pr-6">Puerto</th>
                      <th className="py-2 pr-6">Servicio</th>
                      <th className="py-2">Estado</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.ports.map(p => (
                      <tr key={p.port} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                        <td className="py-2 pr-6 font-mono text-zinc-200">{p.port}/tcp</td>
                        <td className="py-2 pr-6 text-zinc-400">{p.service}</td>
                        <td className="py-2">
                          <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                            p.state === "open"     ? "bg-green-900/40 text-green-400 border border-green-700" :
                            p.state === "filtered" ? "bg-yellow-900/40 text-yellow-400 border border-yellow-700" :
                                                     "bg-zinc-800 text-zinc-500 border border-zinc-700"
                          }`}>
                            {p.state}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
