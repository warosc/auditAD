"use client";

import { useEffect, useState } from "react";
import {
  GitBranch, ChevronDown, ChevronUp, AlertTriangle, Plus, Minus, Edit3,
  TrendingUp, Users, Monitor, Lock, BarChart3, Trash2, RefreshCw,
} from "lucide-react";

interface Baseline {
  id: number;
  name: string;
  source: string;
  created_at: string;
  summary: string;
  tags: string;
}

interface UserDelta {
  sam: string;
  ou?: string;
  disabled?: boolean;
  changes?: Record<string, [any, any]>;
}

interface ComparisonResult {
  comparison: {
    users: {
      new: UserDelta[];
      removed: UserDelta[];
      modified: UserDelta[];
      counts: { new: number; removed: number; modified: number };
    };
    computers: {
      new: any[];
      removed: any[];
      modified: any[];
      counts: { new: number; removed: number; modified: number };
    };
    groups: {
      new: any[];
      removed: any[];
      modified: any[];
      counts: { new: number; removed: number; modified: number };
    };
    policy: {
      changes: Array<{ key: string; before: any; after: any }>;
      count: number;
    };
  };
  security_deltas: Array<{
    severity: string;
    type: string;
    count: number;
    description: string;
    examples?: string[];
  }>;
  summary: Record<string, number>;
  baseline1: string;
  baseline2: string;
}

export function ComparisonPanel() {
  const [baselines, setBaselines] = useState<Baseline[]>([]);
  const [loading, setLoading] = useState(false);
  const [comparing, setComparing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [baseline1Id, setBaseline1Id] = useState<number | null>(null);
  const [baseline2Id, setBaseline2Id] = useState<number | null>(null);

  const [result, setResult] = useState<ComparisonResult | null>(null);
  const [activeTab, setActiveTab] = useState("summary");

  // Load baselines on mount
  useEffect(() => {
    loadBaselines();
  }, []);

  const loadBaselines = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/audit/baselines");
      if (!res.ok) throw new Error("Failed to load baselines");
      const data = await res.json();
      setBaselines(data.baselines || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error loading baselines");
    } finally {
      setLoading(false);
    }
  };

  const handleCompare = async () => {
    if (!baseline1Id || !baseline2Id) {
      setError("Selecciona dos baselines para comparar");
      return;
    }

    setComparing(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/audit/compare", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          baseline1_id: baseline1Id,
          baseline2_id: baseline2Id,
        }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Error ${res.status}`);
      }

      const data = await res.json();
      setResult(data);
      setActiveTab("summary");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Error comparing");
    } finally {
      setComparing(false);
    }
  };

  const severityColor = (sev: string) => {
    switch (sev) {
      case "critical":
        return "text-red-400 bg-red-950 border-red-700";
      case "high":
        return "text-orange-400 bg-orange-950 border-orange-700";
      case "medium":
        return "text-yellow-400 bg-yellow-950 border-yellow-700";
      case "low":
        return "text-blue-400 bg-blue-950 border-blue-700";
      default:
        return "text-zinc-400 bg-zinc-900 border-zinc-700";
    }
  };

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <GitBranch className="w-6 h-6 text-blue-400" />
        <div>
          <h1 className="text-lg font-bold text-zinc-100">Comparación de Auditorías</h1>
          <p className="text-xs text-zinc-500">
            Compara dos snapshots de auditoría para identificar cambios y deltas de seguridad.
          </p>
        </div>
      </div>

      {/* Selector de baselines */}
      <div className="bg-zinc-900/50 border border-zinc-700 rounded-lg p-4 space-y-4">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-2">
              Baseline 1 (Anterior)
            </label>
            <select
              value={baseline1Id || ""}
              onChange={(e) => setBaseline1Id(e.target.value ? parseInt(e.target.value) : null)}
              className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-zinc-100 text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">-- Selecciona un baseline --</option>
              {baselines.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.name} ({b.summary})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-zinc-300 mb-2">
              Baseline 2 (Actual)
            </label>
            <select
              value={baseline2Id || ""}
              onChange={(e) => setBaseline2Id(e.target.value ? parseInt(e.target.value) : null)}
              className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-zinc-100 text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">-- Selecciona un baseline --</option>
              {baselines.map((b) => (
                <option key={b.id} value={b.id}>
                  {b.name} ({b.summary})
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="bg-red-900/30 border border-red-700 rounded px-3 py-2 text-sm text-red-200">
            {error}
          </div>
        )}

        <button
          onClick={handleCompare}
          disabled={comparing || !baseline1Id || !baseline2Id}
          className="w-full flex items-center justify-center gap-2 bg-blue-900 hover:bg-blue-800 disabled:opacity-50 disabled:cursor-not-allowed text-blue-200 px-4 py-2 rounded-lg transition-colors"
        >
          {comparing ? (
            <>
              <RefreshCw size={16} className="animate-spin" />
              Comparando…
            </>
          ) : (
            <>
              <BarChart3 size={16} />
              Comparar
            </>
          )}
        </button>
      </div>

      {/* Resultados */}
      {result && (
        <div className="space-y-6">
          {/* Tabs */}
          <div className="flex gap-2 border-b border-zinc-700 overflow-x-auto">
            {[
              { id: "summary", label: "Resumen", icon: BarChart3 },
              { id: "security", label: "Deltas Seguridad", icon: AlertTriangle },
              { id: "users", label: "Usuarios", icon: Users },
              { id: "computers", label: "Equipos", icon: Monitor },
              { id: "groups", label: "Grupos", icon: Lock },
              { id: "policies", label: "Políticas", icon: TrendingUp },
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`flex items-center gap-1.5 px-4 py-2 text-sm whitespace-nowrap border-b-2 transition-colors ${
                  activeTab === id
                    ? "border-blue-500 text-blue-400"
                    : "border-transparent text-zinc-500 hover:text-zinc-300"
                }`}
              >
                <Icon size={14} />
                {label}
              </button>
            ))}
          </div>

          {/* Tab: Resumen */}
          {activeTab === "summary" && (
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              {[
                { label: "Usuarios Añadidos", value: result.summary.users_added, color: "green" },
                { label: "Usuarios Eliminados", value: result.summary.users_removed, color: "red" },
                { label: "Usuarios Modificados", value: result.summary.users_modified, color: "yellow" },
                { label: "Equipos Añadidos", value: result.summary.computers_added, color: "green" },
                { label: "Equipos Eliminados", value: result.summary.computers_removed, color: "red" },
                { label: "Grupos Modificados", value: result.summary.groups_modified, color: "blue" },
              ].map(({ label, value, color }) => (
                <div
                  key={label}
                  className={`bg-zinc-900 border border-zinc-700 rounded p-4 text-center`}
                >
                  <p className="text-zinc-500 text-sm mb-1">{label}</p>
                  <p className={`text-3xl font-bold ${
                    color === "green" ? "text-green-400" :
                    color === "red" ? "text-red-400" :
                    color === "yellow" ? "text-yellow-400" :
                    "text-blue-400"
                  }`}>
                    {value}
                  </p>
                </div>
              ))}
            </div>
          )}

          {/* Tab: Security Deltas */}
          {activeTab === "security" && (
            <div className="space-y-3">
              {result.security_deltas.length === 0 ? (
                <div className="text-center py-8 text-zinc-500">
                  No hay cambios de seguridad significativos.
                </div>
              ) : (
                result.security_deltas.map((delta, i) => (
                  <div
                    key={i}
                    className={`rounded-lg border p-4 ${severityColor(delta.severity)}`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <h4 className="font-medium">{delta.description}</h4>
                        <p className="text-xs opacity-75 mt-1">{delta.type}</p>
                        {delta.examples && delta.examples.length > 0 && (
                          <div className="text-xs mt-2 opacity-75">
                            Ejemplos: {delta.examples.join(", ")}
                          </div>
                        )}
                      </div>
                      <div className="text-2xl font-bold ml-4">{delta.count}</div>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* Tab: Usuarios */}
          {activeTab === "users" && (
            <div className="space-y-4">
              {/* Usuarios Nuevos */}
              {result.comparison.users.new.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-green-400 mb-2 flex items-center gap-2">
                    <Plus size={14} /> Usuarios Nuevos ({result.comparison.users.counts.new})
                  </h3>
                  <div className="space-y-1 text-xs">
                    {result.comparison.users.new.slice(0, 10).map((u) => (
                      <div key={u.sam} className="bg-green-900/20 border border-green-700/30 rounded px-2 py-1">
                        {u.sam} {u.ou ? `(${u.ou})` : ""}
                      </div>
                    ))}
                    {result.comparison.users.new.length > 10 && (
                      <div className="text-zinc-500">+{result.comparison.users.new.length - 10} más...</div>
                    )}
                  </div>
                </div>
              )}

              {/* Usuarios Eliminados */}
              {result.comparison.users.removed.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2">
                    <Minus size={14} /> Usuarios Eliminados ({result.comparison.users.counts.removed})
                  </h3>
                  <div className="space-y-1 text-xs">
                    {result.comparison.users.removed.slice(0, 10).map((u) => (
                      <div key={u.sam} className="bg-red-900/20 border border-red-700/30 rounded px-2 py-1">
                        {u.sam} {u.ou ? `(${u.ou})` : ""}
                      </div>
                    ))}
                    {result.comparison.users.removed.length > 10 && (
                      <div className="text-zinc-500">+{result.comparison.users.removed.length - 10} más...</div>
                    )}
                  </div>
                </div>
              )}

              {/* Usuarios Modificados */}
              {result.comparison.users.modified.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-yellow-400 mb-2 flex items-center gap-2">
                    <Edit3 size={14} /> Usuarios Modificados ({result.comparison.users.counts.modified})
                  </h3>
                  <div className="space-y-1 text-xs">
                    {result.comparison.users.modified.slice(0, 10).map((u) => (
                      <div key={u.sam} className="bg-yellow-900/20 border border-yellow-700/30 rounded px-2 py-1">
                        <div className="font-medium">{u.sam}</div>
                        {u.changes && Object.entries(u.changes).map(([key, [before, after]]) => (
                          <div key={key} className="text-zinc-400">
                            {key}: {String(before)} → {String(after)}
                          </div>
                        ))}
                      </div>
                    ))}
                    {result.comparison.users.modified.length > 10 && (
                      <div className="text-zinc-500">+{result.comparison.users.modified.length - 10} más...</div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab: Equipos */}
          {activeTab === "computers" && (
            <div className="space-y-4">
              {result.comparison.computers.new.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-green-400 mb-2">
                    Equipos Nuevos ({result.comparison.computers.counts.new})
                  </h3>
                  <div className="space-y-1 text-xs">
                    {result.comparison.computers.new.slice(0, 10).map((c) => (
                      <div key={c.name} className="bg-green-900/20 border border-green-700/30 rounded px-2 py-1">
                        {c.name} ({c.os || "Unknown"})
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {result.comparison.computers.removed.length > 0 && (
                <div>
                  <h3 className="text-sm font-semibold text-red-400 mb-2">
                    Equipos Eliminados ({result.comparison.computers.counts.removed})
                  </h3>
                  <div className="space-y-1 text-xs">
                    {result.comparison.computers.removed.slice(0, 10).map((c) => (
                      <div key={c.name} className="bg-red-900/20 border border-red-700/30 rounded px-2 py-1">
                        {c.name}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab: Grupos */}
          {activeTab === "groups" && (
            <div className="space-y-4">
              <p className="text-zinc-400 text-sm">
                Grupos modificados: {result.comparison.groups.counts.modified}
              </p>
              {result.comparison.groups.modified.length > 0 && (
                <div className="space-y-2 text-xs">
                  {result.comparison.groups.modified.slice(0, 10).map((g) => (
                    <div key={g.name} className="bg-blue-900/20 border border-blue-700/30 rounded px-2 py-1">
                      <div className="font-medium">{g.name}</div>
                      <div className="text-zinc-400">
                        Miembros: {g.member_count_before} → {g.member_count_after}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab: Políticas */}
          {activeTab === "policies" && (
            <div className="space-y-2 text-xs">
              {result.comparison.policy.changes.length === 0 ? (
                <div className="text-zinc-500">Sin cambios en políticas.</div>
              ) : (
                result.comparison.policy.changes.map((change, i) => (
                  <div key={i} className="bg-zinc-900 border border-zinc-700 rounded px-3 py-2">
                    <div className="font-medium">{change.key}</div>
                    <div className="text-zinc-400 mt-1">
                      {String(change.before)} → {String(change.after)}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
