"use client";

import { useCallback, useEffect, useState } from "react";
import { api, type LabHealth, type Container } from "@/lib/api";
import { StatusCard } from "@/components/soc/StatusCard";
import { containerStatusToService } from "@/lib/utils";
import type { ServiceStatus } from "@/lib/utils";
import {
  Activity, RefreshCw, Database, Eye, BarChart2,
  ShieldAlert, Network, Server, Shield, Terminal, Globe,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

// Servicios con probe HTTP activo (vía health_service.py)
const HEALTH_META: Record<string, { label: string; icon: LucideIcon; desc: string; link?: string }> = {
  opensearch:              { label: "OpenSearch",       icon: Database,    desc: "SIEM / log indexing · :9200",    link: "http://localhost:9200" },
  "opensearch-dashboards": { label: "OS Dashboards",   icon: Eye,         desc: "Kibana UI · :5601",              link: "http://localhost:5601" },
  grafana:                 { label: "Grafana",          icon: BarChart2,   desc: "Metrics dashboards · :3000",     link: "http://localhost:3000" },
  neo4j:                   { label: "Neo4j",            icon: Database,    desc: "BloodHound graph DB · :7474",    link: "http://localhost:7474" },
};

// Servicios sin probe HTTP (estado desde Docker)
const CONTAINER_META: Record<string, { label: string; icon: LucideIcon; desc: string }> = {
  "kali-audit":    { label: "Kali Audit",     icon: Terminal,    desc: "Contenedor de auditorías AD" },
  "zeek":          { label: "Zeek NSM",       icon: Network,     desc: "Network security monitor · eth0" },
  "suricata":      { label: "Suricata IDS",   icon: ShieldAlert, desc: "IDS/IPS · EVE JSON output" },
  "wazuh-manager": { label: "Wazuh Manager",  icon: Shield,      desc: "SIEM/XDR · API :55000 · Agentes :51514" },
  "panel-api":     { label: "Panel API",      icon: Server,      desc: "FastAPI backend · :8080" },
  "panel-ui":      { label: "Panel UI",       icon: Globe,       desc: "Next.js frontend · :3002" },
};

export default function HealthPage() {
  const [health,     setHealth]     = useState<LabHealth | null>(null);
  const [containers, setContainers] = useState<Container[]>([]);
  const [loading,    setLoading]    = useState(false);
  const [updated,    setUpdated]    = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [h, c] = await Promise.all([api.labHealth(), api.containers()]);
      setHealth(h);
      setContainers(c);
      setUpdated(new Date());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15_000);
    return () => clearInterval(t);
  }, [load]);

  // Entries from HTTP health probes
  const healthEntries = health
    ? Object.entries(health).filter(([k]) => k !== "_summary")
    : [];

  // Container-based status
  const cStatus = (name: string): ServiceStatus => {
    const c = containers.find((x) => x.name === name);
    if (!c) return "not_found";
    return containerStatusToService(c.status, c.health);
  };

  // HTTP-probe status → ServiceStatus
  const probeStatus = (key: string): ServiceStatus => {
    if (!health) return "unknown";
    const r = health[key as keyof LabHealth];
    if (!r || typeof r !== "object" || !("status" in r)) return "unknown";
    const s = (r as { status: string }).status;
    if (s === "up")   return "up";
    if (s === "down") return "down";
    return "unknown";
  };

  const totalUp   = (health?._summary.services_up ?? 0)
    + Object.keys(CONTAINER_META).filter((n) => cStatus(n) === "up").length;
  const totalAll  = (health?._summary.services_checked ?? 0) + Object.keys(CONTAINER_META).length;

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-6 h-6 text-soc-green" />
          <div>
            <h1 className="text-lg font-bold text-soc-text">Lab Health</h1>
            <p className="text-xs text-soc-dim">Estado de todos los servicios. Auto-refresh cada 15 s.</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {updated && <span className="text-[10px] text-soc-dim">{updated.toLocaleTimeString()}</span>}
          <button onClick={load} disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-soc-dim hover:text-soc-text hover:bg-soc-card border border-soc-border transition-colors">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Summary bar */}
      <div className="flex items-center gap-4 rounded-lg border border-soc-border bg-soc-card px-4 py-3 text-xs">
        <span className="text-soc-dim font-semibold">Total:</span>
        <span className={`font-bold ${totalUp === totalAll ? "text-soc-green" : "text-yellow-400"}`}>
          {totalUp} / {totalAll} servicios UP
        </span>
        {health?._summary.all_up && Object.keys(CONTAINER_META).every(n => cStatus(n) === "up") && (
          <span className="text-soc-green ml-1">— Stack completo ✓</span>
        )}
        <span className="ml-auto text-soc-dim text-[11px]">
          Probes HTTP: {health?._summary.services_up ?? "…"}/{health?._summary.services_checked ?? "…"} ·
          Docker: {Object.keys(CONTAINER_META).filter(n => cStatus(n) === "up").length}/{Object.keys(CONTAINER_META).length}
        </span>
      </div>

      {/* HTTP-probed services */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-soc-dim mb-3">
          Servicios con Health Probe HTTP
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {healthEntries.map(([key]) => {
            const meta = HEALTH_META[key] ?? { label: key, icon: Server, desc: "" };
            const status = probeStatus(key);
            const detail = health?.[key as keyof LabHealth];
            const extra = typeof detail === "object" && detail !== null && "cluster_status" in detail
              ? ` · cluster: ${(detail as { cluster_status?: string }).cluster_status ?? ""}`
              : typeof detail === "object" && detail !== null && "database" in detail
              ? ` · db: ${(detail as { database?: string }).database ?? ""}`
              : "";
            return (
              <a key={key} href={meta.link} target="_blank" rel="noopener noreferrer"
                className="block hover:opacity-90 transition-opacity">
                <StatusCard
                  title={meta.label}
                  status={status}
                  detail={meta.desc + extra}
                  icon={meta.icon}
                />
              </a>
            );
          })}
        </div>
      </div>

      {/* Container-based services */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-soc-dim mb-3">
          Servicios por Estado de Contenedor
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {Object.entries(CONTAINER_META).map(([name, meta]) => {
            const c = containers.find((x) => x.name === name);
            const status = cStatus(name);
            const detail = c
              ? `${meta.desc} · imagen: ${c.image !== "N/A" ? c.image.split(":")[0].split("/").pop() : "—"}`
              : meta.desc;
            return (
              <StatusCard
                key={name}
                title={meta.label}
                status={status}
                detail={detail}
                icon={meta.icon}
                sub={c?.id !== "N/A" ? `ID: ${c?.id}` : undefined}
              />
            );
          })}
        </div>
      </div>

      {/* External links */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-soc-dim mb-3">
          Acceso directo a dashboards
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Grafana",             url: "http://localhost:3000", color: "text-orange-400 border-orange-500/30 hover:bg-orange-500/10" },
            { label: "OpenSearch",          url: "http://localhost:5601", color: "text-blue-400 border-blue-500/30 hover:bg-blue-500/10" },
            { label: "Neo4j Browser",       url: "http://localhost:7474", color: "text-green-400 border-green-500/30 hover:bg-green-500/10" },
            { label: "Wazuh API",           url: "https://localhost:55000", color: "text-purple-400 border-purple-500/30 hover:bg-purple-500/10" },
          ].map(({ label, url, color }) => (
            <a key={url} href={url} target="_blank" rel="noopener noreferrer"
              className={`rounded-lg border bg-soc-card px-4 py-3 text-sm font-semibold transition-colors ${color}`}>
              {label}
              <span className="block text-[11px] font-normal opacity-60 mt-0.5">{url}</span>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
