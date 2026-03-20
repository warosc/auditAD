"use client";

import { useEffect, useState } from "react";
import { api, type Container, type LabHealth, type SettingDef } from "@/lib/api";
import { StatusCard } from "@/components/soc/StatusCard";
import { containerStatusToService } from "@/lib/utils";
import {
  Shield, Terminal, Database, Eye, Activity,
  Server, AlertTriangle, CheckCircle2, RefreshCw,
  Target, Wifi, Users, Lock,
} from "lucide-react";

function MetricTile({
  label, value, sub, accent = "text-soc-accent",
}: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="rounded-lg border border-soc-border bg-soc-card p-4">
      <p className="text-[10px] uppercase tracking-widest text-soc-dim mb-1">{label}</p>
      <p className={`text-2xl font-bold font-mono ${accent}`}>{value}</p>
      {sub && <p className="text-[10px] text-soc-dim mt-0.5">{sub}</p>}
    </div>
  );
}

const CORE_SERVICES = [
  { name: "neo4j",                 label: "Neo4j",            icon: Database,      desc: "BloodHound graph DB · :7474" },
  { name: "opensearch",            label: "OpenSearch",       icon: Eye,           desc: "SIEM indexing · :9200" },
  { name: "opensearch-dashboards", label: "OS Dashboards",    icon: Activity,      desc: "Kibana UI · :5601" },
  { name: "grafana",               label: "Grafana",          icon: Activity,      desc: "Metrics · :3000" },
  { name: "suricata",              label: "Suricata IDS",     icon: AlertTriangle, desc: "Network IDS" },
  { name: "zeek",                  label: "Zeek NSM",         icon: Eye,           desc: "Network monitor" },
  { name: "wazuh-manager",         label: "Wazuh Manager",    icon: Shield,        desc: "SIEM/XDR · :55000" },
  { name: "kali-audit",            label: "Kali Audit",       icon: Terminal,      desc: "Audit scripts" },
];

export default function DashboardPage() {
  const [containers, setContainers] = useState<Container[]>([]);
  const [health,     setHealth]     = useState<LabHealth | null>(null);
  const [adSettings, setAdSettings] = useState<Record<string, string>>({});
  const [loading,    setLoading]    = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [c, h, s] = await Promise.all([
        api.containers(),
        api.labHealth(),
        api.settings(),
      ]);
      setContainers(c);
      setHealth(h);
      const adMap: Record<string, string> = {};
      for (const def of s) {
        if (def.group === "ad") adMap[def.key] = def.value ?? def.default;
      }
      setAdSettings(adMap);
      setLastUpdate(new Date());
    } catch {
      // silent
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, []);

  const upCount   = containers.filter((c) => c.status === "running").length;
  const downCount = containers.filter((c) => c.status !== "running" && c.status !== "not_found").length;
  const notFound  = containers.filter((c) => c.status === "not_found").length;

  const svcStatus = (name: string) => {
    const c = containers.find((x) => x.name === name);
    if (!c) return "not_found" as const;
    return containerStatusToService(c.status, c.health);
  };

  const adReady = !!(adSettings.DC_IP && adSettings.DC_IP !== "192.168.1.10" && adSettings.AD_PASSWORD);

  return (
    <div className="space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-6 h-6 text-soc-purple" />
          <div>
            <h1 className="text-lg font-bold text-soc-text">SOC Dashboard</h1>
            <p className="text-xs text-soc-dim">AD Purple Lab — Security Operations Center</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {lastUpdate && (
            <span className="text-[10px] text-soc-dim">
              Actualizado {lastUpdate.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={load}
            disabled={loading}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs text-soc-dim hover:text-soc-text hover:bg-soc-card border border-soc-border transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* AD Target banner */}
      <div className={`rounded-lg border px-4 py-3 flex flex-wrap items-center gap-4 text-xs
        ${adReady
          ? "border-soc-accent/30 bg-soc-accent/5"
          : "border-yellow-500/30 bg-yellow-500/5"}`}>
        <Target className={`w-4 h-4 shrink-0 ${adReady ? "text-soc-accent" : "text-yellow-400"}`} />
        <div className="flex flex-wrap gap-x-6 gap-y-1 flex-1">
          <span>
            <span className="text-soc-dim">Target DC: </span>
            <span className="font-mono font-semibold text-soc-text">{adSettings.DC_IP || "—"}</span>
          </span>
          <span>
            <span className="text-soc-dim">Dominio: </span>
            <span className="font-mono font-semibold text-soc-text">{adSettings.AD_DOMAIN || "—"}</span>
          </span>
          <span>
            <span className="text-soc-dim">Usuario: </span>
            <span className="font-mono font-semibold text-soc-text">{adSettings.AD_USERNAME || "—"}</span>
          </span>
          <span>
            <span className="text-soc-dim">Password: </span>
            <span className={`font-mono font-semibold ${adSettings.AD_PASSWORD ? "text-soc-green" : "text-yellow-400"}`}>
              {adSettings.AD_PASSWORD ? "••••••••" : "⚠ no configurada"}
            </span>
          </span>
        </div>
        <a href="/settings" className="text-soc-accent hover:underline text-[11px] shrink-0">
          Configurar →
        </a>
      </div>

      {/* Quick metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricTile
          label="Contenedores UP"
          value={upCount}
          sub={`de ${containers.length} total`}
          accent="text-soc-green"
        />
        <MetricTile
          label="Detenidos / Error"
          value={downCount + notFound}
          accent={downCount + notFound > 0 ? "text-soc-red" : "text-soc-dim"}
        />
        <MetricTile
          label="Lab Health"
          value={health ? `${health._summary.services_up}/${health._summary.services_checked}` : "—"}
          sub="servicios con probe HTTP"
          accent={health?._summary.all_up ? "text-soc-green" : "text-yellow-400"}
        />
        <MetricTile
          label="Target AD"
          value={adReady ? "Listo" : "Pendiente"}
          sub={adReady ? adSettings.DC_IP : "Configurar credenciales"}
          accent={adReady ? "text-soc-green" : "text-yellow-400"}
        />
      </div>

      {/* Service status grid */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-soc-dim mb-3">
          Servicios del Laboratorio
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
          {CORE_SERVICES.map(({ name, label, icon, desc }) => (
            <StatusCard
              key={name}
              title={label}
              status={svcStatus(name)}
              detail={desc}
              icon={icon}
            />
          ))}
        </div>
      </div>

      {/* Quick action cards */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-widest text-soc-dim mb-3">
          Acciones Rápidas
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <a href="/audit"
            className="rounded-lg border border-soc-border bg-soc-card p-4 hover:border-soc-accent/40 hover:bg-soc-accent/5 transition-colors group">
            <Terminal className="w-5 h-5 text-soc-accent mb-2 group-hover:scale-110 transition-transform" />
            <p className="text-sm font-semibold text-soc-text">Auditoría AD</p>
            <p className="text-xs text-soc-dim mt-0.5">Safe audit, BloodHound, LDAP, DNS</p>
          </a>
          <a href="/health"
            className="rounded-lg border border-soc-border bg-soc-card p-4 hover:border-green-500/40 hover:bg-green-500/5 transition-colors group">
            <Wifi className="w-5 h-5 text-soc-green mb-2 group-hover:scale-110 transition-transform" />
            <p className="text-sm font-semibold text-soc-text">Lab Health</p>
            <p className="text-xs text-soc-dim mt-0.5">Verificar estado de todos los servicios</p>
          </a>
          <a href="/containers"
            className="rounded-lg border border-soc-border bg-soc-card p-4 hover:border-yellow-500/40 hover:bg-yellow-500/5 transition-colors group">
            <Server className="w-5 h-5 text-yellow-400 mb-2 group-hover:scale-110 transition-transform" />
            <p className="text-sm font-semibold text-soc-text">Contenedores</p>
            <p className="text-xs text-soc-dim mt-0.5">Logs, restart y estado de servicios</p>
          </a>
          <a href="/reports"
            className="rounded-lg border border-soc-border bg-soc-card p-4 hover:border-purple-500/40 hover:bg-purple-500/5 transition-colors group">
            <CheckCircle2 className="w-5 h-5 text-soc-purple mb-2 group-hover:scale-110 transition-transform" />
            <p className="text-sm font-semibold text-soc-text">Reportes</p>
            <p className="text-xs text-soc-dim mt-0.5">Descargar y revisar resultados</p>
          </a>
        </div>
      </div>

      {/* Primer test checklist */}
      <div className="rounded-lg border border-soc-border bg-soc-card p-4 space-y-3">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-soc-dim">
          Checklist — Primera Prueba
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
          {[
            { ok: !!adSettings.DC_IP && adSettings.DC_IP !== "192.168.1.10", label: "DC IP configurada", sub: adSettings.DC_IP || "ir a Settings → Active Directory", href: "/settings" },
            { ok: !!adSettings.AD_PASSWORD,                                   label: "Credenciales AD",   sub: adSettings.AD_PASSWORD ? "configuradas" : "falta AD_PASSWORD",        href: "/settings" },
            { ok: svcStatus("kali-audit") === "up",                           label: "kali-audit running", sub: "contenedor de auditorías",                                           href: "/containers" },
            { ok: svcStatus("neo4j") === "up",                                label: "Neo4j running",     sub: "necesario para BloodHound",                                          href: "/containers" },
            { ok: svcStatus("wazuh-manager") === "up",                        label: "Wazuh Manager up",  sub: "instalar agente en el DC",                                           href: "/settings" },
            { ok: upCount >= 8,                                               label: "Stack completo",    sub: `${upCount}/10 contenedores arriba`,                                   href: "/containers" },
          ].map(({ ok, label, sub, href }) => (
            <a key={label} href={href}
              className="flex items-center gap-3 rounded border border-soc-border/50 bg-soc-surface/40 px-3 py-2 hover:bg-soc-card transition-colors">
              <span className={`w-4 h-4 rounded-full flex items-center justify-center shrink-0 text-[10px] font-bold
                ${ok ? "bg-soc-green/20 text-soc-green border border-soc-green/40" : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/30"}`}>
                {ok ? "✓" : "!"}
              </span>
              <div>
                <p className={`font-medium ${ok ? "text-soc-text" : "text-yellow-300"}`}>{label}</p>
                <p className="text-soc-dim text-[11px]">{sub}</p>
              </div>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
}
