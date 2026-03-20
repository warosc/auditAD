"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Terminal,
  Box,
  FileText,
  Activity,
  Shield,
  BarChart2,
  Eye,
  ExternalLink,
  Settings,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/",            label: "Dashboard",    icon: LayoutDashboard },
  { href: "/audit",       label: "Auditoría AD", icon: Terminal },
  { href: "/results",     label: "Resultados",   icon: BarChart2 },
  { href: "/containers",  label: "Contenedores", icon: Box },
  { href: "/reports",     label: "Reportes",     icon: FileText },
  { href: "/health",      label: "Lab Health",   icon: Activity },
  { href: "/settings",    label: "Configuración",icon: Settings },
];

const EXTERNAL = [
  { href: "http://localhost:3000",  label: "Grafana",        color: "text-orange-400" },
  { href: "http://localhost:5601",  label: "OpenSearch",     color: "text-blue-400" },
  { href: "http://localhost:7474",  label: "Neo4j Browser",  color: "text-green-400" },
];

export default function Sidebar() {
  const path = usePathname();

  return (
    <aside className="w-56 shrink-0 flex flex-col bg-soc-surface border-r border-soc-border h-screen">
      {/* Brand */}
      <div className="flex items-center gap-2 px-4 py-4 border-b border-soc-border">
        <Shield className="w-5 h-5 text-soc-purple" />
        <div>
          <p className="text-xs font-bold text-soc-text leading-none">AD Purple Lab</p>
          <p className="text-[10px] text-soc-dim leading-none mt-0.5">SOC Panel</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
        <p className="px-2 py-1 text-[10px] font-semibold uppercase tracking-widest text-soc-dim">
          Panel
        </p>
        {NAV.map(({ href, label, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className={cn(
              "flex items-center gap-2.5 px-2 py-2 rounded text-sm transition-colors",
              path === href
                ? "bg-soc-accent/10 text-soc-accent border border-soc-accent/20"
                : "text-soc-dim hover:text-soc-text hover:bg-soc-card"
            )}
          >
            <Icon className="w-4 h-4 shrink-0" />
            {label}
          </Link>
        ))}

        <div className="pt-3">
          <p className="px-2 py-1 text-[10px] font-semibold uppercase tracking-widest text-soc-dim">
            Dashboards
          </p>
          {EXTERNAL.map(({ href, label, color }) => (
            <a
              key={href}
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className={cn(
                "flex items-center gap-2.5 px-2 py-2 rounded text-sm hover:bg-soc-card transition-colors",
                color
              )}
            >
              <Eye className="w-4 h-4 shrink-0" />
              {label}
              <ExternalLink className="w-3 h-3 ml-auto opacity-50" />
            </a>
          ))}
        </div>
      </nav>

      {/* Footer */}
      <div className="px-4 py-3 border-t border-soc-border">
        <p className="text-[10px] text-soc-dim">Purple Team Lab</p>
        <p className="text-[10px] text-soc-dim opacity-50">Authorized use only</p>
      </div>
    </aside>
  );
}
