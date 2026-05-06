"use client";

import { useEffect, useState } from "react";
import { AuditRunner } from "@/components/soc/AuditRunner";
import { api } from "@/lib/api";
import { Terminal, Target, AlertTriangle, Search } from "lucide-react";

const RUNNERS = [
  {
    endpoint:    "/audit/validate",
    label:       "1. Validar Entorno",
    description: "Verifica conectividad al DC, credenciales LDAP, puertos AD y disponibilidad de herramientas. Ejecutar siempre primero.",
    accentColor: "yellow",
    group:       "recon",
  },
  {
    endpoint:    "/audit/dns",
    label:       "2. DNS Check",
    description: "Registros SOA/NS/MX/SRV, resolución del DC, intento de zone transfer AXFR.",
    accentColor: "green",
    group:       "recon",
  },
  {
    endpoint:    "/audit/ldap",
    label:       "3. LDAP Enumeration",
    description: "ldapdomaindump — enumera usuarios, grupos, GPOs y equipos del dominio vía LDAP/LDAPS.",
    accentColor: "blue",
    group:       "recon",
  },
  {
    endpoint:    "/audit/bloodhound",
    label:       "4. BloodHound Collection",
    description: "bloodhound-python DCOnly — ACLs, sessions, trusts, GPOs. Genera ZIP para importar en BloodHound.",
    accentColor: "red",
    group:       "recon",
  },
  {
    endpoint:    "/audit/asrep-roast",
    label:       "5. AS-REP Roasting",
    description: "T1558.004 — Identifica cuentas sin pre-auth Kerberos, solicita AS-REP hashes e intenta crackear offline. No requiere contraseña.",
    accentColor: "orange",
    group:       "attack",
    badge:       "T1558.004",
  },
  {
    endpoint:    "/audit/kerberoast",
    label:       "6. Kerberoasting",
    description: "T1558.003 — Enumera cuentas con SPN, solicita TGS tickets y crackea hashes RC4 offline para recuperar contraseñas de servicio.",
    accentColor: "red",
    group:       "attack",
    badge:       "T1558.003",
  },
  {
    endpoint:    "/audit/run",
    label:       "7. Safe Audit Completo",
    description: "Orquestador: ejecuta validación → DNS → LDAP → BloodHound en secuencia. Lee settings inyectados desde el panel.",
    accentColor: "emerald",
    group:       "full",
  },
  {
    endpoint:    "/audit/export",
    label:       "Exportar Logs",
    description: "Empaqueta todos los reportes y logs generados en un archivo .tar.gz para descarga.",
    accentColor: "purple",
    group:       "util",
  },
];

export default function AuditPage() {
  const [dc,     setDc]     = useState("—");
  const [domain, setDomain] = useState("—");
  const [ready,  setReady]  = useState<boolean | null>(null);

  useEffect(() => {
    api.settings().then((s) => {
      const m: Record<string, string> = {};
      for (const d of s) m[d.key] = d.value ?? d.default;
      setDc(m.DC_IP || "—");
      setDomain(m.AD_DOMAIN || "—");
      setReady(!!(m.DC_IP && m.DC_IP !== "192.168.1.10" && m.AD_PASSWORD));
    }).catch(() => {});
  }, []);

  return (
    <div className="space-y-5 p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Terminal className="w-6 h-6 text-soc-accent" />
        <div>
          <h1 className="text-lg font-bold text-soc-text">Auditoría Active Directory</h1>
          <p className="text-xs text-soc-dim">
            Enumeración defensiva. Output en tiempo real vía SSE desde kali-audit.
          </p>
        </div>
      </div>

      {/* Target info */}
      <div className={`rounded-lg border px-4 py-3 flex items-center gap-4 text-xs
        ${ready === true  ? "border-soc-accent/30 bg-soc-accent/5"
        : ready === false ? "border-yellow-500/30 bg-yellow-500/5"
        : "border-soc-border bg-soc-card"}`}>
        <Target className={`w-4 h-4 shrink-0 ${ready ? "text-soc-accent" : "text-yellow-400"}`} />
        <span>
          <span className="text-soc-dim">Target: </span>
          <span className="font-mono font-semibold text-soc-text">{dc}</span>
          <span className="text-soc-dim mx-2">·</span>
          <span className="font-mono font-semibold text-soc-text">{domain}</span>
        </span>
        {ready === false && (
          <span className="text-yellow-400 ml-2">
            ⚠ Configura las credenciales en{" "}
            <a href="/settings" className="underline">Settings</a> antes de auditar
          </span>
        )}
        {ready === true && (
          <span className="text-soc-green ml-2">✓ Credenciales configuradas — listo para auditar</span>
        )}
      </div>

      {/* Tomcat OCSP module shortcut */}
      <a
        href="/tomcat-scanner"
        className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 px-4 py-3 flex items-center gap-3 text-xs hover:bg-cyan-500/10 transition-colors"
      >
        <Search className="w-4 h-4 shrink-0 text-cyan-400" />
        <div>
          <span className="font-semibold text-cyan-400">5. Tomcat OCSP Scanner</span>
          <span className="text-soc-dim ml-2">— Módulo independiente con target configurable (dominio / IP pública)</span>
        </div>
        <span className="ml-auto text-soc-dim text-[10px]">→ Ir al módulo</span>
      </a>

      {/* Safety notice */}
      <div className="rounded-lg border border-soc-border bg-soc-surface/50 px-4 py-3 text-xs text-soc-dim flex gap-3">
        <AlertTriangle className="w-4 h-4 shrink-0 text-yellow-400 mt-0.5" />
        <span>
          <strong className="text-yellow-400">Entorno autorizado.</strong>{" "}
          Herramientas de Purple Team para laboratorio controlado. Los settings del panel
          (DC IP, credenciales, rate limits) se inyectan automáticamente en cada ejecución.{" "}
          <strong className="text-soc-text">SAFE_MODE=true</strong> — no realiza modificaciones en el AD.
        </span>
      </div>

      {/* Runners */}
      <div className="space-y-4">
        {RUNNERS.map((r) => (
          <AuditRunner key={r.endpoint} {...r} />
        ))}
      </div>
    </div>
  );
}
