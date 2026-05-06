"use client";

import { Shield, Info } from "lucide-react";
import { TomcatScanner } from "@/components/soc/TomcatScanner";

export default function TomcatScannerPage() {
  return (
    <div className="space-y-5 p-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <Shield className="w-6 h-6 text-cyan-400" />
        <div>
          <h1 className="text-lg font-bold text-soc-text">Tomcat OCSP Scanner</h1>
          <p className="text-xs text-soc-dim">
            Análisis de versión, OCSP stapling y seguridad TLS sobre un dominio o IP pública.
          </p>
        </div>
      </div>

      {/* Info panel */}
      <div className="rounded-lg border border-soc-border bg-soc-surface/50 px-4 py-3 text-xs text-soc-dim flex gap-3">
        <Info className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
        <div className="space-y-1">
          <p>
            <strong className="text-cyan-400">OCSP stapling</strong>{" "}
            (RFC 6066) — cuando está ausente el cliente debe contactar directamente al
            OCSP responder de la CA en cada handshake TLS, filtrando el dominio visitado.
            Un servidor bien configurado debe servir la respuesta OCSP embebida en el handshake.
          </p>
          <p>
            <strong className="text-red-400">CVE-2025-24813</strong>{" "}
            Partial PUT / partial GET session fixation en Tomcat 9.0.x, 10.1.x, 11.0.x.{" "}
            <strong className="text-red-400">CVE-2024-56337</strong>{" "}
            RCE via case-insensitive filesystem (Windows/macOS) en las mismas ramas.
          </p>
          <p className="text-soc-dim/60">
            Ejecuta desde el contenedor <span className="font-mono text-soc-text">tomcat-ocsp-scanner</span> —
            separado de kali-audit. Puedes apuntar a cualquier dominio público o IP de laboratorio.
          </p>
        </div>
      </div>

      {/* Scanner module */}
      <TomcatScanner />
    </div>
  );
}
