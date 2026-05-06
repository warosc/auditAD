"use client";

import { useCallback, useRef, useState } from "react";
import { streamPost, type StreamEvent } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  Play,
  Square,
  Trash2,
  Download,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Loader2,
} from "lucide-react";

const DEFAULT_PORTS = [443, 8443, 8080];

interface ScanResult {
  target:         string;
  tomcat_version: string;
  vulnerable:     boolean | string;
  cves:           string[];
  ocsp_stapling:  boolean;
  ocsp_missing_ports: number[];
  tls_protocol:   string | null;
  tls_cipher:     string | null;
  insecure_tls:   boolean;
  weak_reason:    string | null;
  cert_cn:        string | null;
  cert_expiry:    string | null;
  findings:       string[];
  port_443:       boolean;
  port_8443:      boolean;
  port_8080:      boolean;
  checked_at:     string;
}

export function TomcatScanner() {
  const [target,    setTarget]    = useState("");
  const [ports,     setPorts]     = useState<number[]>(DEFAULT_PORTS);
  const [running,   setRunning]   = useState(false);
  const [output,    setOutput]    = useState("");
  const [elapsed,   setElapsed]   = useState<number | null>(null);
  const [error,     setError]     = useState<string | null>(null);
  const [result,    setResult]    = useState<ScanResult | null>(null);

  const termRef  = useRef<HTMLPreElement>(null);
  const abortRef = useRef<AbortController | null>(null);

  const scrollToBottom = () => {
    if (termRef.current) {
      termRef.current.parentElement!.scrollTop =
        termRef.current.parentElement!.scrollHeight;
    }
  };

  const togglePort = (port: number) => {
    setPorts((prev) =>
      prev.includes(port) ? prev.filter((p) => p !== port) : [...prev, port]
    );
  };

  const run = useCallback(async () => {
    const trimmed = target.trim();
    if (!trimmed) return;

    setRunning(true);
    setOutput("");
    setError(null);
    setElapsed(null);
    setResult(null);

    abortRef.current = new AbortController();

    // Buffer to collect JSON output lines for result parsing
    let outputBuf = "";

    const onEvent = (evt: StreamEvent) => {
      if ("error" in evt) {
        setError(evt.error);
        setRunning(false);
        return;
      }
      if ("done" in evt) {
        setElapsed(evt.elapsed);
        setRunning(false);
        // Try to parse the last JSON report emitted by the scanner
        tryParseResult(outputBuf);
        return;
      }
      if ("line" in evt) {
        outputBuf += evt.line;
        setOutput((prev) => prev + evt.line);
        setTimeout(scrollToBottom, 10);
      }
    };

    try {
      await streamPost(
        "/scan/tomcat-ocsp",
        onEvent,
        abortRef.current.signal,
        { target: trimmed, ports },
      );
    } catch (e: unknown) {
      if (e instanceof Error && e.name !== "AbortError") {
        setError(String(e));
      }
      setRunning(false);
    }
  }, [target, ports]);

  /** Extract last JSON block from output and set result card */
  function tryParseResult(raw: string) {
    // The scanner writes output/<name>.json — we parse stdout instead via
    // a JSON summary line we embed. Fallback: parse summary flags from text.
    const lines = raw.split("\n");
    // Look for a line starting with "[JSON]" that the scanner may emit
    for (const line of lines.reverse()) {
      const trimmed = line.trim();
      if (trimmed.startsWith("[JSON]")) {
        try {
          const parsed = JSON.parse(trimmed.slice(6).trim());
          if (Array.isArray(parsed) && parsed.length > 0) {
            setResult(parsed[0] as ScanResult);
          }
        } catch { /* ignore */ }
        return;
      }
    }
    // Fallback: build a lightweight result from the text output
    buildResultFromText(raw);
  }

  function buildResultFromText(raw: string) {
    const version = raw.match(/Tomcat version:\s*([\d.]+|Detected but version unknown|Unknown)/)?.[1] ?? "Unknown";
    const vuln    = raw.includes("VULNERABLE:");
    const cveMatch= raw.match(/\(([^)]+CVE[^)]+)\)/);
    const cves    = cveMatch ? cveMatch[1].split(",").map((s) => s.trim()) : [];
    const ocspOk  = raw.includes("OCSP stapling: PRESENT");
    const ocspBad = raw.includes("OCSP stapling: MISSING");
    const insec   = raw.includes("INSECURE TLS:");

    setResult({
      target,
      tomcat_version: version,
      vulnerable: vuln,
      cves,
      ocsp_stapling:  ocspOk,
      ocsp_missing_ports: ocspBad ? [] : [],
      tls_protocol:   raw.match(/Protocol\s*:\s*(\S+)/)?.[1] ?? null,
      tls_cipher:     raw.match(/Cipher\s*:\s*(.+)/)?.[1]?.trim() ?? null,
      insecure_tls:   insec,
      weak_reason:    null,
      cert_cn:        raw.match(/Cert CN\s*:\s*(.+)/)?.[1]?.trim() ?? null,
      cert_expiry:    raw.match(/Cert exp\s*:\s*(.+)/)?.[1]?.trim() ?? null,
      findings:       [],
      port_443:       raw.includes("Port 443: OPEN"),
      port_8443:      raw.includes("Port 8443: OPEN"),
      port_8080:      raw.includes("Port 8080: OPEN"),
      checked_at:     new Date().toISOString(),
    });
  }

  const stop = () => {
    abortRef.current?.abort();
    setRunning(false);
  };

  const clear = () => {
    setOutput("");
    setError(null);
    setElapsed(null);
    setResult(null);
  };

  const downloadLog = () => {
    const blob = new Blob([output], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `tomcat_ocsp_${target.replace(/[^a-z0-9]/gi, "_")}_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10000);
  };

  const btnBase = cn(
    "inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold",
    "transition-colors focus:outline-none focus:ring-2 focus:ring-offset-1",
    "focus:ring-offset-soc-card disabled:opacity-40 disabled:cursor-not-allowed"
  );

  return (
    <div className="space-y-4">
      {/* Target input */}
      <div className="rounded-lg border border-soc-border bg-soc-card p-4 space-y-4">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-soc-text">Objetivo del escaneo</h3>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !running && target.trim() && run()}
            placeholder="dominio.com  o  192.168.1.100"
            disabled={running}
            className={cn(
              "flex-1 bg-soc-surface border border-soc-border rounded px-3 py-2",
              "text-sm text-soc-text placeholder:text-soc-dim/50",
              "focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/50",
              "disabled:opacity-50 font-mono"
            )}
          />
          {running ? (
            <button
              onClick={stop}
              className={cn(btnBase, "bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/30")}
            >
              <Square className="w-3 h-3" />
              Stop
            </button>
          ) : (
            <button
              onClick={run}
              disabled={!target.trim() || ports.length === 0}
              className={cn(btnBase, "bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30 border border-cyan-500/30")}
            >
              {running ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <Play className="w-3 h-3" />
              )}
              Escanear
            </button>
          )}
        </div>

        {/* Port selection */}
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs text-soc-dim">Puertos:</span>
          {[443, 8443, 8080, 80, 8009].map((p) => (
            <label key={p} className="flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={ports.includes(p)}
                onChange={() => togglePort(p)}
                disabled={running}
                className="w-3 h-3 accent-cyan-500"
              />
              <span className="text-xs font-mono text-soc-dim hover:text-soc-text">:{p}</span>
            </label>
          ))}
        </div>

        {/* Info badges */}
        <div className="flex gap-2 flex-wrap text-[10px]">
          <span className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            OCSP Stapling
          </span>
          <span className="px-2 py-0.5 rounded bg-blue-500/10 border border-blue-500/20 text-blue-400">
            TLS Version / Cipher
          </span>
          <span className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">
            CVE-2025-24813
          </span>
          <span className="px-2 py-0.5 rounded bg-red-500/10 border border-red-500/20 text-red-400">
            CVE-2024-56337
          </span>
          <span className="px-2 py-0.5 rounded bg-orange-500/10 border border-orange-500/20 text-orange-400">
            Cert expiry
          </span>
        </div>
      </div>

      {/* Status bar */}
      {(running || elapsed !== null || error) && (
        <div className="flex items-center gap-2 px-1 text-xs">
          {running && (
            <>
              <span className="w-2 h-2 rounded-full bg-cyan-400 pulse-dot" />
              <span className="text-cyan-400 font-mono">Escaneando {target}…</span>
            </>
          )}
          {elapsed !== null && !running && (
            <>
              <span className="w-2 h-2 rounded-full bg-blue-400" />
              <span className="text-blue-400 font-mono">Completado en {elapsed}s</span>
            </>
          )}
          {error && (
            <>
              <span className="w-2 h-2 rounded-full bg-red-400" />
              <span className="text-red-400">{error}</span>
            </>
          )}
        </div>
      )}

      {/* Results card */}
      {result && !running && (
        <div className="rounded-lg border border-soc-border bg-soc-card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-soc-text font-mono">{result.target}</h3>
            <span className="text-[10px] text-soc-dim">{result.checked_at?.slice(0, 19).replace("T", " ")} UTC</span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {/* Tomcat version */}
            <ResultTile
              label="Versión Tomcat"
              value={result.tomcat_version}
              status={
                result.vulnerable === true ? "bad"
                : result.vulnerable === false ? "ok"
                : "warn"
              }
            />
            {/* OCSP stapling */}
            <ResultTile
              label="OCSP Stapling"
              value={result.ocsp_stapling ? "Presente" : "Ausente"}
              status={result.ocsp_stapling ? "ok" : "bad"}
            />
            {/* TLS */}
            <ResultTile
              label="Protocolo TLS"
              value={result.tls_protocol ?? "N/A"}
              status={result.insecure_tls ? "bad" : result.tls_protocol ? "ok" : "warn"}
            />
            {/* Cert CN */}
            <ResultTile
              label="Certificado CN"
              value={result.cert_cn ?? "N/A"}
              status={result.cert_cn ? "ok" : "warn"}
            />
          </div>

          {/* CVEs */}
          {result.cves && result.cves.length > 0 && (
            <div className="flex gap-2 flex-wrap">
              {result.cves.map((cve) => (
                <span
                  key={cve}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-red-500/15 border border-red-500/30 text-red-400"
                >
                  {cve}
                </span>
              ))}
            </div>
          )}

          {/* Findings */}
          {result.findings && result.findings.length > 0 && (
            <div className="space-y-1">
              {result.findings.map((f, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-orange-300">
                  <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5 text-orange-400" />
                  {f}
                </div>
              ))}
            </div>
          )}

          {/* Ports open */}
          <div className="flex gap-3 text-[10px] flex-wrap">
            {([443, 8443, 8080] as const).map((p) => {
              const key = `port_${p}` as keyof ScanResult;
              const open = result[key] as boolean | undefined;
              return (
                <span
                  key={p}
                  className={cn(
                    "px-2 py-0.5 rounded font-mono border",
                    open
                      ? "bg-green-500/10 border-green-500/20 text-green-400"
                      : "bg-soc-muted/20 border-soc-border text-soc-dim"
                  )}
                >
                  :{p} {open ? "open" : "closed"}
                </span>
              );
            })}
          </div>

          {/* Cipher */}
          {result.tls_cipher && (
            <p className="text-[10px] text-soc-dim font-mono">
              Cipher: <span className="text-soc-text">{result.tls_cipher}</span>
              {result.weak_reason && (
                <span className="text-red-400 ml-2">— {result.weak_reason}</span>
              )}
            </p>
          )}
        </div>
      )}

      {/* Terminal output */}
      {(output || running) && (
        <div className="rounded-lg border border-soc-border bg-soc-card p-3 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[10px] text-soc-dim uppercase tracking-widest">Output</span>
            {output && !running && (
              <div className="flex items-center gap-1">
                <button
                  onClick={downloadLog}
                  className={cn(btnBase, "bg-soc-muted/30 text-soc-dim hover:text-soc-text")}
                >
                  <Download className="w-3 h-3" />
                  Log
                </button>
                <button
                  onClick={clear}
                  className={cn(btnBase, "bg-soc-muted/30 text-soc-dim hover:text-soc-text")}
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            )}
          </div>
          <div className="terminal h-96 overflow-y-auto rounded">
            <pre ref={termRef}>{output || (running ? "Iniciando escaneo…" : "")}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Helper tile ────────────────────────────────────────────────────────────

function ResultTile({
  label,
  value,
  status,
}: {
  label: string;
  value: string;
  status: "ok" | "bad" | "warn";
}) {
  const colors = {
    ok:   "border-green-500/20  bg-green-500/5  text-green-400",
    bad:  "border-red-500/20    bg-red-500/5    text-red-400",
    warn: "border-yellow-500/20 bg-yellow-500/5 text-yellow-400",
  };
  const icons = {
    ok:   <CheckCircle className="w-3 h-3" />,
    bad:  <XCircle     className="w-3 h-3" />,
    warn: <AlertTriangle className="w-3 h-3" />,
  };
  return (
    <div className={cn("rounded-lg border p-3 space-y-1", colors[status])}>
      <div className="flex items-center gap-1 text-[10px] opacity-70">
        {icons[status]}
        {label}
      </div>
      <p className="text-xs font-mono font-semibold truncate" title={value}>{value}</p>
    </div>
  );
}
