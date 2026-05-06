"use client";

import { useCallback, useRef, useState } from "react";
import { streamPost, type StreamEvent } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Play, Square, Trash2, Download, AlertTriangle } from "lucide-react";

interface AuditRunnerProps {
  endpoint:     string;  // e.g. "/audit/run"
  label:        string;
  description?: string;
  accentColor?: string;
  group?:       string;  // "recon" | "attack" | "full" | "util"
  badge?:       string;  // e.g. "T1558.003"
}

export function AuditRunner({
  endpoint,
  label,
  description,
  accentColor = "emerald",
  group,
  badge,
}: AuditRunnerProps) {
  const [running,        setRunning]        = useState(false);
  const [output,         setOutput]         = useState("");
  const [elapsed,        setElapsed]        = useState<number | null>(null);
  const [error,          setError]          = useState<string | null>(null);
  const [pendingConfirm, setPendingConfirm] = useState(false);
  const [confirmChecks,  setConfirmChecks]  = useState({ aware: false, authorized: false });

  const termRef    = useRef<HTMLPreElement>(null);
  const abortRef   = useRef<AbortController | null>(null);

  const scrollToBottom = () => {
    if (termRef.current) {
      termRef.current.parentElement!.scrollTop =
        termRef.current.parentElement!.scrollHeight;
    }
  };

  const run = useCallback(async () => {
    setRunning(true);
    setOutput("");
    setError(null);
    setElapsed(null);

    abortRef.current = new AbortController();

    const onEvent = (evt: StreamEvent) => {
      if ("error" in evt) {
        setError(evt.error);
        setRunning(false);
        return;
      }
      if ("done" in evt) {
        setElapsed(evt.elapsed);
        setRunning(false);
        return;
      }
      if ("line" in evt) {
        setOutput((prev) => prev + evt.line);
        setTimeout(scrollToBottom, 10);
      }
    };

    try {
      await streamPost(endpoint, onEvent, abortRef.current.signal);
    } catch (e: unknown) {
      if (e instanceof Error && e.name !== "AbortError") {
        setError(String(e));
      }
      setRunning(false);
    }
  }, [endpoint]);

  const stop = () => {
    abortRef.current?.abort();
    setRunning(false);
  };

  const clear = () => {
    setOutput("");
    setError(null);
    setElapsed(null);
  };

  const downloadLog = () => {
    const blob = new Blob([output], { type: "text/plain" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `${label.replace(/\s+/g, "_")}_${Date.now()}.txt`;
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
    <div className="rounded-lg border border-soc-border bg-soc-card p-4 space-y-3">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-soc-text flex items-center gap-2">
            {label}
            {badge && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-orange-500/15 text-orange-400 border border-orange-500/20">
                {badge}
              </span>
            )}
          </h3>
          {description && (
            <p className="text-xs text-soc-dim mt-0.5">{description}</p>
          )}
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-1.5 shrink-0">
          {output && !running && (
            <>
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
            </>
          )}

          {running ? (
            <button
              onClick={stop}
              className={cn(btnBase, "bg-red-500/20 text-red-400 hover:bg-red-500/30 border border-red-500/30")}
            >
              <Square className="w-3 h-3" />
              Stop
            </button>
          ) : group === "attack" ? (
            <button
              onClick={() => { setConfirmChecks({ aware: false, authorized: false }); setPendingConfirm(true); }}
              className={cn(
                btnBase,
                `bg-${accentColor}-500/20 text-${accentColor}-400`,
                `hover:bg-${accentColor}-500/30 border border-${accentColor}-500/30`
              )}
            >
              <Play className="w-3 h-3" />
              Run
            </button>
          ) : (
            <button
              onClick={run}
              className={cn(
                btnBase,
                `bg-${accentColor}-500/20 text-${accentColor}-400`,
                `hover:bg-${accentColor}-500/30 border border-${accentColor}-500/30`
              )}
            >
              <Play className="w-3 h-3" />
              Run
            </button>
          )}
        </div>
      </div>

      {/* Status bar */}
      {(running || elapsed !== null || error) && (
        <div className="flex items-center gap-2 text-xs">
          {running && (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-400 pulse-dot" />
              <span className="text-emerald-400 font-mono">Running…</span>
            </>
          )}
          {elapsed !== null && !running && (
            <>
              <span className="w-2 h-2 rounded-full bg-blue-400" />
              <span className="text-blue-400 font-mono">Completed in {elapsed}s</span>
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

      {/* Terminal output */}
      {(output || running) && (
        <div className="terminal h-72 overflow-y-auto rounded">
          <pre ref={termRef}>{output || (running ? "Waiting for output…" : "")}</pre>
        </div>
      )}

      {/* Modal de confirmación — solo para group="attack" */}
      {pendingConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-soc-card border border-orange-500/30 rounded-xl p-6 max-w-md w-full mx-4 space-y-4 shadow-2xl">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-orange-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-bold text-soc-text">Confirmación requerida — Técnica ofensiva</h4>
                {badge && <span className="text-xs font-mono text-orange-400">MITRE ATT&amp;CK: {badge}</span>}
              </div>
            </div>

            <div className="rounded-lg bg-orange-500/10 border border-orange-500/20 px-4 py-3 text-xs text-orange-300 space-y-1">
              <p className="font-semibold text-orange-400">Esta acción generará tráfico visible en el DC:</p>
              <p>• Se registrarán eventos en el log de seguridad del Domain Controller</p>
              <p>• {badge === "T1558.003"
                  ? "Event ID 4769 — TGS Request (Kerberoasting)"
                  : "Event ID 4768 — AS-REP con Pre-Auth Type 0x0"}</p>
              <p>• Confirma que tienes autorización del propietario del dominio</p>
            </div>

            <div className="space-y-3">
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={confirmChecks.aware}
                  onChange={(e) => setConfirmChecks(p => ({ ...p, aware: e.target.checked }))}
                  className="mt-0.5 accent-orange-500"
                />
                <span className="text-xs text-soc-dim">
                  Entiendo que esta técnica generará eventos de seguridad en el Domain Controller
                </span>
              </label>
              <label className="flex items-start gap-2.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={confirmChecks.authorized}
                  onChange={(e) => setConfirmChecks(p => ({ ...p, authorized: e.target.checked }))}
                  className="mt-0.5 accent-orange-500"
                />
                <span className="text-xs text-soc-dim">
                  Confirmo que tengo autorización para ejecutar esta auditoría en este dominio
                </span>
              </label>
            </div>

            <div className="flex gap-2 pt-1">
              <button
                onClick={() => setPendingConfirm(false)}
                className={cn(btnBase, "flex-1 bg-soc-muted/30 text-soc-dim hover:text-soc-text border border-soc-border")}
              >
                Cancelar
              </button>
              <button
                onClick={() => { setPendingConfirm(false); run(); }}
                disabled={!confirmChecks.aware || !confirmChecks.authorized}
                className={cn(
                  btnBase,
                  "flex-1 bg-orange-500/20 text-orange-400 hover:bg-orange-500/30 border border-orange-500/30",
                  "disabled:opacity-40 disabled:cursor-not-allowed"
                )}
              >
                <Play className="w-3 h-3" />
                Confirmar y ejecutar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
