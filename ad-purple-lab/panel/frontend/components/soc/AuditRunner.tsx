"use client";

import { useCallback, useRef, useState } from "react";
import { streamPost, type StreamEvent } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Play, Square, Trash2, Download } from "lucide-react";

interface AuditRunnerProps {
  endpoint: string;  // e.g. "/audit/run"
  label:    string;
  description?: string;
  accentColor?: string;
}

export function AuditRunner({
  endpoint,
  label,
  description,
  accentColor = "emerald",
}: AuditRunnerProps) {
  const [running,  setRunning]  = useState(false);
  const [output,   setOutput]   = useState("");
  const [elapsed,  setElapsed]  = useState<number | null>(null);
  const [error,    setError]    = useState<string | null>(null);

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
    a.click();
    URL.revokeObjectURL(url);
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
          <h3 className="text-sm font-semibold text-soc-text">{label}</h3>
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
    </div>
  );
}
