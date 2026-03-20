"use client";

import { useState } from "react";
import { api, type Container } from "@/lib/api";
import {
  containerStatusToService,
  formatDate,
  cn,
  STATUS_COLOR,
  STATUS_DOT,
} from "@/lib/utils";
import { StatusBadge } from "@/components/soc/StatusCard";
import { RefreshCw, RotateCcw, Terminal } from "lucide-react";

interface LogModalProps {
  name:    string;
  content: string;
  onClose: () => void;
}

function LogModal({ name, content, onClose }: LogModalProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70"
      onClick={onClose}
    >
      <div
        className="bg-soc-card border border-soc-border rounded-lg w-[80vw] max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-soc-border">
          <h3 className="text-sm font-semibold text-soc-text flex items-center gap-2">
            <Terminal className="w-4 h-4 text-soc-accent" />
            {name} — logs
          </h3>
          <button
            onClick={onClose}
            className="text-soc-dim hover:text-soc-text text-xs px-2 py-1 rounded hover:bg-soc-muted/30"
          >
            ✕ Close
          </button>
        </div>
        <div className="terminal flex-1 overflow-auto m-3 rounded text-xs">
          <pre>{content || "(empty)"}</pre>
        </div>
      </div>
    </div>
  );
}

interface ContainerTableProps {
  containers:  Container[];
  onRefresh:   () => void;
  loading:     boolean;
}

export function ContainerTable({ containers, onRefresh, loading }: ContainerTableProps) {
  const [restarting, setRestarting] = useState<string | null>(null);
  const [logModal,   setLogModal]   = useState<{ name: string; content: string } | null>(null);
  const [toast,      setToast]      = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3000);
  };

  const handleRestart = async (name: string) => {
    setRestarting(name);
    try {
      const r = await api.restartContainer(name);
      showToast(r.message);
    } catch (e) {
      showToast(`Error: ${e}`);
    } finally {
      setRestarting(null);
      onRefresh();
    }
  };

  const handleLogs = async (name: string) => {
    try {
      const r = await api.containerLogs(name, 300);
      setLogModal({ name, content: r.logs });
    } catch (e) {
      showToast(`Error loading logs: ${e}`);
    }
  };

  const btnBase =
    "inline-flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors";

  return (
    <>
      {/* Toast */}
      {toast && (
        <div className="fixed bottom-4 right-4 z-50 bg-soc-card border border-soc-border rounded px-3 py-2 text-xs text-soc-text shadow-lg">
          {toast}
        </div>
      )}

      {/* Log modal */}
      {logModal && (
        <LogModal
          name={logModal.name}
          content={logModal.content}
          onClose={() => setLogModal(null)}
        />
      )}

      {/* Table */}
      <div className="rounded-lg border border-soc-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 bg-soc-surface border-b border-soc-border">
          <h2 className="text-sm font-semibold text-soc-text">Contenedores del laboratorio</h2>
          <button
            onClick={onRefresh}
            disabled={loading}
            className={cn(btnBase, "text-soc-dim hover:text-soc-text hover:bg-soc-muted/30")}
          >
            <RefreshCw className={cn("w-3 h-3", loading && "animate-spin")} />
            Refresh
          </button>
        </div>

        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-soc-border bg-soc-surface/50">
              {["Nombre", "Estado", "Health", "Imagen", "Acciones"].map((h) => (
                <th
                  key={h}
                  className="px-4 py-2.5 text-left font-semibold text-soc-dim uppercase tracking-wide text-[10px]"
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {containers.map((c, i) => {
              const svc = containerStatusToService(c.status, c.health);
              return (
                <tr
                  key={c.name}
                  className={cn(
                    "border-b border-soc-border/50 transition-colors hover:bg-soc-muted/10",
                    i % 2 === 0 ? "bg-soc-card" : "bg-soc-surface/30"
                  )}
                >
                  <td className="px-4 py-2.5 font-mono text-soc-text font-medium">
                    {c.name}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={cn("font-mono", STATUS_COLOR[svc])}>{c.status}</span>
                  </td>
                  <td className="px-4 py-2.5">
                    <StatusBadge status={svc} />
                  </td>
                  <td className="px-4 py-2.5 text-soc-dim font-mono truncate max-w-[180px]">
                    {c.image}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => handleLogs(c.name)}
                        className={cn(btnBase, "bg-soc-muted/20 text-soc-dim hover:text-soc-text")}
                      >
                        <Terminal className="w-3 h-3" />
                        Logs
                      </button>
                      {c.status !== "not_found" && (
                        <button
                          onClick={() => handleRestart(c.name)}
                          disabled={restarting === c.name}
                          className={cn(
                            btnBase,
                            "bg-yellow-500/10 text-yellow-400 hover:bg-yellow-500/20",
                            "disabled:opacity-40"
                          )}
                        >
                          <RotateCcw
                            className={cn("w-3 h-3", restarting === c.name && "animate-spin")}
                          />
                          {restarting === c.name ? "…" : "Restart"}
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
