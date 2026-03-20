"use client";

import { cn, ServiceStatus, STATUS_BG, STATUS_COLOR, STATUS_DOT } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";

interface StatusCardProps {
  title:   string;
  status:  ServiceStatus;
  detail?: string;
  sub?:    string;
  icon?:   LucideIcon;
}

export function StatusCard({ title, status, detail, sub, icon: Icon }: StatusCardProps) {
  const isAlive = status === "up" || status === "starting";

  return (
    <div
      className={cn(
        "rounded-lg border p-4 flex flex-col gap-2 transition-colors",
        "bg-soc-card",
        STATUS_BG[status]
      )}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {Icon && <Icon className={cn("w-4 h-4", STATUS_COLOR[status])} />}
          <span className={cn("text-sm font-semibold", STATUS_COLOR[status])}>{title}</span>
        </div>
        <span
          className={cn(
            "w-2.5 h-2.5 rounded-full shrink-0",
            STATUS_DOT[status],
            isAlive && "pulse-dot"
          )}
        />
      </div>
      {detail && (
        <p className="text-xs text-soc-dim leading-snug">{detail}</p>
      )}
      {sub && (
        <p className="text-[10px] text-soc-dim opacity-60">{sub}</p>
      )}
    </div>
  );
}

export function StatusBadge({ status }: { status: ServiceStatus }) {
  const label: Record<ServiceStatus, string> = {
    up:        "UP",
    down:      "DOWN",
    degraded:  "DEGRADED",
    starting:  "STARTING",
    unknown:   "UNKNOWN",
    not_found: "NOT FOUND",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase",
        STATUS_COLOR[status],
        STATUS_BG[status],
        "border"
      )}
    >
      <span className={cn("w-1.5 h-1.5 rounded-full", STATUS_DOT[status])} />
      {label[status]}
    </span>
  );
}
