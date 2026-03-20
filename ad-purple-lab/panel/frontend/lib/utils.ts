import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export type ServiceStatus = "up" | "down" | "degraded" | "starting" | "unknown" | "not_found";

export function containerStatusToService(status: string, health: string): ServiceStatus {
  if (status === "not_found") return "not_found";
  if (status !== "running") return "down";
  if (health === "healthy") return "up";
  if (health === "starting") return "starting";
  if (health === "unhealthy") return "degraded";
  if (health === "no_healthcheck") return "up"; // running without healthcheck = up
  return "unknown";
}

export const STATUS_COLOR: Record<ServiceStatus, string> = {
  up:        "text-emerald-400",
  down:      "text-red-400",
  degraded:  "text-yellow-400",
  starting:  "text-blue-400",
  unknown:   "text-gray-400",
  not_found: "text-gray-600",
};

export const STATUS_BG: Record<ServiceStatus, string> = {
  up:        "bg-emerald-400/10 border-emerald-400/20",
  down:      "bg-red-400/10 border-red-400/20",
  degraded:  "bg-yellow-400/10 border-yellow-400/20",
  starting:  "bg-blue-400/10 border-blue-400/20",
  unknown:   "bg-gray-400/10 border-gray-400/20",
  not_found: "bg-gray-900/50 border-gray-800",
};

export const STATUS_DOT: Record<ServiceStatus, string> = {
  up:        "bg-emerald-400",
  down:      "bg-red-500",
  degraded:  "bg-yellow-400",
  starting:  "bg-blue-400",
  unknown:   "bg-gray-500",
  not_found: "bg-gray-700",
};

export function formatBytes(bytes: number): string {
  const units = ["B", "KB", "MB", "GB"];
  let v = bytes;
  for (const u of units) {
    if (v < 1024) return `${v.toFixed(1)} ${u}`;
    v /= 1024;
  }
  return `${v.toFixed(1)} TB`;
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}
