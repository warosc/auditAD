/**
 * api.ts — Typed API client for the Panel backend.
 * All calls go to /api/* which Next.js rewrites to the FastAPI backend.
 */

const BASE = "/api";

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method:  "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body:    body ? JSON.stringify(body) : undefined,
    cache:   "no-store",
  });
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

// ── Types ──────────────────────────────────────────────────────

export interface SettingDef {
  key:         string;
  label:       string;
  group:       string;
  type:        "text" | "password" | "number" | "bool";
  default:     string;
  value?:      string;
  placeholder?: string;
  min?:        number;
  max?:        number;
  step?:       number;
  help?:       string;
}

export interface ScheduledJob {
  id:               number;
  audit_type:       string;
  label:            string;
  interval_minutes: number;
  enabled:          boolean;
  last_run:         string | null;
  next_run:         string | null;
  created_at:       string | null;
}

export interface Container {
  name:   string;
  id:     string;
  status: string;
  image:  string;
  health: string;
}

export interface Report {
  filename:   string;
  path:       string;
  size:       number;
  size_human: string;
  created:    string;
  type:       string;
}

// ── Neo4j Graph Query types ────────────────────────────────────────────────

export interface QueryParam {
  name:        string;
  label:       string;
  placeholder: string;
  required:    boolean;
}

export interface QueryDef {
  id:          string;
  title:       string;
  description: string;
  category:    string;
  risk:        "critical" | "high" | "medium" | "low" | "info";
  schema:      "csv" | "bloodhound" | "ntfs";
  params:      QueryParam[];
  cypher:      string;
}

// Standalone wrappers (also accessible via api.*)
export const neo4jQueries = () =>
  get<{ queries: QueryDef[] }>("/neo4j/queries").then((r) => r.queries);

export const neo4jExecute = (query_id: string, params: Record<string, string> = {}) =>
  post<QueryResult>("/neo4j/execute", { query_id, params });

export interface GraphNode {
  id:    string;
  label: string;
  title: string;
  props: Record<string, unknown>;
}

export interface GraphEdge {
  id:   string;
  from: string;
  to:   string;
  type: string;
}

export interface QueryResult {
  query_id:  string;
  title:     string;
  rows:      Record<string, unknown>[];
  columns:   string[];
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  count:     number;
  has_graph: boolean;
}

export interface Neo4jStats {
  connected: boolean;
  error?:    string;
  stats: {
    total_users?:     number | null;
    disabled_users?:  number | null;
    no_pwd_users?:    number | null;
    kerberoastable?:  number | null;
    asrep_roast?:     number | null;
    total_computers?: number | null;
    total_groups?:    number | null;
    legacy_os?:       number | null;
  };
}

export interface HealthResult {
  status:         string;
  http_code?:     number;
  error?:         string;
  cluster_status?: string;
  database?:      string;
}

export interface LabHealth {
  opensearch:              HealthResult;
  grafana:                 HealthResult;
  neo4j:                   HealthResult;
  "opensearch-dashboards": HealthResult;
  [key: string]:           HealthResult | { all_up: boolean; services_checked: number; services_up: number };
  _summary: {
    all_up:           boolean;
    services_checked: number;
    services_up:      number;
  };
}

// ── Endpoints ──────────────────────────────────────────────────

export const api = {
  /** Liveness probe */
  ping: () => get<{ status: string }>("/health"),

  /** List all lab containers */
  containers: () =>
    get<{ containers: Container[] }>("/containers").then((r) => r.containers),

  /** Restart a container */
  restartContainer: (name: string) =>
    post<{ status: string; message: string }>(`/containers/${name}/restart`),

  /** Get container logs */
  containerLogs: (name: string, tail = 200) =>
    get<{ container: string; logs: string }>(
      `/containers/${name}/logs?tail=${tail}`
    ),

  /** List reports */
  reports: () =>
    get<{ reports: Report[]; total: number }>("/reports"),

  /** Audit run history */
  auditHistory: () =>
    get<{ history: unknown[]; total: number }>("/reports/history"),

  /** Full lab health check */
  labHealth: () => get<LabHealth>("/lab/health"),

  /** Download URL for a report file */
  downloadUrl: (filename: string) => `${BASE}/reports/download/${filename}`,

  // ── Settings ─────────────────────────────────────────────────

  /** Get all settings (defs + current values) */
  settings: () =>
    get<{ settings: SettingDef[] }>("/settings").then((r) => r.settings),

  /** Save key-value settings */
  saveSettings: (settings: Record<string, string>) =>
    post<{ status: string; count: number }>("/settings", { settings }),

  /** Get settings schema (no values) */
  settingsSchema: () =>
    get<{ definitions: SettingDef[] }>("/settings/schema").then(
      (r) => r.definitions
    ),

  // ── Schedule ─────────────────────────────────────────────────

  /** List scheduled jobs and available audit types */
  schedule: () =>
    get<{ jobs: ScheduledJob[]; audit_types: Record<string, string> }>(
      "/settings/schedule"
    ),

  /** Add a scheduled job */
  addScheduleJob: (
    audit_type: string,
    interval_minutes: number,
    label = ""
  ) =>
    post<{ status: string; job: ScheduledJob }>("/settings/schedule", {
      audit_type,
      interval_minutes,
      label,
    }),

  /** Enable/disable a scheduled job */
  toggleScheduleJob: (id: number, enabled: boolean) => {
    const res = fetch(`${BASE}/settings/schedule/${id}`, {
      method:  "PATCH",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ enabled }),
      cache:   "no-store",
    });
    return res.then((r) => {
      if (!r.ok) throw new Error(`PATCH /settings/schedule/${id} → ${r.status}`);
      return r.json() as Promise<{ status: string; job: ScheduledJob }>;
    });
  },

  /** Delete a scheduled job */
  deleteScheduleJob: (id: number) => {
    const res = fetch(`${BASE}/settings/schedule/${id}`, {
      method: "DELETE",
      cache:  "no-store",
    });
    return res.then((r) => {
      if (!r.ok) throw new Error(`DELETE /settings/schedule/${id} → ${r.status}`);
      return r.json() as Promise<{ status: string }>;
    });
  },

  // ── Neo4j Graph Query ─────────────────────────────────────────────────

  /** Get the full Cypher query catalog */
  neo4jQueries: () =>
    get<{ queries: QueryDef[] }>("/neo4j/queries").then((r) => r.queries),

  /** Get quick AD stats for dashboard cards */
  neo4jStats: () => get<Neo4jStats>("/neo4j/stats"),

  /** Execute a predefined query with optional params */
  neo4jExecute: (query_id: string, params: Record<string, string> = {}) =>
    post<QueryResult>("/neo4j/execute", { query_id, params }),

  /** Get the last 100 executed queries (audit log) */
  neo4jLog: () =>
    get<{ log: unknown[] }>("/neo4j/log").then((r) => r.log),
};

// ── Streaming helper ───────────────────────────────────────────

export type StreamEvent =
  | { line: string; type?: string }
  | { done: true; elapsed: number }
  | { error: string };

/**
 * Posts to *endpoint* and streams SSE-formatted events.
 * Calls *onEvent* for each parsed event, *onDone* when the stream ends.
 */
export async function streamPost(
  endpoint: string,
  onEvent: (evt: StreamEvent) => void,
  signal?: AbortSignal,
  body?: unknown,
): Promise<void> {
  const res = await fetch(`${BASE}${endpoint}`, {
    method:  "POST",
    headers: body ? { "Content-Type": "application/json" } : undefined,
    body:    body ? JSON.stringify(body) : undefined,
    cache:   "no-store",
    signal,
  });

  if (!res.ok || !res.body) {
    onEvent({ error: `HTTP ${res.status}` });
    return;
  }

  const reader  = res.body.getReader();
  const decoder = new TextDecoder();
  let   buf     = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buf += decoder.decode(value, { stream: true });
    const lines = buf.split("\n");
    buf = lines.pop() ?? ""; // keep partial line

    for (const line of lines) {
      if (!line.startsWith("data: ")) continue;
      try {
        const evt = JSON.parse(line.slice(6)) as StreamEvent;
        onEvent(evt);
      } catch {
        // malformed SSE line — ignore
      }
    }
  }
}
