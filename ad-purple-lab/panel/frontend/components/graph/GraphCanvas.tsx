"use client";

import { useEffect, useRef, useCallback } from "react";
import type { GraphNode, GraphEdge } from "@/lib/api";

// ── Node color palette by label ────────────────────────────────────────────

const LABEL_COLOR: Record<string, string> = {
  ADUser:     "#818cf8",
  ADGroup:    "#34d399",
  ADComputer: "#f59e0b",
  ADOU:       "#f87171",
  ADDomain:   "#a78bfa",
  User:       "#818cf8",
  Group:      "#34d399",
  Computer:   "#f59e0b",
  Domain:     "#a78bfa",
  Folder:     "#fb923c",  // orange — file server folders
  Unknown:    "#6b7280",
};

function nodeColor(label: string): string {
  return LABEL_COLOR[label] ?? "#6b7280";
}

const NODE_R = 22;      // circle radius px
const FONT   = "11px 'JetBrains Mono', monospace";

// ── Simulation types ───────────────────────────────────────────────────────

interface SimNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  dragging?: boolean;
}

interface SimEdge extends GraphEdge {
  source: SimNode;
  target: SimNode;
}

// ── Force simulation ───────────────────────────────────────────────────────

function buildSim(nodes: SimNode[], edges: SimEdge[]) {
  const REPEL   = 9000;
  const SPRING  = 0.004;
  const REST    = 140;
  const GRAVITY = 0.006;
  const DAMP    = 0.87;

  function step() {
    // Dampen velocities
    for (const n of nodes) {
      if (n.dragging) { n.vx = 0; n.vy = 0; continue; }
      n.vx *= DAMP;
      n.vy *= DAMP;
    }

    // Node–node repulsion (O(n²) — fine for <200 nodes)
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        if (a.dragging && b.dragging) continue;
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        const d2 = dx * dx + dy * dy || 1;
        const d  = Math.sqrt(d2);
        const f  = REPEL / (d2 + 1);
        dx /= d; dy /= d;
        if (!a.dragging) { a.vx += dx * f; a.vy += dy * f; }
        if (!b.dragging) { b.vx -= dx * f; b.vy -= dy * f; }
      }
    }

    // Edge spring attraction
    for (const e of edges) {
      const a = e.source, b = e.target;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const d  = Math.sqrt(dx * dx + dy * dy) || 1;
      const f  = SPRING * (d - REST);
      const fx = (dx / d) * f;
      const fy = (dy / d) * f;
      if (!a.dragging) { a.vx += fx; a.vy += fy; }
      if (!b.dragging) { b.vx -= fx; b.vy -= fy; }
    }

    // Center gravity
    for (const n of nodes) {
      if (n.dragging) continue;
      n.vx -= n.x * GRAVITY;
      n.vy -= n.y * GRAVITY;
    }

    // Integrate
    for (const n of nodes) {
      if (n.dragging) continue;
      n.x += n.vx;
      n.y += n.vy;
    }
  }

  return { step };
}

// ── Draw ───────────────────────────────────────────────────────────────────

function draw(
  ctx: CanvasRenderingContext2D,
  w: number,
  h: number,
  nodes: SimNode[],
  edges: SimEdge[],
  hovered: SimNode | null,
) {
  ctx.clearRect(0, 0, w, h);

  const cx = w / 2;
  const cy = h / 2;

  // Edges
  ctx.save();
  ctx.translate(cx, cy);

  for (const e of edges) {
    const { source: a, target: b } = e;
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const d  = Math.sqrt(dx * dx + dy * dy) || 1;
    const ux = dx / d;
    const uy = dy / d;

    const sx = a.x + ux * NODE_R;
    const sy = a.y + uy * NODE_R;
    const ex = b.x - ux * NODE_R;
    const ey = b.y - uy * NODE_R;

    // Line
    ctx.beginPath();
    ctx.moveTo(sx, sy);
    ctx.lineTo(ex, ey);
    ctx.strokeStyle = "#374151";
    ctx.lineWidth   = 1.5;
    ctx.stroke();

    // Arrowhead
    const angle = Math.atan2(ey - sy, ex - sx);
    const aLen  = 10;
    const aAng  = Math.PI / 6;
    ctx.beginPath();
    ctx.moveTo(ex, ey);
    ctx.lineTo(ex - aLen * Math.cos(angle - aAng), ey - aLen * Math.sin(angle - aAng));
    ctx.lineTo(ex - aLen * Math.cos(angle + aAng), ey - aLen * Math.sin(angle + aAng));
    ctx.closePath();
    ctx.fillStyle = "#374151";
    ctx.fill();

    // Edge label
    const mx = (sx + ex) / 2;
    const my = (sy + ey) / 2;
    ctx.font         = "9px monospace";
    ctx.fillStyle    = "#6b7280";
    ctx.textAlign    = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(e.type, mx, my - 7);
  }

  // Nodes
  for (const n of nodes) {
    const isHovered = hovered?.id === n.id;
    const color     = nodeColor(n.label);

    // Glow for hovered
    if (isHovered) {
      ctx.shadowColor = color;
      ctx.shadowBlur  = 18;
    }

    // Circle fill
    ctx.beginPath();
    ctx.arc(n.x, n.y, NODE_R, 0, Math.PI * 2);
    ctx.fillStyle   = isHovered ? color : color + "33";
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.lineWidth   = isHovered ? 2.5 : 1.5;
    ctx.stroke();

    ctx.shadowBlur = 0;

    // Label initial inside circle
    ctx.font         = "bold 10px monospace";
    ctx.fillStyle    = isHovered ? "#000" : color;
    ctx.textAlign    = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(n.label.slice(0, 2).toUpperCase(), n.x, n.y);

    // Title below circle
    const title = n.title.length > 18 ? n.title.slice(0, 17) + "…" : n.title;
    ctx.font         = FONT;
    ctx.fillStyle    = isHovered ? "#e5e7eb" : "#9ca3af";
    ctx.textAlign    = "center";
    ctx.textBaseline = "top";
    ctx.fillText(title, n.x, n.y + NODE_R + 4);
  }

  ctx.restore();
}

// ── Legend ─────────────────────────────────────────────────────────────────

function drawLegend(ctx: CanvasRenderingContext2D, labels: string[]) {
  let y = 14;
  for (const lbl of labels) {
    ctx.beginPath();
    ctx.arc(14, y, 6, 0, Math.PI * 2);
    ctx.fillStyle = nodeColor(lbl) + "55";
    ctx.fill();
    ctx.strokeStyle = nodeColor(lbl);
    ctx.lineWidth   = 1.5;
    ctx.stroke();

    ctx.font         = "10px monospace";
    ctx.fillStyle    = "#9ca3af";
    ctx.textAlign    = "left";
    ctx.textBaseline = "middle";
    ctx.fillText(lbl, 26, y);

    y += 20;
  }
}

// ── Component ──────────────────────────────────────────────────────────────

interface Props {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export default function GraphCanvas({ nodes: rawNodes, edges: rawEdges }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const simNodes  = useRef<SimNode[]>([]);
  const simEdges  = useRef<SimEdge[]>([]);
  const rafRef    = useRef<number>(0);
  const hovRef    = useRef<SimNode | null>(null);
  const dragRef   = useRef<SimNode | null>(null);
  const frameRef  = useRef(0);

  // Rebuild sim when data changes
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const w = canvas.offsetWidth || 800;
    const h = canvas.offsetHeight || 500;

    simNodes.current = rawNodes.map((n) => ({
      ...n,
      x:  (Math.random() - 0.5) * Math.min(w, h) * 0.6,
      y:  (Math.random() - 0.5) * Math.min(w, h) * 0.6,
      vx: 0,
      vy: 0,
    }));

    const nodeMap = new Map(simNodes.current.map((n) => [n.id, n]));
    simEdges.current = rawEdges
      .map((e) => ({ ...e, source: nodeMap.get(e.from)!, target: nodeMap.get(e.to)! }))
      .filter((e) => e.source && e.target);

    frameRef.current = 0;
    hovRef.current   = null;
  }, [rawNodes, rawEdges]);

  // Animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const sim = buildSim(simNodes.current, simEdges.current);

    function tick() {
      const w = canvas!.width;
      const h = canvas!.height;

      frameRef.current++;
      // Settle after 200 frames (stop wasting CPU)
      if (frameRef.current < 200) {
        sim.step();
      }

      const uniqueLabels = Array.from(new Set(simNodes.current.map((n) => n.label)));
      draw(ctx!, w, h, simNodes.current, simEdges.current, hovRef.current);
      drawLegend(ctx!, uniqueLabels);

      rafRef.current = requestAnimationFrame(tick);
    }

    rafRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(rafRef.current);
  }, []);

  // Canvas resize
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ro = new ResizeObserver(() => {
      canvas.width  = canvas.offsetWidth;
      canvas.height = canvas.offsetHeight;
      frameRef.current = 0;
    });
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
    ro.observe(canvas);
    return () => ro.disconnect();
  }, []);

  // ── Mouse interaction ──────────────────────────────────────────────────

  const hitTest = useCallback((cx: number, cy: number, mx: number, my: number) => {
    const ox = mx - cx;
    const oy = my - cy;
    for (const n of simNodes.current) {
      const dx = n.x - ox;
      const dy = n.y - oy;
      if (dx * dx + dy * dy <= (NODE_R + 4) ** 2) return n;
    }
    return null;
  }, []);

  const getCenter = (canvas: HTMLCanvasElement) => ({
    cx: canvas.width  / 2,
    cy: canvas.height / 2,
  });

  const onMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx   = e.clientX - rect.left;
      const my   = e.clientY - rect.top;
      const { cx, cy } = getCenter(canvas);

      if (dragRef.current) {
        dragRef.current.x = mx - cx;
        dragRef.current.y = my - cy;
        frameRef.current = 0;
        return;
      }

      const hit = hitTest(cx, cy, mx, my);
      hovRef.current = hit;
      canvas.style.cursor = hit ? "grab" : "default";
    },
    [hitTest],
  );

  const onMouseDown = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const mx   = e.clientX - rect.left;
      const my   = e.clientY - rect.top;
      const { cx, cy } = getCenter(canvas);
      const hit = hitTest(cx, cy, mx, my);
      if (hit) {
        dragRef.current   = hit;
        hit.dragging      = true;
        canvas.style.cursor = "grabbing";
      }
    },
    [hitTest],
  );

  const onMouseUp = useCallback(() => {
    if (dragRef.current) {
      dragRef.current.dragging = false;
      dragRef.current = null;
    }
    frameRef.current = 0; // resume settling
  }, []);

  if (rawNodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-soc-dim text-sm font-mono">
        No hay datos de grafo para esta query
      </div>
    );
  }

  return (
    <canvas
      ref={canvasRef}
      className="w-full h-full"
      style={{ display: "block" }}
      onMouseMove={onMouseMove}
      onMouseDown={onMouseDown}
      onMouseUp={onMouseUp}
      onMouseLeave={onMouseUp}
    />
  );
}
