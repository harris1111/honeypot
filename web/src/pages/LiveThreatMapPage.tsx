import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  Ban,
  CheckCircle2,
  Eye,
  Filter,
  Flame,
  Globe,
  Pause,
  Play,
  Radar,
  ShieldAlert,
  Sparkles,
  Terminal,
  X,
} from "lucide-react";
import { apiFetch, type GeoPoint, type LiveEventTick } from "../lib/api";
import { Badge, Button, Card, EmptyState, Input, StatCard } from "../components/ui/primitives";
import {
  CONTINENT_PATHS,
  LATITUDE_GRID_LINES,
  LONGITUDE_GRID_LINES,
  WORLD_VIEWBOX_HEIGHT,
  WORLD_VIEWBOX_WIDTH,
  lonLatToXY,
} from "../components/WorldMapPaths";

interface SensorNodePoint {
  id: string;
  name: string;
  region: string;
  public_ip: string;
  status: string;
  geo: GeoPoint;
}

interface TimelineBucket {
  bucket_iso: string;
  label: string;
  cowrie: number;
  webcve: number;
  llmproxy: number;
  infratrap: number;
  heralding: number;
  total: number;
}

interface KillChainStage {
  stage: string;
  label: string;
  description: string;
  count: number;
}

interface VectorMatrixRow {
  dest_port: number;
  protocol: string;
  trap_kind: string;
  count: number;
  unique_ips: number;
  max_severity: number;
}

interface AttackOrigin {
  ip: string;
  count: number;
  distinct_traps: number;
  top_trap: string;
  top_port: number;
  max_severity: number;
  last_seen_at: string;
  greynoise: string;
  asn: number;
  abuse_score: number;
  geo: GeoPoint;
}

interface TopCommandRow {
  command: string;
  count: number;
}

interface RadarEventItem {
  id: string;
  source_ip: string;
  dest_port: number;
  protocol: string;
  trap_kind: string;
  persona: string;
  cve_id: string;
  is_kev: boolean;
  http_method: string;
  http_path: string;
  raw_payload: string;
  response_summary: string;
  severity_score: number;
  canary_hit: boolean;
  observed_at: string;
  ssh_replay_id?: string;
  geo?: GeoPoint;
}

interface LiveRadarResponse {
  window: "60m" | "24h";
  kpis: {
    events_24h: number;
    events_60m: number;
    events_5m: number;
    events_per_min: number;
    unique_ips_24h: number;
    critical_events_24h: number;
    ssh_intrusions_24h: number;
    active_bans: number;
    online_sensors: number;
  };
  sensor_nodes: SensorNodePoint[];
  timeline: TimelineBucket[];
  kill_chain: KillChainStage[];
  vector_matrix: VectorMatrixRow[];
  attack_origins: AttackOrigin[];
  top_commands: TopCommandRow[];
  recent_feed: RadarEventItem[];
}

const TRAP_META: Record<string, { label: string; color: string; pill: string }> = {
  cowrie: { label: "SSH / Telnet", color: "#06b6d4", pill: "bg-cyan-500" },
  webcve: { label: "Web / CVE", color: "#f43f5e", pill: "bg-rose-500" },
  llmproxy: { label: "Ollama / AI", color: "#a855f7", pill: "bg-purple-500" },
  infratrap: { label: "DB / Docker / K8s", color: "#f59e0b", pill: "bg-amber-500" },
  heralding: { label: "FTP / Mail", color: "#10b981", pill: "bg-emerald-500" },
};

const TRAP_FILTERS: { id: string; label: string }[] = [
  { id: "all", label: "All Vectors" },
  { id: "cowrie", label: "SSH / Telnet" },
  { id: "webcve", label: "Web / CVE" },
  { id: "llmproxy", label: "Ollama / AI" },
  { id: "infratrap", label: "DB / K8s" },
  { id: "heralding", label: "FTP / Mail" },
];

function trapColor(kind: string): string {
  return TRAP_META[kind]?.color ?? "#3b82f6";
}

function severityTone(score: number, isKev?: boolean, canaryHit?: boolean): "danger" | "warning" | "info" | "default" {
  if (canaryHit || isKev || score >= 80) return "danger";
  if (score >= 55) return "warning";
  if (score > 0) return "info";
  return "default";
}

function quadBezierArc(x1: number, y1: number, x2: number, y2: number): string {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2;
  const dist = Math.hypot(x2 - x1, y2 - y1);
  const lift = Math.min(130, Math.max(24, dist * 0.28));
  const cy = Math.max(12, my - lift);
  return `M${x1},${y1} Q${mx.toFixed(1)},${cy.toFixed(1)} ${x2},${y2}`;
}

function formatShortTime(iso: string): string {
  if (!iso) return "";
  const idx = iso.indexOf("T");
  if (idx >= 0) {
    return iso.slice(idx + 1, idx + 9);
  }
  const space = iso.indexOf(" ");
  if (space >= 0) {
    return iso.slice(space + 1, space + 9);
  }
  return iso.slice(0, 12);
}

export function LiveThreatMapPage({
  liveEvents,
  onOpenReplay,
  onOpenTrapLogs,
}: {
  liveEvents: LiveEventTick[];
  onOpenReplay: (replayId: string) => void;
  onOpenTrapLogs: (trapKind: string) => void;
}) {
  const [windowMode, setWindowMode] = useState<"60m" | "24h">("60m");
  const [vectorFilter, setVectorFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [focusedIP, setFocusedIP] = useState<string>("");
  const [streamPaused, setStreamPaused] = useState(false);
  const [wavePulseNonce, setWavePulseNonce] = useState(0);
  const [rightTab, setRightTab] = useState<"actors" | "commands">("actors");
  const [hoveredBucketIdx, setHoveredBucketIdx] = useState<number | null>(null);
  const [inspectedEvent, setInspectedEvent] = useState<RadarEventItem | null>(null);
  const [actionBanner, setActionBanner] = useState<{ tone: "ok" | "err"; text: string } | null>(null);
  const [blockingIP, setBlockingIP] = useState<string>("");
  const [data, setData] = useState<LiveRadarResponse | null>(null);
  const [err, setErr] = useState("");

  const fetchRadar = useCallback(async () => {
    try {
      const res = await apiFetch<LiveRadarResponse>(`/api/admin/live-radar?window=${windowMode}`);
      setData(res);
      setErr("");
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load Live Threat Radar telemetry");
    }
  }, [windowMode]);

  useEffect(() => {
    void fetchRadar();
  }, [fetchRadar]);

  // Refresh telemetry periodically or on incoming WS bursts unless operator paused the stream
  useEffect(() => {
    if (streamPaused) return;
    const timer = window.setInterval(() => {
      void fetchRadar();
    }, 15000);
    return () => window.clearInterval(timer);
  }, [fetchRadar, streamPaused]);

  useEffect(() => {
    if (!streamPaused && liveEvents.length > 0) {
      void fetchRadar();
    }
  }, [liveEvents.length, fetchRadar, streamPaused]);

  const mergedFeed = useMemo<RadarEventItem[]>(() => {
    const byId = new Map<string, RadarEventItem>();
    for (const ev of liveEvents) {
      if (!ev.event_uuid) continue;
      byId.set(ev.event_uuid, {
        id: ev.event_uuid,
        source_ip: ev.source_ip,
        dest_port: ev.dest_port ?? 0,
        protocol: ev.protocol ?? "tcp",
        trap_kind: ev.trap_kind,
        persona: ev.persona,
        cve_id: ev.cve_id,
        is_kev: ev.is_kev,
        http_method: ev.http_method ?? "",
        http_path: ev.http_path,
        raw_payload: "",
        response_summary: ev.response_summary ?? "",
        severity_score: ev.severity,
        canary_hit: Boolean(ev.canary_hit),
        observed_at: ev.observed,
        geo: ev.geo,
      });
    }
    for (const row of data?.recent_feed ?? []) {
      const prev = byId.get(row.id);
      byId.set(row.id, prev ? { ...row, ...prev, ssh_replay_id: row.ssh_replay_id, raw_payload: row.raw_payload } : row);
    }
    return Array.from(byId.values()).slice(0, 80);
  }, [liveEvents, data?.recent_feed]);

  const filteredFeed = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return mergedFeed.filter((ev) => {
      if (vectorFilter !== "all" && ev.trap_kind !== vectorFilter) return false;
      if (focusedIP && ev.source_ip !== focusedIP) return false;
      if (!q) return true;
      return (
        ev.source_ip.toLowerCase().includes(q) ||
        ev.trap_kind.toLowerCase().includes(q) ||
        ev.cve_id.toLowerCase().includes(q) ||
        ev.http_path.toLowerCase().includes(q) ||
        ev.response_summary.toLowerCase().includes(q) ||
        (ev.geo?.region_label ?? "").toLowerCase().includes(q)
      );
    });
  }, [mergedFeed, vectorFilter, focusedIP, searchQuery]);

  const origins = useMemo(() => {
    const list = data?.attack_origins ?? [];
    if (vectorFilter === "all") return list;
    return list.filter((o) => o.top_trap === vectorFilter);
  }, [data?.attack_origins, vectorFilter]);

  const primarySensor = data?.sensor_nodes?.[0] ?? {
    id: "hive-default-sensor",
    name: "primary-honeypot-sensor",
    region: "default",
    public_ip: "",
    status: "online",
    geo: { lat: 39.04, lon: -77.49, country_code: "US", region_label: "Sensor Target Node", approximate: true },
  };
  const [sensorX, sensorY] = lonLatToXY(primarySensor.geo.lon, primarySensor.geo.lat);

  const selectedOrigin = useMemo(
    () => (focusedIP ? origins.find((o) => o.ip === focusedIP) ?? null : null),
    [focusedIP, origins]
  );

  // Threat posture indicator derived from critical ratio + live velocity
  const threatPosture = useMemo(() => {
    const crit = data?.kpis.critical_events_24h ?? 0;
    const rpm = data?.kpis.events_per_min ?? 0;
    if (crit >= 20 || rpm >= 10) {
      return { label: "DEFCON 2 · ACTIVE EXPLOIT WAVE", tone: "danger" as const };
    }
    if (crit > 0 || rpm >= 1 || (data?.kpis.events_24h ?? 0) > 0) {
      return { label: "DEFCON 3 · ELEVATED PROBES", tone: "warning" as const };
    }
    return { label: "DEFCON 4 · GUARDED WATCH", tone: "success" as const };
  }, [data]);

  const handleQuickBlockIP = async (ip: string) => {
    setBlockingIP(ip);
    setActionBanner(null);
    try {
      await apiFetch("/api/admin/guard/manual-block", {
        method: "POST",
        body: JSON.stringify({
          indicator_type: "ip",
          indicator_value: ip,
          target_sync: "nginx",
          ttl_hours: 168,
          reason: "SOC Live Threat Radar 1-click containment",
        }),
      });
      setActionBanner({ tone: "ok", text: `Enforced Nginx edge block for ${ip} (168h TTL)` });
      void fetchRadar();
    } catch (e) {
      setActionBanner({
        tone: "err",
        text: e instanceof Error ? e.message : `Failed to block ${ip}`,
      });
    } finally {
      setBlockingIP("");
    }
  };

  // Timeline chart scale calculations (pure SVG)
  const timelineBuckets = data?.timeline ?? [];
  const maxTimelineVal = Math.max(1, ...timelineBuckets.map((b) => b.total));
  const chartW = 840;
  const chartH = 150;
  const padL = 36;
  const padR = 12;
  const padT = 12;
  const padB = 26;
  const plotW = chartW - padL - padR;
  const plotH = chartH - padT - padB;
  const hoveredBucket = hoveredBucketIdx !== null ? timelineBuckets[hoveredBucketIdx] ?? null : null;

  const killMax = Math.max(1, ...(data?.kill_chain ?? []).map((s) => s.count));

  return (
    <div className="space-y-5">
      {err && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200">
          {err}
        </div>
      )}

      {actionBanner && (
        <div
          className={`flex items-center justify-between gap-3 rounded-lg border px-4 py-2.5 text-sm ${
            actionBanner.tone === "ok"
              ? "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200"
              : "border-rose-300 bg-rose-50 text-rose-900 dark:border-rose-800 dark:bg-rose-950/50 dark:text-rose-200"
          }`}
        >
          <span className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            {actionBanner.text}
          </span>
          <button type="button" onClick={() => setActionBanner(null)} className="text-xs underline">
            Dismiss
          </button>
        </div>
      )}

      {/* SOC Posture & Filter Toolbar */}
      <div className="hp-surface flex flex-wrap items-center justify-between gap-3 rounded-xl border p-3.5">
        <div className="flex flex-wrap items-center gap-2.5">
          <Badge tone={threatPosture.tone}>
            <Radar className="h-3.5 w-3.5" />
            {threatPosture.label}
          </Badge>
          <div className="flex items-center rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setWindowMode("60m")}
              className={`rounded-md px-2.5 py-1 font-medium transition ${
                windowMode === "60m"
                  ? "bg-blue-600 text-white shadow-xs"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              60m Live
            </button>
            <button
              type="button"
              onClick={() => setWindowMode("24h")}
              className={`rounded-md px-2.5 py-1 font-medium transition ${
                windowMode === "24h"
                  ? "bg-blue-600 text-white shadow-xs"
                  : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              }`}
            >
              24h Window
            </button>
          </div>
          <div className="flex flex-wrap items-center gap-1">
            {TRAP_FILTERS.map((tf) => {
              const active = vectorFilter === tf.id;
              return (
                <button
                  key={tf.id}
                  type="button"
                  onClick={() => setVectorFilter(tf.id)}
                  className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                    active
                      ? "border-blue-600 bg-blue-600/12 text-blue-700 dark:border-blue-400 dark:bg-blue-500/20 dark:text-blue-200"
                      : "border-[var(--border-subtle)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:bg-[var(--bg-subtle)]"
                  }`}
                >
                  {tf.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="secondary"
            className="px-2.5 py-1.5 text-xs"
            onClick={() => setWavePulseNonce((n) => n + 1)}
          >
            <Sparkles className="h-3.5 w-3.5 text-blue-500" />
            Replay Attack Wave
          </Button>
          <Button
            type="button"
            variant={streamPaused ? "primary" : "secondary"}
            className="px-2.5 py-1.5 text-xs"
            onClick={() => setStreamPaused((p) => !p)}
          >
            {streamPaused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            {streamPaused ? "Resume Stream" : "Live Auto-Sync"}
          </Button>
        </div>
      </div>

      {/* Tactical KPI Row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="Velocity (ev/min)"
          value={`${data?.kpis.events_per_min ?? 0}/m`}
          hint={`${data?.kpis.events_5m ?? 0} hits in last 5m`}
          tone="blue"
        />
        <StatCard
          label="Attacks (24h)"
          value={data?.kpis.events_24h ?? "—"}
          hint={`${data?.kpis.events_60m ?? 0} in last 60m`}
          tone="default"
        />
        <StatCard
          label="Unique Source IPs"
          value={data?.kpis.unique_ips_24h ?? "—"}
          hint="Distinct scanners & bots"
          tone="amber"
        />
        <StatCard
          label="Critical / KEV / Canary"
          value={data?.kpis.critical_events_24h ?? "—"}
          hint="High-confidence exploit hits"
          tone="red"
        />
        <StatCard
          label="SSH Sessions (24h)"
          value={data?.kpis.ssh_intrusions_24h ?? "—"}
          hint="Interactive shell captures"
          tone="emerald"
          onClick={() => onOpenTrapLogs("cowrie")}
        />
        <StatCard
          label="Enforced Bans"
          value={data?.kpis.active_bans ?? "—"}
          hint={`${data?.kpis.online_sensors ?? 0} sensor(s) online`}
          tone="default"
        />
      </div>

      {/* Main Map + Tactical Rail */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12">
        {/* Global SVG Threat Radar */}
        <Card
          className="xl:col-span-8"
          title={
            <span className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-500" />
              Global Live Attack Vector Radar
            </span>
          }
          subtitle="Animated attack trajectories converging on active Honeypot sensor nodes. Click any origin dot to filter the SOC stream."
          action={
            focusedIP ? (
              <Button type="button" variant="secondary" className="px-2 py-1 text-xs" onClick={() => setFocusedIP("")}>
                <X className="h-3 w-3" /> Clear IP ({focusedIP})
              </Button>
            ) : (
              <span className="text-[11px] font-medium text-[var(--text-muted)]">
                Geo: MaxMind + IANA RIR Projection
              </span>
            )
          }
        >
          <div className="relative overflow-hidden rounded-xl border border-slate-300/80 bg-gradient-to-b from-slate-100 via-sky-50/70 to-slate-100 dark:border-slate-800 dark:from-[#060d1b] dark:via-[#081326] dark:to-[#050b16]">
            <svg
              key={wavePulseNonce}
              viewBox={`0 0 ${WORLD_VIEWBOX_WIDTH} ${WORLD_VIEWBOX_HEIGHT}`}
              className="block h-auto w-full select-none"
              role="img"
              aria-label="Global Cyber Threat Vector Map"
              data-testid="world-threat-map"
            >
              <defs>
                <radialGradient id="hpSensorGlow" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.45" />
                  <stop offset="100%" stopColor="#3b82f6" stopOpacity="0" />
                </radialGradient>
              </defs>

              {/* Lat/Lon Graticule */}
              {LATITUDE_GRID_LINES.map((g) => (
                <line
                  key={`lat-${g.lat}`}
                  x1={0}
                  y1={g.y}
                  x2={WORLD_VIEWBOX_WIDTH}
                  y2={g.y}
                  className="stroke-slate-300/60 dark:stroke-slate-800/70"
                  strokeWidth={g.lat === 0 ? 1 : 0.6}
                  strokeDasharray={g.lat === 0 ? "5 4" : "2 4"}
                />
              ))}
              {LONGITUDE_GRID_LINES.map((g) => (
                <line
                  key={`lon-${g.lon}`}
                  x1={g.x}
                  y1={0}
                  x2={g.x}
                  y2={WORLD_VIEWBOX_HEIGHT}
                  className="stroke-slate-300/50 dark:stroke-slate-800/60"
                  strokeWidth={0.6}
                  strokeDasharray="2 4"
                />
              ))}

              {/* World Landmass Polygons */}
              <g className="fill-slate-300/80 stroke-slate-400/70 dark:fill-[#15243e] dark:stroke-[#263f6b]" strokeWidth={0.9}>
                {CONTINENT_PATHS.map((land) => (
                  <path key={land.id} d={land.d} />
                ))}
              </g>

              {/* Attack Arcs from Hostile Origins to Sensor Node */}
              <g fill="none">
                {origins.slice(0, 28).map((origin, idx) => {
                  const [ox, oy] = lonLatToXY(origin.geo.lon, origin.geo.lat);
                  const d = quadBezierArc(ox, oy, sensorX, sensorY);
                  const color = trapColor(origin.top_trap);
                  const selected = focusedIP === origin.ip;
                  const highPriority = idx < 10 || origin.max_severity >= 75 || selected;
                  return (
                    <g key={`arc-${origin.ip}`}>
                      <path
                        d={d}
                        stroke={color}
                        strokeWidth={selected ? 2.4 : highPriority ? 1.5 : 0.9}
                        strokeOpacity={selected ? 0.95 : highPriority ? 0.55 : 0.25}
                      />
                      {highPriority && (
                        <path
                          d={d}
                          stroke={color}
                          strokeWidth={selected ? 2.6 : 1.7}
                          strokeOpacity={0.92}
                          className="hp-arc-animated"
                        />
                      )}
                    </g>
                  );
                })}
              </g>

              {/* Attacker Origin Dots */}
              {origins.map((origin) => {
                const [ox, oy] = lonLatToXY(origin.geo.lon, origin.geo.lat);
                const color = trapColor(origin.top_trap);
                const selected = focusedIP === origin.ip;
                const radius = Math.min(7.5, Math.max(3.2, 2.5 + Math.log2(origin.count + 1) * 0.9));
                return (
                  <g
                    key={`node-${origin.ip}`}
                    className="cursor-pointer"
                    onClick={() => setFocusedIP((cur) => (cur === origin.ip ? "" : origin.ip))}
                  >
                    <title>{`${origin.ip} (${origin.geo.region_label}) — ${origin.count} hits · max sev ${origin.max_severity}`}</title>
                    {(origin.max_severity >= 80 || selected) && (
                      <circle cx={ox} cy={oy} r={radius + 5} fill={color} fillOpacity={0.22} />
                    )}
                    <circle
                      cx={ox}
                      cy={oy}
                      r={selected ? radius + 2 : radius}
                      fill={color}
                      stroke="#ffffff"
                      strokeWidth={selected ? 2 : 1.1}
                    />
                  </g>
                );
              })}

              {/* Sensor Node Target Hubs */}
              {(data?.sensor_nodes ?? [primarySensor]).map((node) => {
                const [sx, sy] = lonLatToXY(node.geo.lon, node.geo.lat);
                return (
                  <g key={`sensor-${node.id}`}>
                    <circle cx={sx} cy={sy} r={24} fill="url(#hpSensorGlow)" />
                    <circle
                      cx={sx}
                      cy={sy}
                      r={6}
                      fill="none"
                      stroke="#3b82f6"
                      strokeWidth={1.6}
                      className="hp-sensor-pulse"
                    />
                    <circle cx={sx} cy={sy} r={5.5} fill="#2563eb" stroke="#ffffff" strokeWidth={1.8} />
                    <text
                      x={sx + 10}
                      y={sy + 4}
                      fontSize="11"
                      fontWeight="700"
                      className="fill-slate-900 dark:fill-blue-100"
                    >
                      {node.name}
                    </text>
                  </g>
                );
              })}
            </svg>

            {/* Map Overlay HUD for Selected Origin */}
            {selectedOrigin && (
              <div className="hp-surface absolute bottom-3 left-3 max-w-xs rounded-xl border p-3 text-xs shadow-lg">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono font-bold text-[var(--text-primary)]">{selectedOrigin.ip}</span>
                  <Badge tone={severityTone(selectedOrigin.max_severity)}>Sev {selectedOrigin.max_severity}</Badge>
                </div>
                <div className="mt-1 text-[var(--text-secondary)]">
                  {selectedOrigin.geo.region_label} · {selectedOrigin.count} hits · Top port :{selectedOrigin.top_port || 22}
                </div>
                <div className="mt-2 flex items-center gap-2">
                  <Button
                    type="button"
                    variant="danger"
                    className="px-2 py-1 text-[11px]"
                    disabled={blockingIP === selectedOrigin.ip}
                    onClick={() => void handleQuickBlockIP(selectedOrigin.ip)}
                  >
                    <Ban className="h-3 w-3" /> Block IP
                  </Button>
                  <button
                    type="button"
                    className="text-[11px] font-medium text-[var(--text-muted)] underline"
                    onClick={() => setFocusedIP("")}
                  >
                    Clear filter
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Vector Color Legend */}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3 text-xs text-[var(--text-secondary)]">
            <div className="flex flex-wrap items-center gap-3">
              {Object.entries(TRAP_META).map(([k, meta]) => (
                <span key={k} className="inline-flex items-center gap-1.5">
                  <span className={`h-2.5 w-2.5 rounded-full ${meta.pill}`} />
                  {meta.label}
                </span>
              ))}
              <span className="inline-flex items-center gap-1.5 font-medium text-blue-600 dark:text-blue-400">
                <span className="h-2.5 w-2.5 rounded-full bg-blue-600 ring-2 ring-blue-400/50" />
                Honeypot Sensor
              </span>
            </div>
            <span className="tabular-nums text-[var(--text-muted)]">{origins.length} active attacker origins plotted</span>
          </div>
        </Card>

        {/* Right Tactical Rail: Kill-Chain Funnel & Targeted Ports Matrix */}
        <div className="space-y-5 xl:col-span-4">
          <Card
            title={
              <span className="flex items-center gap-2">
                <Flame className="h-4 w-4 text-rose-500" />
                24h Attack Kill-Chain Funnel
              </span>
            }
            subtitle="Progression from initial scan to containment."
          >
            <div className="space-y-3">
              {(data?.kill_chain ?? []).map((stage, idx) => {
                const pct = Math.max(4, Math.min(100, Math.round((stage.count / killMax) * 100)));
                const barColors = [
                  "bg-sky-500",
                  "bg-cyan-500",
                  "bg-amber-500",
                  "bg-purple-500",
                  "bg-rose-500",
                ];
                return (
                  <div key={stage.stage} className="space-y-1">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <span className="font-semibold text-[var(--text-primary)]">
                        {idx + 1}. {stage.label}
                      </span>
                      <span className="font-mono font-semibold tabular-nums text-[var(--text-primary)]">
                        {stage.count}
                      </span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-[var(--bg-subtle)]">
                      <div
                        className={`h-full rounded-full ${barColors[idx % barColors.length]}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <div className="text-[11px] text-[var(--text-muted)]">{stage.description}</div>
                  </div>
                );
              })}
            </div>
          </Card>

          <Card title="Targeted Ports & Trap Matrix" subtitle="Click any vector row to filter the console stream.">
            {(data?.vector_matrix ?? []).length === 0 ? (
              <EmptyState title="No port activity yet" description="Waiting for incoming scans across exposed trap ports." />
            ) : (
              <div className="space-y-1.5">
                {data?.vector_matrix.slice(0, 7).map((row, idx) => (
                  <button
                    key={`${row.dest_port}-${row.trap_kind}-${idx}`}
                    type="button"
                    onClick={() => setVectorFilter(row.trap_kind)}
                    className="hp-subtle flex w-full items-center justify-between gap-2 rounded-lg border px-2.5 py-2 text-left text-xs transition hover:border-blue-500/60"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span
                        className="h-2.5 w-2.5 shrink-0 rounded-full"
                        style={{ backgroundColor: trapColor(row.trap_kind) }}
                      />
                      <span className="font-mono font-semibold text-[var(--text-primary)]">
                        :{row.dest_port || "—"}
                      </span>
                      <span className="truncate text-[var(--text-secondary)]">
                        {TRAP_META[row.trap_kind]?.label ?? row.trap_kind}
                      </span>
                    </div>
                    <div className="flex shrink-0 items-center gap-2 tabular-nums">
                      <span className="text-[11px] text-[var(--text-muted)]">{row.unique_ips} IPs</span>
                      <Badge tone={severityTone(row.max_severity)}>{row.count}</Badge>
                    </div>
                  </button>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>

      {/* Stacked Attack Velocity Timeline (Pure Inline SVG) */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-blue-500" />
            Attack Velocity Timeline ({windowMode === "60m" ? "Last 60 Minutes · 2m Buckets" : "Last 24 Hours · 1h Buckets"})
          </span>
        }
        subtitle="Stacked attack volume segmented by trap vector. Hover any bar for per-service breakdown."
        action={
          hoveredBucket ? (
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="font-semibold text-[var(--text-primary)]">{hoveredBucket.label}</span>
              <Badge tone="info">SSH {hoveredBucket.cowrie}</Badge>
              <Badge tone="danger">Web {hoveredBucket.webcve}</Badge>
              <Badge tone="warning">AI {hoveredBucket.llmproxy}</Badge>
              <Badge>Infra {hoveredBucket.infratrap}</Badge>
              <Badge tone="success">FTP {hoveredBucket.heralding}</Badge>
            </div>
          ) : (
            <span className="text-xs text-[var(--text-muted)]">Hover bars to inspect interval breakdown</span>
          )
        }
      >
        {timelineBuckets.length === 0 ? (
          <div className="py-6 text-center text-xs text-[var(--text-muted)]">Loading timeline buckets...</div>
        ) : (
          <svg
            viewBox={`0 0 ${chartW} ${chartH}`}
            className="block h-auto w-full select-none"
            role="img"
            aria-label="Stacked Attack Velocity Timeline"
          >
            {/* Horizontal grid lines */}
            {[0, 0.5, 1].map((frac) => {
              const y = padT + plotH - frac * plotH;
              const val = Math.round(maxTimelineVal * frac);
              return (
                <g key={`grid-${frac}`}>
                  <line
                    x1={padL}
                    y1={y}
                    x2={chartW - padR}
                    y2={y}
                    className="stroke-slate-200 dark:stroke-slate-800"
                    strokeDasharray="3 3"
                  />
                  <text
                    x={padL - 6}
                    y={y + 3}
                    textAnchor="end"
                    fontSize="10"
                    className="fill-slate-500 dark:fill-slate-400"
                  >
                    {val}
                  </text>
                </g>
              );
            })}

            {/* Stacked Vector Bars */}
            {timelineBuckets.map((b, idx) => {
              const stepW = plotW / Math.max(1, timelineBuckets.length);
              const barW = Math.max(6, stepW * 0.68);
              const x = padL + idx * stepW + (stepW - barW) / 2;
              const stacks: { key: string; val: number; color: string }[] = [
                { key: "cowrie", val: b.cowrie, color: trapColor("cowrie") },
                { key: "webcve", val: b.webcve, color: trapColor("webcve") },
                { key: "llmproxy", val: b.llmproxy, color: trapColor("llmproxy") },
                { key: "infratrap", val: b.infratrap, color: trapColor("infratrap") },
                { key: "heralding", val: b.heralding, color: trapColor("heralding") },
              ];
              let curY = padT + plotH;
              const showLabel = idx % 5 === 0 || idx === timelineBuckets.length - 1;
              return (
                <g
                  key={b.bucket_iso}
                  onMouseEnter={() => setHoveredBucketIdx(idx)}
                  onMouseLeave={() => setHoveredBucketIdx(null)}
                >
                  <rect
                    x={padL + idx * stepW}
                    y={padT}
                    width={stepW}
                    height={plotH}
                    fill={hoveredBucketIdx === idx ? "rgba(59,130,246,0.08)" : "transparent"}
                  />
                  {stacks.map((s) => {
                    if (s.val <= 0) return null;
                    const h = Math.max(2, (s.val / maxTimelineVal) * plotH);
                    curY -= h;
                    return (
                      <rect
                        key={s.key}
                        x={x}
                        y={curY}
                        width={barW}
                        height={h}
                        rx={1.5}
                        fill={s.color}
                      />
                    );
                  })}
                  {showLabel && (
                    <text
                      x={x + barW / 2}
                      y={chartH - 6}
                      textAnchor="middle"
                      fontSize="10"
                      className="fill-slate-500 dark:fill-slate-400"
                    >
                      {b.label}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        )}
      </Card>

      {/* Bottom Split SOC Console */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-12">
        {/* Live Streaming Event Console */}
        <Card
          className="lg:col-span-7"
          title={`Live Attack Event Console (${filteredFeed.length})`}
          subtitle="Real-time WebSocket detections merged with recent Postgres events. Inspect payloads, replay SSH sessions, or block attackers."
          action={
            <div className="relative w-52">
              <Filter className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[var(--text-muted)]" />
              <Input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter IP, CVE, path..."
                className="pl-8 py-1.5 text-xs"
              />
            </div>
          }
        >
          {filteredFeed.length === 0 ? (
            <EmptyState
              title="No matching attack events"
              description="Try clearing the search box or switching vector filters above."
            />
          ) : (
            <div className="max-h-[430px] space-y-2 overflow-y-auto pr-1">
              {filteredFeed.slice(0, 40).map((ev) => (
                <div
                  key={ev.id}
                  className="hp-subtle flex flex-wrap items-center justify-between gap-2 rounded-xl border p-2.5 text-xs"
                >
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-mono text-[11px] text-[var(--text-muted)]">
                        {formatShortTime(ev.observed_at)}
                      </span>
                      <span
                        className="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11px] font-semibold text-white"
                        style={{ backgroundColor: trapColor(ev.trap_kind) }}
                      >
                        {ev.trap_kind}
                        {ev.dest_port > 0 ? `:${ev.dest_port}` : ""}
                      </span>
                      <button
                        type="button"
                        onClick={() => setFocusedIP((cur) => (cur === ev.source_ip ? "" : ev.source_ip))}
                        className="font-mono font-semibold text-[var(--text-primary)] hover:text-blue-600 dark:hover:text-blue-400"
                      >
                        {ev.source_ip}
                      </button>
                      {ev.geo?.country_code && (
                        <span className="text-[11px] text-[var(--text-muted)]">[{ev.geo.country_code}]</span>
                      )}
                      <Badge tone={severityTone(ev.severity_score, ev.is_kev, ev.canary_hit)}>
                        Sev {ev.severity_score}
                      </Badge>
                      {ev.canary_hit && <Badge tone="danger">CANARY</Badge>}
                      {ev.is_kev && <Badge tone="danger">KEV</Badge>}
                    </div>
                    <div className="truncate font-mono text-[11px] text-[var(--text-secondary)]">
                      {[ev.cve_id, ev.http_method && ev.http_path ? `${ev.http_method} ${ev.http_path}` : ev.http_path, ev.response_summary]
                        .filter(Boolean)
                        .join(" · ") || ev.persona}
                    </div>
                  </div>

                  <div className="flex shrink-0 items-center gap-1.5">
                    <Button
                      type="button"
                      variant="secondary"
                      className="px-2 py-1 text-[11px]"
                      onClick={() => setInspectedEvent(ev)}
                    >
                      <Eye className="h-3 w-3" /> Inspect
                    </Button>
                    {ev.ssh_replay_id && (
                      <Button
                        type="button"
                        variant="secondary"
                        className="px-2 py-1 text-[11px]"
                        onClick={() => onOpenReplay(ev.ssh_replay_id!)}
                      >
                        <Terminal className="h-3 w-3 text-emerald-500" /> Replay
                      </Button>
                    )}
                    <Button
                      type="button"
                      variant="danger"
                      className="px-2 py-1 text-[11px]"
                      disabled={blockingIP === ev.source_ip}
                      onClick={() => void handleQuickBlockIP(ev.source_ip)}
                    >
                      <ShieldAlert className="h-3 w-3" /> Block
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Hostile Actors & Top Intruder Commands */}
        <Card
          className="lg:col-span-5"
          title={rightTab === "actors" ? "Top Hostile Actor Origins" : "Top Hacker SSH Commands"}
          subtitle={
            rightTab === "actors"
              ? "Click an IP to isolate its attack trajectory on the global map."
              : "Most frequent shell commands typed inside Cowrie post-compromise."
          }
          action={
            <div className="flex rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-0.5 text-xs">
              <button
                type="button"
                onClick={() => setRightTab("actors")}
                className={`rounded-md px-2 py-1 font-medium ${
                  rightTab === "actors" ? "bg-blue-600 text-white" : "text-[var(--text-secondary)]"
                }`}
              >
                Top Actors
              </button>
              <button
                type="button"
                onClick={() => setRightTab("commands")}
                className={`rounded-md px-2 py-1 font-medium ${
                  rightTab === "commands" ? "bg-blue-600 text-white" : "text-[var(--text-secondary)]"
                }`}
              >
                SSH Commands
              </button>
            </div>
          }
        >
          {rightTab === "actors" ? (
            origins.length === 0 ? (
              <EmptyState title="No attacker origins in 24h" description="Top attacker IPs will appear once probes are logged." />
            ) : (
              <div className="max-h-[430px] space-y-2 overflow-y-auto pr-1">
                {origins.slice(0, 14).map((o) => {
                  const selected = focusedIP === o.ip;
                  return (
                    <div
                      key={o.ip}
                      className={`hp-subtle flex items-center justify-between gap-2 rounded-xl border p-2.5 text-xs ${
                        selected ? "border-blue-500 ring-1 ring-blue-500/40" : ""
                      }`}
                    >
                      <button
                        type="button"
                        onClick={() => setFocusedIP((cur) => (cur === o.ip ? "" : o.ip))}
                        className="min-w-0 flex-1 text-left"
                      >
                        <div className="flex flex-wrap items-center gap-1.5">
                          <span
                            className="h-2 w-2 rounded-full"
                            style={{ backgroundColor: trapColor(o.top_trap) }}
                          />
                          <span className="font-mono font-semibold text-[var(--text-primary)]">{o.ip}</span>
                          {o.greynoise !== "unknown" && <Badge>{o.greynoise}</Badge>}
                        </div>
                        <div className="mt-0.5 truncate text-[11px] text-[var(--text-muted)]">
                          {o.geo.region_label} · {o.distinct_traps} trap(s) · port :{o.top_port || 22}
                        </div>
                      </button>
                      <div className="flex shrink-0 items-center gap-2">
                        <Badge tone={severityTone(o.max_severity)}>{o.count} hits</Badge>
                        <Button
                          type="button"
                          variant="danger"
                          className="px-2 py-1 text-[11px]"
                          disabled={blockingIP === o.ip}
                          onClick={() => void handleQuickBlockIP(o.ip)}
                        >
                          Block
                        </Button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )
          ) : (data?.top_commands ?? []).length === 0 ? (
            <EmptyState
              title="No SSH shell commands recorded yet"
              description="Once an intruder completes SSH login and executes commands, rankings appear here."
            />
          ) : (
            <div className="space-y-2.5">
              {(() => {
                const cmds = data?.top_commands ?? [];
                const topCnt = Math.max(1, ...cmds.map((c) => c.count));
                return cmds.map((c) => (
                  <div key={c.command} className="space-y-1">
                    <div className="flex items-center justify-between gap-2 text-xs">
                      <code className="truncate font-mono font-semibold text-[var(--text-primary)]">{c.command}</code>
                      <span className="shrink-0 font-mono tabular-nums text-[var(--text-muted)]">{c.count}x</span>
                    </div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-[var(--bg-subtle)]">
                      <div
                        className="h-full rounded-full bg-cyan-500"
                        style={{ width: `${Math.max(8, Math.round((c.count / topCnt) * 100))}%` }}
                      />
                    </div>
                  </div>
                ));
              })()}
            </div>
          )}
        </Card>
      </div>

      {/* Payload Inspector Modal */}
      {inspectedEvent && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/75 p-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="hp-surface w-full max-w-2xl overflow-hidden rounded-2xl border shadow-2xl">
            <div className="flex items-center justify-between gap-3 border-b border-[var(--border-subtle)] px-5 py-3.5">
              <div className="min-w-0">
                <div className="flex items-center gap-2 text-sm font-bold text-[var(--text-primary)]">
                  <span>Event Forensics Inspector</span>
                  <Badge tone={severityTone(inspectedEvent.severity_score, inspectedEvent.is_kev, inspectedEvent.canary_hit)}>
                    Sev {inspectedEvent.severity_score}
                  </Badge>
                </div>
                <div className="truncate font-mono text-xs text-[var(--text-muted)]">
                  {inspectedEvent.source_ip} → {inspectedEvent.trap_kind}:{inspectedEvent.dest_port || "?"} ({inspectedEvent.protocol}) ·{" "}
                  {inspectedEvent.geo?.region_label ?? "Unknown Region"}
                </div>
              </div>
              <Button type="button" variant="secondary" className="px-2.5 py-1 text-xs" onClick={() => setInspectedEvent(null)}>
                <X className="h-3.5 w-3.5" /> Close
              </Button>
            </div>
            <div className="max-h-[75vh] space-y-3 overflow-y-auto p-5 text-xs">
              <div className="grid grid-cols-2 gap-2 rounded-xl border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-3">
                <div>
                  <span className="text-[var(--text-muted)]">Persona / Rule:</span>{" "}
                  <span className="font-mono font-semibold text-[var(--text-primary)]">
                    {inspectedEvent.cve_id || inspectedEvent.persona || "—"}
                  </span>
                </div>
                <div>
                  <span className="text-[var(--text-muted)]">Observed:</span>{" "}
                  <span className="font-mono text-[var(--text-primary)]">{inspectedEvent.observed_at}</span>
                </div>
                {inspectedEvent.http_path && (
                  <div className="col-span-2 truncate">
                    <span className="text-[var(--text-muted)]">Request:</span>{" "}
                    <span className="font-mono text-[var(--text-primary)]">
                      {inspectedEvent.http_method} {inspectedEvent.http_path}
                    </span>
                  </div>
                )}
              </div>
              <div>
                <div className="mb-1 font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                  Deception Response Summary
                </div>
                <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-3 font-mono text-[var(--text-primary)]">
                  {inspectedEvent.response_summary || "Logged telemetry probe"}
                </div>
              </div>
              <div>
                <div className="mb-1 font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                  Captured Raw Payload
                </div>
                <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-terminal)] p-3 font-mono text-slate-100">
                  {inspectedEvent.raw_payload || "(No raw payload body — metadata/banner probe)"}
                </pre>
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2 pt-2">
                {inspectedEvent.ssh_replay_id && (
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => {
                      const rid = inspectedEvent.ssh_replay_id!;
                      setInspectedEvent(null);
                      onOpenReplay(rid);
                    }}
                  >
                    <Terminal className="h-3.5 w-3.5" /> Open Terminal Replay
                  </Button>
                )}
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    const tk = inspectedEvent.trap_kind;
                    setInspectedEvent(null);
                    onOpenTrapLogs(tk);
                  }}
                >
                  Open in {inspectedEvent.trap_kind} Logs
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
