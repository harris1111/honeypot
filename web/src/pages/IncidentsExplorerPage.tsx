import { Fragment, useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Play, Search, Terminal, X } from "lucide-react";
import { create as createAsciinema } from "asciinema-player";
import "asciinema-player/dist/bundle/asciinema-player.css";
import { apiFetch } from "../lib/api";
import { Badge, Button, Card, EmptyState, Input } from "../components/ui/primitives";

interface IncidentRow {
  id: string;
  correlation_key: string;
  title: string;
  severity: string;
  confidence_score: number;
  primary_ip: string;
  related_ips: string[];
  trap_kinds: string[];
  cve_ids: string[];
  country_code: string;
  greynoise_classification: string;
  abuseipdb_score: number;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
}

interface TelemetryEventRow {
  id: string;
  source_ip: string;
  dest_port?: number;
  protocol?: string;
  trap_kind: string;
  persona: string;
  cve_id: string;
  is_kev: boolean;
  ja4: string;
  hassh?: string;
  http_method: string;
  http_path: string;
  raw_payload?: string;
  response_summary: string;
  greynoise?: string;
  severity_score: number;
  observed_at: string;
}

interface ReplaySummary {
  id: string;
  source_ip: string;
  username: string;
  hassh: string;
  auth_succeeded?: boolean;
  commands?: string[];
  duration_ms: number;
  started_at: string;
}

interface ReplayDetail extends ReplaySummary {
  asciicast_v2: string;
}

const TRAP_FILTERS = [
  { value: "all", label: "All Traps" },
  { value: "cowrie", label: "SSH / Telnet (cowrie)" },
  { value: "heralding", label: "FTP / Mail (heralding)" },
  { value: "webcve", label: "Web CVEs (webcve)" },
  { value: "infratrap", label: "DB / Docker / K8s (infratrap)" },
  { value: "llmproxy", label: "AI / LLM (llmproxy)" },
];

function severityTone(scoreOrLabel: number | string) {
  if (typeof scoreOrLabel === "number") {
    if (scoreOrLabel >= 80) return "danger" as const;
    if (scoreOrLabel >= 50) return "warning" as const;
    return "info" as const;
  }
  const s = scoreOrLabel.toLowerCase();
  if (s === "critical" || s === "high") return "danger" as const;
  if (s === "medium") return "warning" as const;
  return "info" as const;
}

function AsciicastViewer({ cast }: { cast: string }) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const [fallbackText, setFallbackText] = useState(false);

  useEffect(() => {
    const el = hostRef.current;
    if (!el || !cast) return;
    el.innerHTML = "";
    let player: { dispose?: () => void } | undefined;
    try {
      player = createAsciinema({ data: cast }, el, {
        fit: "width",
        autoPlay: true,
        idleTimeLimit: 2,
      });
      setFallbackText(false);
    } catch {
      setFallbackText(true);
    }
    return () => {
      try {
        player?.dispose?.();
      } catch {
        // Ignore cleanup errors.
      }
    };
  }, [cast]);

  if (!cast) {
    return (
      <div className="rounded-lg border border-slate-700 bg-[var(--bg-terminal)] p-4 text-xs text-slate-300">
        No asciicast TTY frames recorded for this session (see captured command list above).
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <div ref={hostRef} className="overflow-hidden rounded-lg border border-slate-800 bg-[var(--bg-terminal)]" />
      {fallbackText && (
        <pre className="max-h-64 overflow-auto rounded-lg border border-slate-700 bg-[var(--bg-terminal)] p-3 font-mono text-xs text-slate-100">
          {cast}
        </pre>
      )}
    </div>
  );
}

export function IncidentsExplorerPage({ initialReplayId = "" }: { initialReplayId?: string }) {
  const [trapFilter, setTrapFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [events, setEvents] = useState<TelemetryEventRow[]>([]);
  const [replays, setReplays] = useState<ReplaySummary[]>([]);
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [activeReplay, setActiveReplay] = useState<ReplayDetail | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentTimeline, setIncidentTimeline] = useState<TelemetryEventRow[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    Promise.all([
      apiFetch<{ incidents: IncidentRow[] }>("/api/admin/incidents"),
      apiFetch<{ events: TelemetryEventRow[]; replays: ReplaySummary[] }>(
        `/api/admin/telemetry${trapFilter !== "all" ? `?trap=${encodeURIComponent(trapFilter)}` : ""}`
      ),
    ])
      .then(([incRes, telRes]) => {
        setIncidents(incRes.incidents ?? []);
        setEvents(telRes.events ?? []);
        setReplays(telRes.replays ?? []);
      })
      .catch((e) => setErr(e instanceof Error ? e.message : "Failed to load telemetry"));
  }, [trapFilter]);

  const loadReplay = async (id: string) => {
    try {
      const detail = await apiFetch<ReplayDetail>(`/api/admin/replays/${encodeURIComponent(id)}`);
      setActiveReplay(detail);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load SSH replay");
    }
  };

  useEffect(() => {
    if (initialReplayId) {
      void loadReplay(initialReplayId);
    }
  }, [initialReplayId]);

  const loadIncidentTimeline = async (id: string) => {
    if (selectedIncidentId === id) {
      setSelectedIncidentId(null);
      setIncidentTimeline([]);
      return;
    }
    try {
      const res = await apiFetch<{ events: TelemetryEventRow[] }>(`/api/admin/incidents/${encodeURIComponent(id)}`);
      setSelectedIncidentId(id);
      setIncidentTimeline(res.events ?? []);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load incident timeline");
    }
  };

  const q = searchQuery.trim().toLowerCase();

  const filteredEvents = useMemo(() => {
    if (!q) return events;
    return events.filter((ev) =>
      [
        ev.source_ip,
        ev.trap_kind,
        ev.persona,
        ev.cve_id,
        ev.http_method,
        ev.http_path,
        ev.raw_payload ?? "",
        ev.response_summary,
        ev.hassh ?? "",
      ]
        .join(" ")
        .toLowerCase()
        .includes(q)
    );
  }, [events, q]);

  const filteredReplays = useMemo(() => {
    if (!q) return replays;
    return replays.filter((r) =>
      [r.source_ip, r.username, r.hassh, ...(r.commands ?? [])].join(" ").toLowerCase().includes(q)
    );
  }, [replays, q]);

  return (
    <div className="space-y-6">
      {err && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200">
          {err}
        </div>
      )}

      {/* Search & Trap Kind Filter Bar */}
      <Card>
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex flex-wrap gap-1.5">
            {TRAP_FILTERS.map((tf) => {
              const active = trapFilter === tf.value;
              return (
                <button
                  key={tf.value}
                  type="button"
                  onClick={() => setTrapFilter(tf.value)}
                  className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                    active
                      ? "border-blue-600 bg-blue-600 text-white"
                      : "border-[var(--border-subtle)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  {tf.label}
                </button>
              );
            })}
          </div>
          <div className="relative w-full lg:w-80">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[var(--text-muted)]" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search IP, command, path, CVE, payload..."
              className="pl-9"
            />
          </div>
        </div>
      </Card>

      {/* Active Terminal Replay Modal/Panel */}
      {activeReplay && (
        <Card
          title={
            <span className="flex items-center gap-2">
              <Terminal className="h-4 w-4 text-emerald-500" />
              SSH Terminal Replay — {activeReplay.source_ip} ({activeReplay.username || "root"})
            </span>
          }
          subtitle={`HASSH: ${activeReplay.hassh || "n/a"} · Duration: ${(activeReplay.duration_ms / 1000).toFixed(1)}s · Started: ${activeReplay.started_at}`}
          action={
            <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => setActiveReplay(null)}>
              <X className="h-4 w-4" /> Close
            </Button>
          }
        >
          <div className="space-y-4">
            <div>
              <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                Executed Commands ({activeReplay.commands?.length ?? 0})
              </div>
              {activeReplay.commands && activeReplay.commands.length > 0 ? (
                <div className="max-h-40 space-y-1 overflow-y-auto rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-3 font-mono text-xs text-[var(--text-primary)]">
                  {activeReplay.commands.map((cmd, idx) => (
                    <div key={idx} className="break-all">
                      <span className="select-none text-emerald-600 dark:text-emerald-400">$ </span>
                      <span>{cmd}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-xs text-[var(--text-muted)]">No shell commands recorded in this session.</div>
              )}
            </div>
            <AsciicastViewer cast={activeReplay.asciicast_v2} />
          </div>
        </Card>
      )}

      {/* SSH / Telnet Sessions & Commands */}
      <Card
        title="SSH / Telnet Intruder Sessions & Commands"
        subtitle="See who successfully logged in, what shell commands they ran, and replay their full TTY terminal."
      >
        {filteredReplays.length === 0 ? (
          <EmptyState
            title="No matching SSH sessions"
            description="Successful and interactive Cowrie SSH/Telnet sessions appear here with commands and terminal playback."
          />
        ) : (
          <div className="space-y-3">
            {filteredReplays.map((r) => (
              <div
                key={r.id}
                className="hp-subtle flex flex-col justify-between gap-3 rounded-xl border p-4 sm:flex-row sm:items-center"
              >
                <div className="min-w-0 space-y-1.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-[var(--text-primary)]">{r.source_ip}</span>
                    <Badge tone="info">user: {r.username || "root"}</Badge>
                    <Badge tone={r.auth_succeeded ? "success" : "warning"}>
                      {r.auth_succeeded ? "Auth Succeeded" : "Login Attempt"}
                    </Badge>
                    <span className="text-xs tabular-nums text-[var(--text-muted)]">
                      {(r.duration_ms / 1000).toFixed(1)}s · {r.started_at}
                    </span>
                  </div>
                  {r.commands && r.commands.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {r.commands.map((cmd, idx) => (
                        <code
                          key={idx}
                          className="max-w-full truncate rounded border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-2 py-0.5 font-mono text-xs text-[var(--text-primary)]"
                        >
                          $ {cmd}
                        </code>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs text-[var(--text-muted)]">Session opened without typed commands.</div>
                  )}
                </div>
                <Button variant="primary" className="shrink-0 text-xs" onClick={() => void loadReplay(r.id)}>
                  <Play className="h-3.5 w-3.5" />
                  Replay
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Raw Event Stream */}
      <Card
        title={`Captured Telemetry Events (${filteredEvents.length})`}
        subtitle="Click Inspect on any row to read the full raw request, SSH input, or response summary (all HTML/script payloads rendered safely as plain text)."
      >
        {filteredEvents.length === 0 ? (
          <EmptyState
            title="No telemetry events match your filter"
            description="Try selecting All Traps or clearing the search box."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                  <th className="py-2.5 pr-3">Time</th>
                  <th className="py-2.5 pr-3">Source IP</th>
                  <th className="py-2.5 pr-3">Trap / Port</th>
                  <th className="py-2.5 pr-3">Request / Input</th>
                  <th className="py-2.5 pr-3">Severity</th>
                  <th className="py-2.5 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {filteredEvents.map((ev) => {
                  const isOpen = expandedEventId === ev.id;
                  const targetDisplay = ev.dest_port
                    ? `${ev.protocol || "tcp"}:${ev.dest_port}`
                    : ev.persona || ev.trap_kind;
                  const inputText =
                    ev.http_path || ev.raw_payload || ev.response_summary || ev.cve_id || "connection probe";
                  return (
                    <Fragment key={ev.id}>
                      <tr className="align-top hover:bg-[var(--bg-subtle)]/60">
                        <td className="whitespace-nowrap py-3 pr-3 font-mono text-xs text-[var(--text-muted)]">
                          {ev.observed_at}
                        </td>
                        <td className="whitespace-nowrap py-3 pr-3 font-mono font-medium text-[var(--text-primary)]">
                          {ev.source_ip}
                        </td>
                        <td className="whitespace-nowrap py-3 pr-3">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <Badge>{ev.trap_kind}</Badge>
                            <span className="font-mono text-xs text-[var(--text-muted)]">{targetDisplay}</span>
                          </div>
                        </td>
                        <td className="max-w-md py-3 pr-3">
                          <div className="flex flex-wrap items-center gap-1.5">
                            {ev.http_method && (
                              <span className="font-mono text-xs font-semibold text-blue-600 dark:text-blue-400">
                                {ev.http_method}
                              </span>
                            )}
                            <code className="break-all font-mono text-xs text-[var(--text-primary)]">{inputText}</code>
                            {ev.cve_id && <Badge tone="danger">{ev.cve_id}</Badge>}
                          </div>
                        </td>
                        <td className="whitespace-nowrap py-3 pr-3">
                          <Badge tone={severityTone(ev.severity_score)}>{ev.severity_score}</Badge>
                        </td>
                        <td className="whitespace-nowrap py-3 text-right">
                          <Button
                            type="button"
                            variant="ghost"
                            className="px-2 py-1 text-xs"
                            onClick={() => setExpandedEventId(isOpen ? null : ev.id)}
                          >
                            {isOpen ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
                            Inspect
                          </Button>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr key={`${ev.id}-detail`} className="bg-[var(--bg-subtle)]/80">
                          <td colSpan={6} className="p-4">
                            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                              <div>
                                <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                                  Raw Payload / Attacker Input
                                </div>
                                <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-3 font-mono text-xs text-[var(--text-primary)]">
                                  {ev.raw_payload || ev.http_path || "(empty payload)"}
                                </pre>
                              </div>
                              <div className="space-y-2 text-xs">
                                <div className="font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                                  Sensor Response &amp; Fingerprints
                                </div>
                                <div className="rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-3 space-y-1.5">
                                  <div>
                                    <span className="font-semibold text-[var(--text-secondary)]">Response: </span>
                                    <span className="text-[var(--text-primary)]">{ev.response_summary || "—"}</span>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-[var(--text-secondary)]">HASSH: </span>
                                    <code className="font-mono text-[var(--text-primary)]">{ev.hassh || "—"}</code>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-[var(--text-secondary)]">JA4: </span>
                                    <code className="font-mono text-[var(--text-primary)]">{ev.ja4 || "—"}</code>
                                  </div>
                                  <div>
                                    <span className="font-semibold text-[var(--text-secondary)]">Persona / CVE: </span>
                                    <span className="text-[var(--text-primary)]">
                                      {ev.persona || "—"} {ev.cve_id ? `(${ev.cve_id})` : ""}
                                    </span>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Correlated Incidents */}
      <Card
        title={`Correlated Attack Incidents (${incidents.length})`}
        subtitle="Multi-step campaigns grouped automatically by source IP and indicators."
      >
        {incidents.length === 0 ? (
          <EmptyState
            title="No correlated incidents yet"
            description="Repeated probes, exploit attempts, or multi-port scans from the same actor correlate into incidents here."
          />
        ) : (
          <div className="space-y-2.5">
            {incidents.map((inc) => (
              <div key={inc.id} className="hp-subtle rounded-xl border p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={severityTone(inc.severity)}>{inc.severity}</Badge>
                    <span className="font-semibold text-[var(--text-primary)]">{inc.title}</span>
                    <span className="font-mono text-xs text-[var(--text-secondary)]">{inc.primary_ip}</span>
                    <span className="text-xs text-[var(--text-muted)]">Confidence {inc.confidence_score}%</span>
                  </div>
                  <Button variant="secondary" className="text-xs" onClick={() => void loadIncidentTimeline(inc.id)}>
                    {selectedIncidentId === inc.id ? "Hide Timeline" : "View Timeline"}
                  </Button>
                </div>
                {selectedIncidentId === inc.id && (
                  <div className="mt-3 space-y-1.5 border-t border-[var(--border-subtle)] pt-3">
                    {incidentTimeline.length === 0 ? (
                      <div className="text-xs text-[var(--text-muted)]">No correlated child events found.</div>
                    ) : (
                      incidentTimeline.map((tev) => (
                        <div key={tev.id} className="flex flex-wrap items-center justify-between gap-2 text-xs">
                          <div className="flex items-center gap-2">
                            <Badge>{tev.trap_kind}</Badge>
                            <code className="font-mono text-[var(--text-primary)]">
                              {tev.http_path || tev.raw_payload || tev.response_summary}
                            </code>
                          </div>
                          <span className="text-[var(--text-muted)]">{tev.observed_at}</span>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}
