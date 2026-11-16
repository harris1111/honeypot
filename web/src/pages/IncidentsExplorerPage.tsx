import { Fragment, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Play, Search } from "lucide-react";
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

const SERVICE_TABS = [
  { value: "all", label: "All Activity" },
  { value: "non_ssh", label: "Non-SSH Only (Web / AI / DB / FTP)" },
  { value: "cowrie", label: "SSH & Telnet (:22, :23)" },
  { value: "llmproxy", label: "Ollama & AI (:11434, :4000)" },
  { value: "webcve", label: "Web & CVEs (:80, :443)" },
  { value: "infratrap", label: "DB / Docker / K8s" },
  { value: "heralding", label: "FTP & Mail (:21, :25, :110, :143)" },
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

export function IncidentsExplorerPage({
  initialTrapFilter = "all",
  trapFilterNonce = 0,
  onOpenReplay,
}: {
  initialTrapFilter?: string;
  trapFilterNonce?: number;
  onOpenReplay: (replayId: string) => void;
}) {
  const [trapFilter, setTrapFilter] = useState(initialTrapFilter || "all");
  const [searchQuery, setSearchQuery] = useState("");
  const [incidents, setIncidents] = useState<IncidentRow[]>([]);
  const [events, setEvents] = useState<TelemetryEventRow[]>([]);
  const [replays, setReplays] = useState<ReplaySummary[]>([]);
  const [countsByTrap, setCountsByTrap] = useState<Record<string, number>>({});
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [incidentTimeline, setIncidentTimeline] = useState<TelemetryEventRow[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (trapFilterNonce > 0) {
      setTrapFilter(initialTrapFilter || "all");
    }
  }, [initialTrapFilter, trapFilterNonce]);

  useEffect(() => {
    Promise.all([
      apiFetch<{ incidents: IncidentRow[] }>("/api/admin/incidents"),
      apiFetch<{
        events: TelemetryEventRow[];
        replays: ReplaySummary[];
        counts_by_trap?: Record<string, number>;
      }>(`/api/admin/telemetry${trapFilter !== "all" ? `?trap=${encodeURIComponent(trapFilter)}` : ""}`),
    ])
      .then(([incRes, telRes]) => {
        setIncidents(incRes.incidents ?? []);
        setEvents(telRes.events ?? []);
        setReplays(telRes.replays ?? []);
        setCountsByTrap(telRes.counts_by_trap ?? {});
      })
      .catch((e) => setErr(e instanceof Error ? e.message : "Failed to load telemetry"));
  }, [trapFilter]);

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
        String(ev.dest_port ?? ""),
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

  const getTabCount = (val: string): number | null => {
    const entries = Object.entries(countsByTrap);
    if (entries.length === 0) return null;
    if (val === "all") return entries.reduce((sum, [, c]) => sum + c, 0);
    if (val === "non_ssh") return entries.filter(([k]) => k !== "cowrie").reduce((sum, [, c]) => sum + c, 0);
    return countsByTrap[val] ?? 0;
  };

  const showSSHSessions = trapFilter === "all" || trapFilter === "cowrie";
  const prioritizeEventsTop = trapFilter !== "all" && trapFilter !== "cowrie";

  const eventsSection = (
    <Card
      title={`Captured Telemetry Events (${filteredEvents.length})`}
      subtitle="Click Inspect on any row to read the full raw request, SSH input, or response summary (all HTML/script payloads rendered safely as plain text)."
    >
      {filteredEvents.length === 0 ? (
        <EmptyState
          title="No telemetry events match this service tab"
          description="Try switching between Service Tabs above (or run a probe against :80, :11434, :4000, :22, or :6379 to verify live capture)."
        />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b border-[var(--border-subtle)] text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                <th className="py-2.5 pr-3">Time</th>
                <th className="py-2.5 pr-3">Source IP</th>
                <th className="py-2.5 pr-3">Service / Port</th>
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
                      <tr className="bg-[var(--bg-subtle)]/80">
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
                              <div className="space-y-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-3">
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
  );

  const sshSessionsSection = showSSHSessions ? (
    <Card
      title="SSH / Telnet Intruder Sessions & Commands"
      subtitle="Ordered with active command sessions first. Click Replay to watch the terminal playback."
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
              <Button variant="primary" className="shrink-0 text-xs" onClick={() => onOpenReplay(r.id)}>
                <Play className="h-3.5 w-3.5" />
                Replay
              </Button>
            </div>
          ))}
        </div>
      )}
    </Card>
  ) : null;

  return (
    <div className="space-y-6">
      {err && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200">
          {err}
        </div>
      )}

      {/* Service Log Tabs & Search Bar */}
      <Card>
        <div className="flex flex-col gap-3">
          <div className="flex flex-wrap gap-2">
            {SERVICE_TABS.map((tf) => {
              const active = trapFilter === tf.value;
              const cnt = getTabCount(tf.value);
              return (
                <button
                  key={tf.value}
                  type="button"
                  onClick={() => setTrapFilter(tf.value)}
                  className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                    active
                      ? "border-blue-600 bg-blue-600 text-white shadow-xs"
                      : "border-[var(--border-subtle)] bg-[var(--bg-subtle)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                >
                  <span>{tf.label}</span>
                  {cnt !== null && (
                    <span
                      className={`rounded px-1.5 py-0.2 text-[11px] tabular-nums ${
                        active ? "bg-white/20 text-white" : "bg-[var(--bg-surface)] text-[var(--text-muted)]"
                      }`}
                    >
                      {cnt}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
          <div className="relative w-full lg:w-96">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-[var(--text-muted)]" />
            <Input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search IP, port, command, path, CVE, payload..."
              className="pl-9"
            />
          </div>
        </div>
      </Card>

      {prioritizeEventsTop ? (
        <>
          {eventsSection}
          {sshSessionsSection}
        </>
      ) : (
        <>
          {sshSessionsSection}
          {eventsSection}
        </>
      )}

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
