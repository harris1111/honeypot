import { useEffect, useState } from "react";
import { Bot, Database, Globe, Mail, Play, Radar, Terminal } from "lucide-react";
import { apiFetch, type LiveEventTick } from "../lib/api";
import { Badge, Button, Card, EmptyState, StatCard } from "../components/ui/primitives";
import type { NavTab } from "../App";

interface RecentSSHSession {
  id: string;
  source_ip: string;
  username: string;
  auth_succeeded: boolean;
  commands: string[];
  duration_ms: number;
  started_at: string;
}

interface RecentServiceEvent {
  id: string;
  source_ip: string;
  dest_port: number;
  protocol: string;
  trap_kind: string;
  persona: string;
  cve_id: string;
  http_method: string;
  http_path: string;
  response_summary: string;
  severity_score: number;
  observed_at: string;
}

interface OverviewData {
  events_24h: number;
  ssh_sessions_24h?: number;
  open_incidents: number;
  pending_triage: number;
  malware_count: number;
  canary_hits: number;
  llm_spent_usd: number;
  top_cves: { cve_id: string; count: number }[];
  events_by_trap?: { trap_kind: string; count: number }[];
  top_ips?: { ip: string; count: number; country_code: string }[];
  recent_ssh_sessions?: RecentSSHSession[];
  recent_service_events?: RecentServiceEvent[];
}

const TRAP_LABELS: Record<string, string> = {
  cowrie: "SSH & Telnet (cowrie)",
  heralding: "FTP & Mail (heralding)",
  webcve: "Web Exploits (webcve)",
  infratrap: "DB / Docker / K8s (infratrap)",
  llmproxy: "AI / LLM Proxy (llmproxy)",
};

const ACTIVE_SERVICES = [
  {
    trap: "cowrie",
    label: "SSH / Telnet",
    ports: ":22, :23",
    icon: Terminal,
  },
  {
    trap: "llmproxy",
    label: "Ollama & LiteLLM AI",
    ports: ":11434, :4000",
    icon: Bot,
  },
  {
    trap: "webcve",
    label: "Web & CVE Packs",
    ports: ":80, :443",
    icon: Globe,
  },
  {
    trap: "infratrap",
    label: "Docker / K8s / DB",
    ports: ":2375, :3306, :5432, :6379, :6443, :10250",
    icon: Database,
  },
  {
    trap: "heralding",
    label: "FTP & Mail",
    ports: ":21, :25, :110, :143",
    icon: Mail,
  },
];

export function OverviewPage({
  liveEvents,
  onNavigate,
  onOpenReplay,
  onOpenTrapLogs,
}: {
  liveEvents: LiveEventTick[];
  onNavigate: (tab: NavTab) => void;
  onOpenReplay: (replayId: string) => void;
  onOpenTrapLogs: (trapKind: string) => void;
}) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiFetch<OverviewData>("/api/admin/overview")
      .then(setData)
      .catch((e) => setErr(e instanceof Error ? e.message : "Failed to load overview"));
  }, [liveEvents.length]);

  const byTrap = data?.events_by_trap ?? [];
  const trapCountMap = new Map(byTrap.map((row) => [row.trap_kind, row.count]));
  const maxTrapCount = Math.max(1, ...byTrap.map((t) => t.count));
  const topCVEs = data?.top_cves ?? [];
  const topIPs = data?.top_ips ?? [];
  const recentSSH = data?.recent_ssh_sessions ?? [];
  const recentServiceEvents = data?.recent_service_events ?? [];

  return (
    <div className="space-y-6">
      {err && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200">
          {err}
        </div>
      )}

      {/* SOC Live Radar Quick Banner */}
      <div className="hp-surface flex flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3">
        <div className="flex items-center gap-3 text-xs sm:text-sm">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-blue-600/15 text-blue-600 dark:text-blue-400">
            <Radar className="h-4 w-4" />
          </div>
          <div>
            <div className="font-semibold text-[var(--text-primary)]">Blue-Team Live Threat Radar</div>
            <div className="text-xs text-[var(--text-muted)]">
              Xem bản đồ tấn công toàn cầu theo thời gian thực, kill-chain funnel, biểu đồ lưu lượng và chặn IP 1-click.
            </div>
          </div>
        </div>
        <Button type="button" onClick={() => onNavigate("Live Threat Radar")} className="px-3 py-1.5 text-xs">
          <Radar className="h-3.5 w-3.5" /> Open Live Threat Radar →
        </Button>
      </div>

      {/* Active Trap Services Quick Filter Bar */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        {ACTIVE_SERVICES.map((svc) => {
          const Icon = svc.icon;
          const cnt = trapCountMap.get(svc.trap) ?? 0;
          return (
            <button
              key={svc.trap}
              type="button"
              onClick={() => onOpenTrapLogs(svc.trap)}
              className="hp-surface flex items-start justify-between gap-2 rounded-xl border p-3.5 text-left transition hover:border-blue-500/60"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-[var(--text-primary)]">
                  <Icon className="h-3.5 w-3.5 shrink-0 text-blue-600 dark:text-blue-400" />
                  <span className="truncate">{svc.label}</span>
                </div>
                <div className="mt-1 truncate font-mono text-[11px] text-[var(--text-muted)]">{svc.ports}</div>
              </div>
              <Badge tone={cnt > 0 ? "info" : "default"}>{cnt}</Badge>
            </button>
          );
        })}
      </div>

      {/* KPI Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="Events (24h)"
          value={data?.events_24h ?? "—"}
          hint="All SSH, HTTP & infra hits"
          tone="blue"
          onClick={() => onOpenTrapLogs("all")}
        />
        <StatCard
          label="SSH Sessions (24h)"
          value={data?.ssh_sessions_24h ?? recentSSH.length}
          hint="Cowrie logins & shell captures"
          tone="emerald"
          onClick={() => onOpenTrapLogs("cowrie")}
        />
        <StatCard
          label="Open Incidents"
          value={data?.open_incidents ?? "—"}
          hint="Correlated campaigns"
          tone="amber"
          onClick={() => onOpenTrapLogs("all")}
        />
        <StatCard
          label="Pending Triage"
          value={data?.pending_triage ?? "—"}
          hint="Awaiting Guard review"
          tone="red"
          onClick={() => onNavigate("Active Guard")}
        />
        <StatCard
          label="Canary Key Hits"
          value={data?.canary_hits ?? "—"}
          hint="Stolen honeypot keys used"
          tone="amber"
          onClick={() => onNavigate("Canary Factory")}
        />
        <StatCard
          label="Malware Samples"
          value={data?.malware_count ?? "—"}
          hint={`LLM spend: $${(data?.llm_spent_usd ?? 0).toFixed(2)}`}
          tone="default"
          onClick={() => onNavigate("Malware Vault")}
        />
      </div>

      {/* Recent Non-SSH Service Hits (Ollama AI, Web CVE, DB/Docker/K8s, FTP) */}
      <Card
        title="Recent Web CVE, Ollama AI, DB/Docker & FTP Hits"
        subtitle="Filtered view of non-SSH attacks so Ollama (:11434/:4000), Web CVEs (:80/:443), Docker/K8s/DB & FTP activity are never buried under SSH brute-force."
        action={
          <Button variant="secondary" className="text-xs" onClick={() => onOpenTrapLogs("non_ssh")}>
            View Non-SSH Logs
          </Button>
        }
      >
        {recentServiceEvents.length === 0 ? (
          <EmptyState
            title="No Web CVE, Ollama, DB, or FTP hits recorded yet"
            description="Hits against HTTP CVE packs (:80/:443), Ollama/LiteLLM (:11434/:4000), Docker/DB/K8s traps, or Heralding FTP/Mail appear right here."
          />
        ) : (
          <div className="divide-y divide-[var(--border-subtle)]">
            {recentServiceEvents.map((ev) => (
              <div
                key={ev.id}
                className="flex flex-col justify-between gap-2 py-3 text-sm first:pt-0 last:pb-0 sm:flex-row sm:items-center"
              >
                <div className="min-w-0 space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge tone={ev.severity_score >= 80 ? "danger" : ev.severity_score >= 50 ? "warning" : "info"}>
                      {ev.trap_kind}
                    </Badge>
                    <span className="font-mono text-xs font-semibold text-[var(--text-primary)]">
                      {ev.source_ip} → {ev.protocol || "tcp"}:{ev.dest_port || "?"}
                    </span>
                    {ev.cve_id && <Badge tone="danger">{ev.cve_id}</Badge>}
                    {ev.persona && <span className="font-mono text-xs text-[var(--text-muted)]">{ev.persona}</span>}
                  </div>
                  <div className="truncate font-mono text-xs text-[var(--text-secondary)]">
                    {ev.http_method ? `${ev.http_method} ${ev.http_path}` : ev.response_summary || ev.http_path}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <span className="font-mono text-xs text-[var(--text-muted)]">{ev.observed_at}</span>
                  <Button
                    type="button"
                    variant="ghost"
                    className="px-2 py-1 text-xs"
                    onClick={() => onOpenTrapLogs(ev.trap_kind)}
                  >
                    Logs →
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Recent SSH Sessions & Commands */}
      <Card
        title="Recent SSH / Telnet Attacker Sessions & Commands"
        subtitle="Successful Cowrie logins and the exact shell commands executed by intruders."
        action={
          <Button variant="secondary" className="text-xs" onClick={() => onOpenTrapLogs("cowrie")}>
            <Terminal className="h-3.5 w-3.5" />
            All SSH Sessions
          </Button>
        }
      >
        {recentSSH.length === 0 ? (
          <EmptyState
            title="No SSH sessions recorded yet"
            description="When attackers brute-force Cowrie (:22 or :23) and run Linux commands, every login and typed command appears here with 1-click terminal replay."
          />
        ) : (
          <div className="space-y-3">
            {recentSSH.map((sess) => (
              <div
                key={sess.id}
                className="hp-subtle flex flex-col justify-between gap-3 rounded-xl border p-4 sm:flex-row sm:items-center"
              >
                <div className="min-w-0 space-y-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-semibold text-[var(--text-primary)]">{sess.source_ip}</span>
                    <Badge tone="info">user: {sess.username || "root"}</Badge>
                    <Badge tone={sess.auth_succeeded ? "success" : "warning"}>
                      {sess.auth_succeeded ? "Logged In" : "Auth Attempt"}
                    </Badge>
                    <span className="text-xs tabular-nums text-[var(--text-muted)]">
                      {(sess.duration_ms / 1000).toFixed(1)}s · {sess.started_at}
                    </span>
                  </div>
                  {sess.commands.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {sess.commands.slice(0, 8).map((cmd, idx) => (
                        <code
                          key={idx}
                          className="max-w-full truncate rounded-md border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-2 py-0.5 font-mono text-xs text-[var(--text-primary)]"
                        >
                          $ {cmd}
                        </code>
                      ))}
                      {sess.commands.length > 8 && (
                        <span className="self-center text-xs text-[var(--text-muted)]">
                          +{sess.commands.length - 8} more
                        </span>
                      )}
                    </div>
                  ) : (
                    <div className="text-xs text-[var(--text-muted)]">Interactive login without typed commands.</div>
                  )}
                </div>
                <Button variant="primary" className="shrink-0 text-xs" onClick={() => onOpenReplay(sess.id)}>
                  <Play className="h-3.5 w-3.5" />
                  Watch Replay
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Attack Mix + Top IPs + Top CVEs */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card title="Attack Activity by Trap (24h)" subtitle="Click any service at top to view dedicated logs">
          {byTrap.length === 0 ? (
            <EmptyState
              title="No trap events in last 24h"
              description="Deploy Cowrie, Heralding, or L7 sensors under Nodes & Traps to start capturing traffic."
            />
          ) : (
            <div className="space-y-3">
              {byTrap.map((row) => (
                <div key={row.trap_kind} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <span className="font-medium text-[var(--text-primary)]">
                      {TRAP_LABELS[row.trap_kind] ?? row.trap_kind}
                    </span>
                    <span className="tabular-nums font-semibold text-[var(--text-secondary)]">{row.count}</span>
                  </div>
                  <div className="h-2.5 w-full overflow-hidden rounded-full bg-[var(--bg-subtle)]">
                    <div
                      className="h-full rounded-full bg-blue-600 dark:bg-blue-500"
                      style={{ width: `${Math.max(6, Math.round((row.count / maxTrapCount) * 100))}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Top Attacker IPs (24h)" subtitle="Highest-volume source addresses targeting your sensors">
          {topIPs.length === 0 ? (
            <EmptyState title="No source IPs recorded yet" description="Source IPs appear automatically as probes arrive." />
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {topIPs.map((row) => (
                <div key={row.ip} className="flex items-center justify-between py-2.5 text-sm first:pt-0 last:pb-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-medium text-[var(--text-primary)]">{row.ip}</span>
                    {row.country_code && <Badge>{row.country_code}</Badge>}
                  </div>
                  <span className="font-semibold tabular-nums text-[var(--text-secondary)]">{row.count} hits</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card title="Top Targeted CVEs (24h)" subtitle="Matched HTTP/app exploit signatures from CVE packs">
          {topCVEs.length === 0 ? (
            <EmptyState
              title="No CVE signatures matched in 24h"
              description="Current traffic was primarily SSH/Telnet or port probing. Enable or test HTTP CVE traps on port 80/443 under Nodes & Traps."
            />
          ) : (
            <div className="divide-y divide-[var(--border-subtle)]">
              {topCVEs.map((row) => (
                <div key={row.cve_id} className="flex items-center justify-between py-2.5 text-sm first:pt-0 last:pb-0">
                  <span className="font-mono font-medium text-[var(--text-primary)]">{row.cve_id}</span>
                  <Badge tone="danger">{row.count} attempts</Badge>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
