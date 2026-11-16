import { useEffect, useState } from "react";
import { Play, Terminal } from "lucide-react";
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
}

const TRAP_LABELS: Record<string, string> = {
  cowrie: "SSH & Telnet (cowrie)",
  heralding: "FTP & Mail (heralding)",
  webcve: "Web Exploits (webcve)",
  infratrap: "DB / Docker / K8s (infratrap)",
  llmproxy: "AI / LLM Proxy (llmproxy)",
};

export function OverviewPage({
  liveEvents,
  onNavigate,
  onOpenReplay,
}: {
  liveEvents: LiveEventTick[];
  onNavigate: (tab: NavTab) => void;
  onOpenReplay: (replayId: string) => void;
}) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiFetch<OverviewData>("/api/admin/overview")
      .then(setData)
      .catch((e) => setErr(e instanceof Error ? e.message : "Failed to load overview"));
  }, [liveEvents.length]);

  const byTrap = data?.events_by_trap ?? [];
  const maxTrapCount = Math.max(1, ...byTrap.map((t) => t.count));
  const topCVEs = data?.top_cves ?? [];
  const topIPs = data?.top_ips ?? [];
  const recentSSH = data?.recent_ssh_sessions ?? [];

  return (
    <div className="space-y-6">
      {err && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200">
          {err}
        </div>
      )}

      {/* KPI Row */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <StatCard
          label="Events (24h)"
          value={data?.events_24h ?? "—"}
          hint="All SSH, HTTP & infra hits"
          tone="blue"
          onClick={() => onNavigate("Incidents & Replays")}
        />
        <StatCard
          label="SSH Sessions (24h)"
          value={data?.ssh_sessions_24h ?? recentSSH.length}
          hint="Cowrie logins & shell captures"
          tone="emerald"
          onClick={() => onNavigate("Incidents & Replays")}
        />
        <StatCard
          label="Open Incidents"
          value={data?.open_incidents ?? "—"}
          hint="Correlated campaigns"
          tone="amber"
          onClick={() => onNavigate("Incidents & Replays")}
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

      {/* Recent SSH Sessions & Commands */}
      <Card
        title="Recent SSH / Telnet Attacker Sessions & Commands"
        subtitle="Successful Cowrie logins and the exact shell commands executed by intruders."
        action={
          <Button variant="secondary" className="text-xs" onClick={() => onNavigate("Incidents & Replays")}>
            <Terminal className="h-3.5 w-3.5" />
            All Sessions &amp; Payloads
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
        <Card title="Attack Activity by Trap (24h)" subtitle="Breakdown across SSH, FTP/Mail, HTTP, Docker, K8s & AI proxies">
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
