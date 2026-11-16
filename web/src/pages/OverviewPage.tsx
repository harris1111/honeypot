import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { Card, Badge } from "../components/ui/primitives";
import { apiFetch, LiveEventTick } from "../lib/api";

export function OverviewPage({ liveFeed }: { liveFeed: LiveEventTick[] }) {
  const [stats, setStats] = useState<any>({
    events_24h: 0,
    open_incidents: 0,
    pending_triage: 0,
    malware_count: 0,
    canary_hits: 0,
    llm_spent_usd: 0,
    top_cves: [],
  });

  useEffect(() => {
    apiFetch<any>("/api/admin/overview").then(setStats).catch(() => {});
  }, []);

  const spentPct = Math.min(100, Math.round(((stats.llm_spent_usd || 0) / 5.0) * 100));

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <Card title="Events (24h)"><div className="text-2xl font-bold text-cyan-400">{stats.events_24h}</div></Card>
        <Card title="Open Incidents"><div className="text-2xl font-bold text-amber-400">{stats.open_incidents}</div></Card>
        <Card title="Pending Triage"><div className="text-2xl font-bold text-red-400">{stats.pending_triage}</div></Card>
        <Card title="Malware Vault"><div className="text-2xl font-bold text-purple-400">{stats.malware_count}</div></Card>
        <Card title="Canary Key Hits"><div className="text-2xl font-bold text-emerald-400">{stats.canary_hits}</div></Card>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card title="Attacks by CVE (24h)" className="lg:col-span-2">
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.top_cves || []}>
                <XAxis dataKey="cve_id" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} />
                <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }} />
                <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card title="LLM Daily Spend &amp; Tarpit Guard">
          <div className="space-y-3">
            <div className="flex items-baseline justify-between">
              <span className="text-xs text-slate-400">Daily Spend vs Cap ($5.00)</span>
              <span className="font-mono text-sm text-cyan-300">${(stats.llm_spent_usd || 0).toFixed(4)}</span>
            </div>
            <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-800">
              <div className="h-full bg-cyan-500 transition-all" style={{ width: `${spentPct}%` }} />
            </div>
            <p className="text-xs text-slate-400">
              Quota breaches fail over safely to the $0 bounded Slow SSE Tarpit (128 global / 2 per IP).
            </p>
          </div>
        </Card>
      </div>

      <Card title="Live Telemetry Ticker" subtitle="Throttled 250ms Redis live stream over same-origin authenticated WebSocket">
        <div className="max-h-64 space-y-1.5 overflow-y-auto font-mono text-xs">
          {liveFeed.length === 0 ? (
            <div className="text-slate-500">Waiting for incoming telemetry events...</div>
          ) : (
            liveFeed.map((ev, i) => (
              <div key={`${ev.event_uuid}-${i}`} className="flex items-center justify-between rounded bg-slate-950/70 px-2.5 py-1.5">
                <div className="flex items-center gap-2">
                  <Badge tone={ev.is_kev ? "red" : "cyan"}>{ev.cve_id || ev.trap_kind}</Badge>
                  <span className="text-slate-200">{ev.source_ip}</span>
                  <span className="text-slate-400">{ev.persona}</span>
                  <span className="truncate max-w-md text-slate-300">{ev.http_path}</span>
                </div>
                <span className="text-slate-500">sev={ev.severity}</span>
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
}
