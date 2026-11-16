import { useEffect, useRef, useState } from "react";
import * as AsciinemaPlayer from "asciinema-player";
import { Card, Badge, Button } from "../components/ui/primitives";
import { apiFetch } from "../lib/api";

export function IncidentsExplorerPage() {
  const [incidents, setIncidents] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [replays, setReplays] = useState<any[]>([]);
  const [activeCast, setActiveCast] = useState<string>("");
  const playerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    apiFetch<any>("/api/admin/incidents").then((d) => setIncidents(d.incidents || [])).catch(() => {});
    apiFetch<any>("/api/admin/telemetry").then((d) => {
      setEvents(d.events || []);
      setReplays(d.replays || []);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!activeCast || !playerRef.current) return;
    playerRef.current.innerHTML = "";
    const instance = AsciinemaPlayer.create({ data: activeCast }, playerRef.current, { autoPlay: true });
    return () => { instance?.dispose?.(); };
  }, [activeCast]);

  const openIncident = async (id: string) => {
    const res = await apiFetch<any>(`/api/admin/incidents/${id}`);
    setEvents(res.events || []);
  };

  const openReplay = async (id: string) => {
    const res = await apiFetch<any>(`/api/admin/replays/${id}`);
    setActiveCast(res.asciicast_v2 || "");
  };

  return (
    <div className="space-y-4">
      <Card title="Correlated Multi-IP Kill-Chain Incidents">
        <div className="space-y-2 text-xs">
          {incidents.map((inc) => (
            <div key={inc.id} className="flex items-center justify-between rounded border border-slate-800 bg-slate-950/70 p-2.5">
              <div>
                <div className="flex items-center gap-2">
                  <Badge tone={inc.severity === "critical" ? "red" : "amber"}>{inc.severity}</Badge>
                  <span className="font-semibold text-slate-100">{inc.title}</span>
                  <span className="text-slate-400">score={inc.confidence_score}</span>
                </div>
                <div className="mt-1 font-mono text-slate-400">
                  IPs: {(inc.related_ips || []).join(", ")} | CVEs: {(inc.cve_ids || []).join(", ")}
                </div>
              </div>
              <Button variant="secondary" onClick={() => openIncident(inc.id)}>Inspect</Button>
            </div>
          ))}
        </div>
      </Card>

      {replays.length > 0 && (
        <Card title="SSH Session Replays (OSC/DCS/APC Sanitized)">
          <div className="flex flex-wrap gap-2">
            {replays.map((r) => (
              <Button key={r.id} variant="secondary" onClick={() => openReplay(r.id)}>
                Replay {r.username || "root"}@{r.source_ip} ({r.hassh?.slice(0, 8) || "no-hassh"})
              </Button>
            ))}
          </div>
          {activeCast && <div ref={playerRef} className="mt-3 overflow-hidden rounded border border-slate-800" />}
        </Card>
      )}

      <Card title="HTTP &amp; Trap Telemetry Inspector (Escaped Read-Only Text)">
        <div className="space-y-2 font-mono text-xs">
          {events.map((ev) => (
            <div key={ev.id} className="rounded border border-slate-800 bg-slate-950/80 p-2">
              <div className="flex items-center gap-2">
                <Badge tone={ev.is_kev ? "red" : "cyan"}>{ev.cve_id || ev.trap_kind}</Badge>
                <span className="text-slate-200">{ev.source_ip}</span>
                <span className="text-slate-400">{ev.http_method} {ev.http_path}</span>
                {ev.ja4 && <span className="text-purple-300">JA4={ev.ja4}</span>}
              </div>
              {ev.raw_payload && (
                <pre className="mt-1.5 max-h-28 overflow-auto whitespace-pre-wrap text-slate-300">
                  <code>{ev.raw_payload}</code>
                </pre>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
