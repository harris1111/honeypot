import { useEffect, useState } from "react";
import { Card, Badge, Button } from "../components/ui/primitives";
import { apiFetch } from "../lib/api";

export function ActiveGuardPage() {
  const [decisions, setDecisions] = useState<any[]>([]);
  const [allowlist, setAllowlist] = useState<any[]>([]);
  const [rules, setRules] = useState<any[]>([]);
  const [wafExpr, setWafExpr] = useState("");
  const [manualIP, setManualIP] = useState("");
  const [newCIDR, setNewCIDR] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [errMsg, setErrMsg] = useState("");

  const load = () => {
    apiFetch<any>("/api/admin/guard/decisions").then((d) => setDecisions(d.decisions || [])).catch(() => {});
    apiFetch<any>("/api/admin/guard/allowlist").then((d) => setAllowlist(d.allowlist || [])).catch(() => {});
    apiFetch<any>("/api/admin/guard/rules").then((d) => setRules(d.rules || [])).catch(() => {});
    apiFetch<any>("/api/admin/guard/waf-expr").then((d) => setWafExpr(d.expression || "")).catch(() => {});
  };
  useEffect(load, []);

  const approve = async (id: string) => {
    setErrMsg("");
    try {
      await apiFetch("/api/admin/guard/decisions/approve", {
        method: "POST",
        body: JSON.stringify({ ids: [id], ttl_hours: 168 }),
      });
      load();
    } catch (e: any) {
      setErrMsg(e.message);
    }
  };

  const unban = async (id: string) => {
    setErrMsg("");
    try {
      await apiFetch(`/api/admin/guard/decisions/${id}/unban`, { method: "POST", body: JSON.stringify({ reason: "Admin rollback" }) });
      load();
    } catch (e: any) {
      setErrMsg(e.message);
    }
  };

  const submitManualBlock = async () => {
    setErrMsg("");
    try {
      await apiFetch("/api/admin/guard/manual-block", {
        method: "POST",
        body: JSON.stringify({ indicator_type: "ip", indicator_value: manualIP, target_sync: "both", ttl_hours: 168, reason: "Manual operator block" }),
      });
      setManualIP("");
      load();
    } catch (e: any) {
      setErrMsg(e.message);
    }
  };

  const addAllow = async () => {
    setErrMsg("");
    try {
      await apiFetch("/api/admin/guard/allowlist", { method: "POST", body: JSON.stringify({ cidr: newCIDR, label: newLabel }) });
      setNewCIDR("");
      setNewLabel("");
      load();
    } catch (e: any) {
      setErrMsg(e.message);
    }
  };

  return (
    <div className="space-y-4">
      {errMsg && <div className="rounded border border-red-800 bg-red-950/60 p-2.5 text-xs text-red-200">{errMsg}</div>}

      <Card
        title="Pending Triage &amp; Active Enforcement Queue (Zero Blind Auto-Ban Default)"
        actions={
          <div className="flex gap-1.5">
            <input value={manualIP} onChange={(e) => setManualIP(e.target.value)} placeholder="Manual IP/CIDR" className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs" />
            <Button onClick={submitManualBlock}>Manual Block</Button>
          </div>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr><th className="py-2">Indicator</th><th>Target</th><th>Status</th><th>Reason</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {decisions.map((d) => (
                <tr key={d.id} className="border-b border-slate-900">
                  <td className="py-2 font-mono text-slate-100">{d.indicator_value}</td>
                  <td><Badge>{d.target_sync}</Badge></td>
                  <td><Badge tone={d.status === "pending_approval" ? "amber" : d.status === "enforced" || d.status === "approved" ? "red" : "slate"}>{d.status}</Badge></td>
                  <td className="text-slate-300">{d.reason}</td>
                  <td className="flex gap-1.5 py-2">
                    {d.status === "pending_approval" && (
                      <>
                        <Button onClick={() => approve(d.id)}>Approve Ban</Button>
                        <Button variant="secondary" onClick={() => apiFetch(`/api/admin/guard/decisions/${d.id}/reject`, { method: "POST", body: JSON.stringify({ reason: "Dismissed" }) }).then(load)}>Dismiss</Button>
                      </>
                    )}
                    {(d.status === "approved" || d.status === "enforced" || d.status === "pending_unban") && (
                      <Button variant="danger" onClick={() => unban(d.id)}>Emergency Unban</Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card title="Protected Allowlist (Safe Guardrails)">
          <div className="mb-2 flex gap-2">
            <input value={newCIDR} onChange={(e) => setNewCIDR(e.target.value)} placeholder="CIDR e.g. 203.0.113.10/32" className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs" />
            <input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="Label" className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs" />
            <Button onClick={addAllow}>Add</Button>
          </div>
          <div className="max-h-48 space-y-1 overflow-y-auto text-xs">
            {allowlist.map((a) => (
              <div key={a.id} className="flex items-center justify-between rounded bg-slate-950/70 px-2 py-1">
                <span><code className="text-cyan-300">{a.cidr}</code> — {a.label}</span>
                {a.is_system_locked ? (
                  <Badge tone="purple">locked</Badge>
                ) : (
                  <Button variant="ghost" onClick={() => apiFetch(`/api/admin/guard/allowlist/${a.id}`, { method: "DELETE" }).then(load)}>Remove</Button>
                )}
              </div>
            ))}
          </div>
        </Card>

        <Card title="Policy Rules &amp; Cloudflare WAF Expression">
          <div className="mb-3 space-y-1 text-xs">
            {rules.map((r) => (
              <div key={r.id} className="flex items-center justify-between rounded bg-slate-950/70 px-2 py-1">
                <span>#{r.priority} {r.name}</span>
                <Badge tone={r.action === "auto_enforce" ? "red" : r.action === "ignore" ? "emerald" : "amber"}>{r.action}</Badge>
              </div>
            ))}
          </div>
          <div className="text-xs text-slate-400">Generated Wirefilter Expression:</div>
          <pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-2 text-xs text-emerald-300">
            <code>{wafExpr}</code>
          </pre>
        </Card>
      </div>
    </div>
  );
}
