import { useEffect, useState } from "react";
import { Check, RotateCcw, Shield, ShieldBan, Trash2 } from "lucide-react";
import { apiFetch } from "../lib/api";
import { Badge, Button, Card, CopyButton, EmptyState, Input, Select } from "../components/ui/primitives";

interface DecisionRow {
  id: string;
  incident_id: string;
  indicator_type: string;
  indicator_value: string;
  target_sync: string;
  status: string;
  decided_by: string;
  reason: string;
  ttl_expires_at?: string;
  created_at: string;
}

interface AllowlistRow {
  id: string;
  cidr: string;
  label: string;
  is_system_locked: boolean;
  created_by: string;
}

interface RuleRow {
  name: string;
  priority: number;
  enabled: boolean;
  conditions_json: string;
  action: string;
  default_ttl_hours: number;
  target_sync: string;
}

interface AuditLogRow {
  id: number;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  created_at: string;
}

function decisionTone(status: string) {
  if (status === "approved" || status === "active") return "danger" as const;
  if (status === "pending_approval") return "warning" as const;
  if (status === "rolled_back") return "info" as const;
  return "default" as const;
}

export function ActiveGuardPage() {
  const [subTab, setSubTab] = useState<"queue" | "allowlist" | "rules" | "audit">("queue");
  const [statusFilter, setStatusFilter] = useState("");
  const [decisions, setDecisions] = useState<DecisionRow[]>([]);
  const [selectedIDs, setSelectedIDs] = useState<Record<string, boolean>>({});
  const [allowlist, setAllowlist] = useState<AllowlistRow[]>([]);
  const [rules, setRules] = useState<RuleRow[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogRow[]>([]);
  const [wafExpr, setWafExpr] = useState("");
  const [enterprise, setEnterprise] = useState(false);

  const [manualValue, setManualValue] = useState("");
  const [manualType, setManualType] = useState("ip");
  const [manualSync, setManualSync] = useState("nginx");
  const [manualTTL, setManualTTL] = useState(24);
  const [manualReason, setManualReason] = useState("Verified malicious scanning");

  const [newCIDR, setNewCIDR] = useState("");
  const [newLabel, setNewLabel] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const loadAll = async () => {
    try {
      const [dRes, aRes, rRes, wRes, lRes] = await Promise.all([
        apiFetch<{ decisions: DecisionRow[] }>(
          `/api/admin/guard/decisions${statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : ""}`
        ),
        apiFetch<{ allowlist: AllowlistRow[] }>("/api/admin/guard/allowlist"),
        apiFetch<{ rules: RuleRow[] }>("/api/admin/guard/rules"),
        apiFetch<{ expression: string; enterprise_enabled: boolean }>("/api/admin/guard/waf-expr"),
        apiFetch<{ logs: AuditLogRow[] }>("/api/admin/audit-logs"),
      ]);
      setDecisions(dRes.decisions ?? []);
      setAllowlist(aRes.allowlist ?? []);
      setRules(rRes.rules ?? []);
      setWafExpr(wRes.expression ?? "");
      setEnterprise(Boolean(wRes.enterprise_enabled));
      setAuditLogs(lRes.logs ?? []);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load Active Guard state");
    }
  };

  useEffect(() => {
    void loadAll();
  }, [statusFilter]);

  const checkedList = Object.entries(selectedIDs)
    .filter(([, v]) => v)
    .map(([k]) => k);

  const approveSelected = async (ids: string[]) => {
    if (ids.length === 0) return;
    setErr("");
    try {
      await apiFetch("/api/admin/guard/decisions/approve", {
        method: "POST",
        body: JSON.stringify({ ids, target_sync: manualSync, ttl_hours: Number(manualTTL) }),
      });
      setSelectedIDs({});
      setMsg(`Approved ${ids.length} block decision(s)`);
      await loadAll();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Approval failed");
    }
  };

  const decisionOp = async (id: string, op: "reject" | "unban") => {
    setErr("");
    try {
      await apiFetch(`/api/admin/guard/decisions/${encodeURIComponent(id)}/${op}`, {
        method: "POST",
        body: JSON.stringify({ reason: "Operator decision" }),
      });
      setMsg(`Decision ${op} completed`);
      await loadAll();
    } catch (e) {
      setErr(e instanceof Error ? e.message : `Operation ${op} failed`);
    }
  };

  const handleManualBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await apiFetch("/api/admin/guard/manual-block", {
        method: "POST",
        body: JSON.stringify({
          indicator_type: manualType,
          indicator_value: manualValue,
          target_sync: manualSync,
          ttl_hours: Number(manualTTL),
          reason: manualReason,
        }),
      });
      setManualValue("");
      setMsg("Manual block submitted");
      await loadAll();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Manual block rejected");
    }
  };

  const handleAddAllowlist = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await apiFetch("/api/admin/guard/allowlist", {
        method: "POST",
        body: JSON.stringify({ cidr: newCIDR, label: newLabel }),
      });
      setNewCIDR("");
      setNewLabel("");
      setMsg("Added CIDR to protected allowlist");
      await loadAll();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to add CIDR");
    }
  };

  const handleDeleteAllowlist = async (id: string) => {
    setErr("");
    try {
      await apiFetch(`/api/admin/guard/allowlist/${encodeURIComponent(id)}`, { method: "DELETE" });
      await loadAll();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Cannot remove allowlist entry");
    }
  };

  return (
    <div className="space-y-6">
      {/* Safety Banner preserving required contract copy */}
      <div className="flex items-start gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">
        <Shield className="mt-0.5 h-5 w-5 shrink-0 text-amber-600 dark:text-amber-400" />
        <div>
          <div className="font-semibold">Zero Blind Auto-Ban Default</div>
          <p className="mt-0.5 opacity-90">
            Attack telemetry creates triage recommendations only. No IP, CIDR, or JA4 hash is synced to Nginx or Cloudflare
            without human approval or explicit allowlist-safe policy match.
          </p>
        </div>
      </div>

      {msg && (
        <div className="rounded-lg border border-emerald-300 bg-emerald-50 px-4 py-2.5 text-sm text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200">
          {msg}
        </div>
      )}
      {err && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-2.5 text-sm text-rose-900 dark:border-rose-800 dark:bg-rose-950/50 dark:text-rose-200">
          {err}
        </div>
      )}

      {/* Sub-navigation */}
      <div className="flex flex-wrap gap-2">
        {[
          { id: "queue", label: `Block Decisions (${decisions.length})` },
          { id: "allowlist", label: `Protected Allowlist (${allowlist.length})` },
          { id: "rules", label: "Policy Rules & Cloudflare WAF" },
          { id: "audit", label: `Audit Logs (${auditLogs.length})` },
        ].map((t) => (
          <Button
            key={t.id}
            type="button"
            variant={subTab === t.id ? "primary" : "secondary"}
            className="text-xs"
            onClick={() => setSubTab(t.id as typeof subTab)}
          >
            {t.label}
          </Button>
        ))}
      </div>

      {subTab === "queue" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <Card
            className="lg:col-span-2"
            title="Guard Triage Queue"
            subtitle="Review recommended bans or roll back active rules."
            action={
              <div className="flex flex-wrap items-center gap-2">
                <Select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="w-auto py-1 text-xs"
                >
                  <option value="">All Statuses</option>
                  <option value="pending_approval">pending_approval</option>
                  <option value="approved">approved</option>
                  <option value="rejected">rejected</option>
                  <option value="rolled_back">rolled_back</option>
                </Select>
                <Button
                  className="px-2.5 py-1 text-xs"
                  disabled={checkedList.length === 0}
                  onClick={() => void approveSelected(checkedList)}
                >
                  <Check className="h-3.5 w-3.5" /> Approve Selected ({checkedList.length})
                </Button>
              </div>
            }
          >
            {decisions.length === 0 ? (
              <EmptyState
                title="No triage decisions in this view"
                description="High-confidence attacker IPs appear here when triage policies flag them, or you can manually stage a block on the right."
              />
            ) : (
              <div className="space-y-2.5">
                {decisions.map((d) => (
                  <div
                    key={d.id}
                    className="hp-subtle flex flex-col justify-between gap-3 rounded-xl border p-3.5 sm:flex-row sm:items-center"
                  >
                    <label className="flex items-start gap-3">
                      <input
                        type="checkbox"
                        checked={Boolean(selectedIDs[d.id])}
                        onChange={(e) => setSelectedIDs((prev) => ({ ...prev, [d.id]: e.target.checked }))}
                        className="mt-1 h-4 w-4 rounded border-slate-400"
                      />
                      <div>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-sm font-semibold text-[var(--text-primary)]">
                            {d.indicator_value}
                          </span>
                          <Badge tone={decisionTone(d.status)}>{d.status}</Badge>
                          <Badge>{d.indicator_type}</Badge>
                          <span className="text-xs text-[var(--text-muted)]">sync: {d.target_sync}</span>
                        </div>
                        <div className="mt-0.5 text-xs text-[var(--text-secondary)]">
                          {d.reason || "Policy match"} · {d.created_at}
                        </div>
                      </div>
                    </label>
                    <div className="flex shrink-0 gap-1.5">
                      {d.status === "pending_approval" && (
                        <>
                          <Button className="px-2.5 py-1 text-xs" onClick={() => void approveSelected([d.id])}>
                            Approve
                          </Button>
                          <Button
                            variant="secondary"
                            className="px-2.5 py-1 text-xs"
                            onClick={() => void decisionOp(d.id, "reject")}
                          >
                            Reject
                          </Button>
                        </>
                      )}
                      {d.status === "approved" && (
                        <Button
                          variant="danger"
                          className="px-2.5 py-1 text-xs"
                          onClick={() => void decisionOp(d.id, "unban")}
                        >
                          <RotateCcw className="h-3.5 w-3.5" /> Unban
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>

          <Card title="Manual Indicator Block" subtitle="Block an attacker IP, CIDR, or JA4 hash immediately (allowlist still enforced).">
            <form onSubmit={handleManualBlock} className="space-y-3">
              <Select value={manualType} onChange={(e) => setManualType(e.target.value)}>
                <option value="ip">IP Address</option>
                <option value="cidr">CIDR Range</option>
                <option value="ja4">JA4 Fingerprint</option>
              </Select>
              <Input
                value={manualValue}
                onChange={(e) => setManualValue(e.target.value)}
                placeholder="e.g. 203.0.113.45"
                required
              />
              <div className="grid grid-cols-2 gap-2">
                <Select value={manualSync} onChange={(e) => setManualSync(e.target.value)}>
                  <option value="nginx">nginx</option>
                  <option value="cloudflare">cloudflare</option>
                  <option value="both">both</option>
                </Select>
                <Input
                  type="number"
                  min={1}
                  max={720}
                  value={manualTTL}
                  onChange={(e) => setManualTTL(Number(e.target.value))}
                  placeholder="TTL hours"
                />
              </div>
              <Input
                value={manualReason}
                onChange={(e) => setManualReason(e.target.value)}
                placeholder="Reason for audit log"
              />
              <Button type="submit" variant="danger" className="w-full">
                <ShieldBan className="h-4 w-4" /> Block Indicator
              </Button>
            </form>
          </Card>
        </div>
      )}

      {subTab === "allowlist" && (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <Card
            className="lg:col-span-2"
            title="Protected CIDR Allowlist"
            subtitle="System-locked and operator-safe CIDRs can never be banned by Active Guard."
          >
            <div className="divide-y divide-[var(--border-subtle)]">
              {allowlist.map((row) => (
                <div key={row.id} className="flex items-center justify-between gap-2 py-2.5 text-sm">
                  <div>
                    <span className="font-mono font-semibold text-[var(--text-primary)]">{row.cidr}</span>
                    <span className="ml-2 text-xs text-[var(--text-muted)]">{row.label}</span>
                  </div>
                  {row.is_system_locked ? (
                    <Badge tone="info">System Locked</Badge>
                  ) : (
                    <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => void handleDeleteAllowlist(row.id)}>
                      <Trash2 className="h-3.5 w-3.5 text-rose-500" /> Remove
                    </Button>
                  )}
                </div>
              ))}
            </div>
          </Card>

          <Card title="Add Safe CIDR" subtitle="Protect your office, VPN, or monitoring IPs before testing.">
            <form onSubmit={handleAddAllowlist} className="space-y-3">
              <Input value={newCIDR} onChange={(e) => setNewCIDR(e.target.value)} placeholder="198.51.100.10/32" required />
              <Input value={newLabel} onChange={(e) => setNewLabel(e.target.value)} placeholder="Operator VPN" required />
              <Button type="submit" className="w-full">
                Add to Allowlist
              </Button>
            </form>
          </Card>
        </div>
      )}

      {subTab === "rules" && (
        <div className="space-y-6">
          <Card
            title="Generated Cloudflare WAF Expression"
            subtitle={enterprise ? "Enterprise JA4 + IP List expression ready." : "Standard IP List wirefilter rule ready."}
            action={<CopyButton value={wafExpr} label="Copy Rule" />}
          >
            <pre className="overflow-x-auto rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-3 font-mono text-xs text-[var(--text-primary)]">
              {wafExpr || "(no active WAF expression generated yet)"}
            </pre>
          </Card>
          <Card title={`Policy Engine Rules (${rules.length})`}>
            <div className="divide-y divide-[var(--border-subtle)] text-sm">
              {rules.map((r) => (
                <div key={r.name} className="flex flex-wrap items-center justify-between gap-2 py-3">
                  <div>
                    <div className="font-semibold text-[var(--text-primary)]">{r.name}</div>
                    <code className="font-mono text-xs text-[var(--text-muted)]">{r.conditions_json}</code>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge tone={r.enabled ? "success" : "default"}>{r.enabled ? "Enabled" : "Disabled"}</Badge>
                    <Badge tone="warning">{r.action}</Badge>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}

      {subTab === "audit" && (
        <Card title="Operator Audit Log" subtitle="Immutable trail of logins, canary minting, trap control, and blocks.">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-[var(--border-subtle)] uppercase tracking-wide text-[var(--text-muted)]">
                  <th className="py-2 pr-3">Time</th>
                  <th className="py-2 pr-3">Actor</th>
                  <th className="py-2 pr-3">Action</th>
                  <th className="py-2 pr-3">Target</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[var(--border-subtle)]">
                {auditLogs.map((l) => (
                  <tr key={l.id}>
                    <td className="py-2 pr-3 font-mono text-[var(--text-muted)]">{l.created_at}</td>
                    <td className="py-2 pr-3 font-medium text-[var(--text-primary)]">{l.actor}</td>
                    <td className="py-2 pr-3 font-mono text-[var(--text-secondary)]">{l.action}</td>
                    <td className="py-2 pr-3 font-mono text-[var(--text-muted)]">
                      {l.target_type}:{l.target_id}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
