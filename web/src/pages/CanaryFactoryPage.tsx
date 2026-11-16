import { useEffect, useState } from "react";
import { KeyRound, Sparkles } from "lucide-react";
import { apiFetch } from "../lib/api";
import { Badge, Button, Card, CopyButton, EmptyState, Input, Select } from "../components/ui/primitives";

interface CanaryRow {
  id: string;
  key_prefix: string;
  provider_style: string;
  node_id: string;
  placement_source: string;
  placement_path: string;
  paid_upstream_eligible: boolean;
  hit_count: number;
  last_hit_at: string;
  created_at: string;
}

export function CanaryFactoryPage() {
  const [canaries, setCanaries] = useState<CanaryRow[]>([]);
  const [providerStyle, setProviderStyle] = useState("openai");
  const [placementSource, setPlacementSource] = useState("cowrie_honeyfs");
  const [placementPath, setPlacementPath] = useState("/var/www/app/.env");
  const [paidEligible, setPaidEligible] = useState(false);
  const [mintedSnippet, setMintedSnippet] = useState("");
  const [err, setErr] = useState("");

  const load = async () => {
    try {
      const res = await apiFetch<{ canaries: CanaryRow[] }>("/api/admin/canaries");
      setCanaries(res.canaries ?? []);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load canary keys");
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const handleMint = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      const res = await apiFetch<{ env_lure: string }>("/api/admin/canaries", {
        method: "POST",
        body: JSON.stringify({
          provider_style: providerStyle,
          placement_source: placementSource,
          placement_path: placementPath,
          paid_upstream_eligible: paidEligible,
        }),
      });
      setMintedSnippet(res.env_lure ?? "");
      await load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to mint canary key");
    }
  };

  return (
    <div className="space-y-6">
      {err && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-2.5 text-sm text-rose-900 dark:border-rose-800 dark:bg-rose-950/50 dark:text-rose-200">
          {err}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card>
          <header className="mb-4 flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-amber-500" />
            <div>
              <h2 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">
                Mint Signed Traceable Canary Keys
              </h2>
              <p className="text-xs text-[var(--text-muted)]">
                Plant realistic API keys inside decoy files or leaked configs to catch credential reuse.
              </p>
            </div>
          </header>

          <form onSubmit={handleMint} className="space-y-3">
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Key Provider Format</span>
              <Select value={providerStyle} onChange={(e) => setProviderStyle(e.target.value)}>
                <option value="openai">OpenAI (sk-proj-...)</option>
                <option value="anthropic">Anthropic (sk-ant-api03-...)</option>
              </Select>
            </label>
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Placement Source</span>
              <Input value={placementSource} onChange={(e) => setPlacementSource(e.target.value)} required />
            </label>
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Lure File Path</span>
              <Input value={placementPath} onChange={(e) => setPlacementPath(e.target.value)} required />
            </label>
            <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={paidEligible}
                onChange={(e) => setPaidEligible(e.target.checked)}
                className="h-4 w-4 rounded border-slate-400"
              />
              Allow paid Chameleon upstream pass-through when hit
            </label>
            <Button type="submit" className="w-full">
              <Sparkles className="h-4 w-4" /> Mint Canary Key
            </Button>
          </form>

          {mintedSnippet && (
            <div className="mt-4 space-y-2 rounded-lg border border-amber-300 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-950/40">
              <div className="flex items-center justify-between text-xs font-semibold text-amber-900 dark:text-amber-200">
                <span>Generated .env Lure Snippet</span>
                <CopyButton value={mintedSnippet} />
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-900 dark:text-amber-100">
                {mintedSnippet}
              </pre>
            </div>
          )}
        </Card>

        <Card
          className="lg:col-span-2"
          title={`Minted Canary Keys (${canaries.length})`}
          subtitle="Tracks where each trap key was planted and how many times attackers tried to call your AI gateway with it."
        >
          {canaries.length === 0 ? (
            <EmptyState
              title="No Canary keys minted yet"
              description="Sensors automatically seed keys for Cowrie and Git lures on enrollment, or mint a custom key on the left."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-[var(--border-subtle)] text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                    <th className="py-2 pr-3">Prefix</th>
                    <th className="py-2 pr-3">Style</th>
                    <th className="py-2 pr-3">Location</th>
                    <th className="py-2 pr-3">Hits</th>
                    <th className="py-2">Last Hit</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]">
                  {canaries.map((c) => (
                    <tr key={c.id}>
                      <td className="py-3 pr-3 font-mono text-xs font-semibold text-[var(--text-primary)]">{c.key_prefix}</td>
                      <td className="py-3 pr-3">
                        <Badge tone="info">{c.provider_style}</Badge>
                      </td>
                      <td className="py-3 pr-3 text-xs text-[var(--text-secondary)]">
                        <div>{c.placement_source}</div>
                        <div className="font-mono text-[var(--text-muted)]">{c.placement_path || "—"}</div>
                      </td>
                      <td className="py-3 pr-3">
                        <Badge tone={c.hit_count > 0 ? "danger" : "default"}>{c.hit_count}</Badge>
                      </td>
                      <td className="py-3 font-mono text-xs text-[var(--text-muted)]">{c.last_hit_at || "never"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
