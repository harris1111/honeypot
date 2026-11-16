import { useEffect, useState } from "react";
import { Card, Badge, Button } from "../components/ui/primitives";
import { apiFetch } from "../lib/api";

export function CanaryFactoryPage() {
  const [canaries, setCanaries] = useState<any[]>([]);
  const [style, setStyle] = useState("openai");
  const [source, setSource] = useState("custom_lure");
  const [mintedEnv, setMintedEnv] = useState("");

  const load = () => {
    apiFetch<any>("/api/admin/canaries").then((d) => setCanaries(d.canaries || [])).catch(() => {});
  };
  useEffect(load, []);

  const mint = async () => {
    const res = await apiFetch<any>("/api/admin/canaries", {
      method: "POST",
      body: JSON.stringify({ provider_style: style, placement_source: source, paid_upstream_eligible: true }),
    });
    setMintedEnv(res.env_lure || "");
    load();
  };

  return (
    <div className="space-y-4">
      <Card title="Mint Signed Traceable Canary Keys">
        <div className="flex flex-wrap gap-2 text-xs">
          <select value={style} onChange={(e) => setStyle(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5">
            <option value="openai">OpenAI (sk-proj-*)</option>
            <option value="anthropic">Anthropic (sk-ant-api03-*)</option>
          </select>
          <input value={source} onChange={(e) => setSource(e.target.value)} placeholder="Placement memo" className="rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5" />
          <Button onClick={mint}>Mint Canary Lure</Button>
        </div>
        {mintedEnv && (
          <pre className="mt-3 overflow-x-auto rounded bg-slate-950 p-2.5 text-xs text-emerald-300">
            <code>{mintedEnv}</code>
          </pre>
        )}
      </Card>

      <Card title="Active Canary Credentials Ledger">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-slate-800 text-slate-400">
            <tr><th className="py-2">Prefix</th><th>Style</th><th>Source</th><th>Paid Gate</th><th>Hits</th></tr>
          </thead>
          <tbody>
            {canaries.map((c) => (
              <tr key={c.id} className="border-b border-slate-900">
                <td className="py-2 font-mono text-cyan-300">{c.key_prefix}...</td>
                <td>{c.provider_style}</td>
                <td>{c.placement_source}</td>
                <td><Badge tone={c.paid_upstream_eligible ? "emerald" : "slate"}>{c.paid_upstream_eligible ? "paid-ok" : "$0-only"}</Badge></td>
                <td className="font-bold text-amber-300">{c.hit_count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
