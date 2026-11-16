import { useEffect, useState } from "react";
import { Card, Badge, Button } from "../components/ui/primitives";
import { apiFetch } from "../lib/api";

export function LlmSpyPage() {
  const [convs, setConvs] = useState<any[]>([]);
  const [personas, setPersonas] = useState<any[]>([]);
  const [editPattern, setEditPattern] = useState("gpt-4o*");
  const [editPrompt, setEditPrompt] = useState("");
  const [editFamily, setEditFamily] = useState("openai");

  const load = () => {
    apiFetch<any>("/api/admin/llm/conversations").then((d) => setConvs(d.conversations || [])).catch(() => {});
    apiFetch<any>("/api/admin/llm/personas").then((d) => setPersonas(d.personas || [])).catch(() => {});
  };
  useEffect(load, []);

  const savePersona = async () => {
    await apiFetch("/api/admin/llm/personas", {
      method: "PUT",
      body: JSON.stringify({
        model_pattern: editPattern,
        vendor_family: editFamily,
        system_prompt: editPrompt,
        anti_leak_terms: ["deepseek", "qwen", "gemini", "alibaba"],
        degrade_mode: "slow_tarpit",
        max_daily_usd: 5.0,
        max_tokens_cap: 512,
      }),
    });
    load();
  };

  return (
    <div className="space-y-4">
      <Card title="Intercepted Attacker LLM Prompts &amp; Offensive Agent Tool Calls">
        <div className="space-y-2 text-xs">
          {convs.map((c) => (
            <div key={c.id} className="rounded border border-slate-800 bg-slate-950/70 p-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone="cyan">{c.api_dialect}</Badge>
                <span className="font-mono text-slate-200">{c.source_ip}</span>
                <span className="text-slate-400">model={c.emulated_persona}</span>
                <Badge tone={c.degraded_mode === "none" ? "emerald" : "amber"}>{c.degraded_mode}</Badge>
                {(c.probe_flags || []).map((f: string) => <Badge key={f} tone="red">{f}</Badge>)}
              </div>
              <pre className="mt-1.5 overflow-x-auto whitespace-pre-wrap text-slate-300"><code>{c.messages_json}</code></pre>
              {c.response_text && <div className="mt-1 text-emerald-300">Reply: {c.response_text}</div>}
            </div>
          ))}
        </div>
      </Card>

      <Card title="Chameleon Persona Studio (Anti-Probe Overrides)">
        <div className="mb-3 space-y-2 text-xs">
          {personas.map((p) => (
            <div key={p.model_pattern} className="rounded bg-slate-950/70 p-2">
              <div className="font-semibold text-cyan-300">{p.model_pattern} ({p.vendor_family}) — max=${p.max_daily_usd}/day</div>
              <div className="text-slate-400">{p.system_prompt}</div>
            </div>
          ))}
        </div>
        <div className="grid grid-cols-1 gap-2 text-xs">
          <div className="flex gap-2">
            <input value={editPattern} onChange={(e) => setEditPattern(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1" />
            <select value={editFamily} onChange={(e) => setEditFamily(e.target.value)} className="rounded border border-slate-700 bg-slate-950 px-2 py-1">
              <option value="openai">openai</option>
              <option value="anthropic">anthropic</option>
              <option value="ollama">ollama</option>
            </select>
          </div>
          <textarea value={editPrompt} onChange={(e) => setEditPrompt(e.target.value)} rows={3} placeholder="Persona system prompt override..." className="rounded border border-slate-700 bg-slate-950 p-2" />
          <Button onClick={savePersona}>Save Persona Profile</Button>
        </div>
      </Card>
    </div>
  );
}
