import { useEffect, useState } from "react";
import { Bot, DollarSign, Save } from "lucide-react";
import { apiFetch } from "../lib/api";
import { Badge, Button, Card, EmptyState, Input, Select, Textarea } from "../components/ui/primitives";

interface ConversationRow {
  id: string;
  canary_key_id: string;
  source_ip: string;
  api_dialect: string;
  requested_model: string;
  emulated_persona: string;
  probe_flags: string[];
  messages_json: string;
  tools_json: string;
  response_text: string;
  degraded_mode: string;
  tokens_in: number;
  tokens_out: number;
  cost_usd: number;
  created_at: string;
}

interface PersonaRow {
  model_pattern: string;
  vendor_family: string;
  system_prompt: string;
  anti_leak_terms: string[];
  degrade_mode: string;
  max_daily_usd: number;
  max_tokens_cap: number;
  updated_at?: string;
}

export function LlmSpyPage() {
  const [conversations, setConversations] = useState<ConversationRow[]>([]);
  const [personas, setPersonas] = useState<PersonaRow[]>([]);
  const [budget, setBudget] = useState<{ spent_today_usd: number; cap_usd: number }>({
    spent_today_usd: 0,
    cap_usd: 5,
  });

  const [pattern, setPattern] = useState("gpt-4o");
  const [vendor, setVendor] = useState("openai");
  const [prompt, setPrompt] = useState("You are an internal OpenAI-compatible assistant serving Acme Analytics.");
  const [antiLeak, setAntiLeak] = useState("honeypot,cowrie,canary,deception");
  const [degradeMode, setDegradeMode] = useState("realistic_stub");
  const [maxDaily, setMaxDaily] = useState(5);
  const [maxTokens, setMaxTokens] = useState(1024);

  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const loadAll = async () => {
    try {
      const [cRes, pRes, bRes] = await Promise.all([
        apiFetch<{ conversations: ConversationRow[] }>("/api/admin/llm/conversations"),
        apiFetch<{ personas: PersonaRow[] }>("/api/admin/llm/personas"),
        apiFetch<{ spent_today_usd: number; cap_usd: number }>("/api/admin/llm/budget"),
      ]);
      setConversations(cRes.conversations ?? []);
      setPersonas(pRes.personas ?? []);
      setBudget(bRes);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load LLM Spy data");
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  const selectPersona = (p: PersonaRow) => {
    setPattern(p.model_pattern);
    setVendor(p.vendor_family);
    setPrompt(p.system_prompt);
    setAntiLeak((p.anti_leak_terms ?? []).join(","));
    setDegradeMode(p.degrade_mode || "realistic_stub");
    setMaxDaily(p.max_daily_usd || 5);
    setMaxTokens(p.max_tokens_cap || 1024);
  };

  const handleSavePersona = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await apiFetch("/api/admin/llm/personas", {
        method: "PUT",
        body: JSON.stringify({
          model_pattern: pattern,
          vendor_family: vendor,
          system_prompt: prompt,
          anti_leak_terms: antiLeak
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          degrade_mode: degradeMode,
          max_daily_usd: Number(maxDaily),
          max_tokens_cap: Number(maxTokens),
        }),
      });
      setMsg(`Saved persona "${pattern}"`);
      await loadAll();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to save persona");
    }
  };

  const pct = Math.min(100, Math.round(((budget.spent_today_usd || 0) / Math.max(0.01, budget.cap_usd || 5)) * 100));

  return (
    <div className="space-y-6">
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

      {/* Circuit Breaker Budget Card */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <DollarSign className="h-4 w-4 text-emerald-500" />
            Upstream Chameleon LLM Budget Cap
          </span>
        }
        subtitle="Protects your API wallet with automatic degraded stub fallback once daily spend reaches limit."
      >
        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <span className="font-semibold tabular-nums text-[var(--text-primary)]">
            ${(budget.spent_today_usd ?? 0).toFixed(4)} spent today
          </span>
          <span className="text-xs text-[var(--text-muted)]">Cap: ${(budget.cap_usd ?? 5).toFixed(2)} / day</span>
        </div>
        <div className="mt-2 h-2.5 w-full overflow-hidden rounded-full bg-[var(--bg-subtle)]">
          <div className="h-full rounded-full bg-emerald-500" style={{ width: `${Math.max(4, pct)}%` }} />
        </div>
      </Card>

      {/* Captured Conversations */}
      <Card
        title={`Captured Attacker AI Prompts (${conversations.length})`}
        subtitle="Inspect what models, prompts, and jailbreaks attackers tested against stolen Canary keys or Ollama/LiteLLM decoys."
      >
        {conversations.length === 0 ? (
          <EmptyState
            title="No AI gateway sessions captured yet"
            description="When an attacker steals a Canary API key or probes :4000 / :11434, full prompts and decoy replies appear here."
          />
        ) : (
          <div className="space-y-3">
            {conversations.map((c) => (
              <div key={c.id} className="hp-subtle rounded-xl border p-4 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Bot className="h-4 w-4 text-blue-500" />
                    <span className="font-mono text-sm font-semibold text-[var(--text-primary)]">{c.source_ip}</span>
                    <Badge tone="info">{c.api_dialect}</Badge>
                    <Badge>{c.requested_model}</Badge>
                    {c.probe_flags?.map((pf) => (
                      <Badge key={pf} tone="warning">
                        {pf}
                      </Badge>
                    ))}
                  </div>
                  <span className="text-xs tabular-nums text-[var(--text-muted)]">
                    in:{c.tokens_in} out:{c.tokens_out} · ${(c.cost_usd ?? 0).toFixed(4)}
                  </span>
                </div>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-3 font-mono text-xs text-[var(--text-primary)]">
                    {c.messages_json}
                  </pre>
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] p-3 font-mono text-xs text-[var(--text-secondary)]">
                    {c.response_text}
                  </pre>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Chameleon Persona Studio */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card>
          <header className="mb-4">
            <h2 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">
              Chameleon Persona Studio
            </h2>
            <p className="mt-0.5 text-sm text-[var(--text-muted)]">
              Configure believable AI identities served to attackers without leaking honeypot indicators.
            </p>
          </header>

          <form onSubmit={handleSavePersona} className="space-y-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>Model Pattern</span>
                <Input value={pattern} onChange={(e) => setPattern(e.target.value)} required />
              </label>
              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>Vendor Family</span>
                <Select value={vendor} onChange={(e) => setVendor(e.target.value)}>
                  <option value="openai">openai</option>
                  <option value="anthropic">anthropic</option>
                  <option value="ollama">ollama</option>
                </Select>
              </label>
            </div>
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>System Prompt</span>
              <Textarea rows={3} value={prompt} onChange={(e) => setPrompt(e.target.value)} required />
            </label>
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Anti-Leak Terms (comma-separated)</span>
              <Input value={antiLeak} onChange={(e) => setAntiLeak(e.target.value)} />
            </label>
            <div className="grid grid-cols-3 gap-2">
              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>Fallback Mode</span>
                <Input value={degradeMode} onChange={(e) => setDegradeMode(e.target.value)} />
              </label>
              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>Max USD/day</span>
                <Input type="number" step="0.5" value={maxDaily} onChange={(e) => setMaxDaily(Number(e.target.value))} />
              </label>
              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>Max Tokens</span>
                <Input type="number" value={maxTokens} onChange={(e) => setMaxTokens(Number(e.target.value))} />
              </label>
            </div>
            <Button type="submit">
              <Save className="h-4 w-4" /> Save Persona
            </Button>
          </form>
        </Card>

        <Card title={`Active Personas (${personas.length})`} subtitle="Click a persona to load it into the editor.">
          {personas.length === 0 ? (
            <EmptyState
              title="No custom personas stored yet"
              description="Save a model pattern on the left to override default OpenAI/Anthropic/Ollama deception replies."
            />
          ) : (
            <div className="space-y-2.5">
              {personas.map((p) => (
                <button
                  key={p.model_pattern}
                  type="button"
                  onClick={() => selectPersona(p)}
                  className="hp-subtle w-full rounded-xl border p-3 text-left transition hover:border-[var(--border-strong)]"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-sm font-semibold text-[var(--text-primary)]">{p.model_pattern}</span>
                    <Badge tone="info">{p.vendor_family}</Badge>
                  </div>
                  <p className="mt-1 line-clamp-2 text-xs text-[var(--text-secondary)]">{p.system_prompt}</p>
                </button>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
