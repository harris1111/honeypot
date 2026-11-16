import { useEffect, useState } from "react";
import { Bot, CheckCircle2, DollarSign, FlaskConical, KeyRound, Save, Trash2 } from "lucide-react";
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

interface LLMSettings {
  base_url: string;
  model: string;
  has_api_key: boolean;
  api_key_masked: string;
  max_daily_usd: number;
  allow_unauthenticated_chat: boolean;
  spent_today_usd: number;
  active_mode: "live_upstream" | "builtin_free";
}

interface LLMTestResult {
  mode: string;
  model: string;
  reply: string;
  latency_ms: number;
  error?: string;
}

const PROVIDER_PRESETS = [
  {
    id: "builtin",
    label: "$0 Built-in Simulator",
    baseURL: "",
    model: "deepseek-v4",
    maxDailyUSD: 0,
  },
  {
    id: "deepseek",
    label: "DeepSeek V4",
    baseURL: "https://api.deepseek.com/v1",
    model: "deepseek-v4",
    maxDailyUSD: 2,
  },
  {
    id: "openai",
    label: "OpenAI (GPT-6)",
    baseURL: "https://api.openai.com/v1",
    model: "gpt-6.1-terra",
    maxDailyUSD: 3,
  },
  {
    id: "openrouter",
    label: "OpenRouter (Claude 5.5)",
    baseURL: "https://openrouter.ai/api/v1",
    model: "anthropic/claude-opus-5.5",
    maxDailyUSD: 3,
  },
  {
    id: "gemini",
    label: "Gemini (OpenAI API)",
    baseURL: "https://generativelanguage.googleapis.com/v1beta/openai",
    model: "gemini-3.8-flash",
    maxDailyUSD: 2,
  },
  {
    id: "groq",
    label: "Groq (Llama 4)",
    baseURL: "https://api.groq.com/openai/v1",
    model: "llama4-maverick:17b",
    maxDailyUSD: 1,
  },
  {
    id: "together",
    label: "Together (Qwen 3.8)",
    baseURL: "https://api.together.xyz/v1",
    model: "Qwen/Qwen3.8-Coder-32B",
    maxDailyUSD: 2,
  },
];

export function LlmSpyPage() {
  const [conversations, setConversations] = useState<ConversationRow[]>([]);
  const [personas, setPersonas] = useState<PersonaRow[]>([]);
  const [budget, setBudget] = useState<{ spent_today_usd: number; cap_usd: number }>({
    spent_today_usd: 0,
    cap_usd: 0,
  });

  // Runtime Upstream LLM Config state
  const [settings, setSettings] = useState<LLMSettings | null>(null);
  const [baseURL, setBaseURL] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [clearKeyFlag, setClearKeyFlag] = useState(false);
  const [upstreamModel, setUpstreamModel] = useState("deepseek-v4");
  const [maxDailyUSD, setMaxDailyUSD] = useState(0);
  const [allowUnauthChat, setAllowUnauthChat] = useState(false);
  const [savingSettings, setSavingSettings] = useState(false);
  const [testingConn, setTestingConn] = useState(false);
  const [testResult, setTestResult] = useState<LLMTestResult | null>(null);

  // Persona editor state
  const [pattern, setPattern] = useState("gpt-6*");
  const [vendor, setVendor] = useState("openai");
  const [prompt, setPrompt] = useState(
    "You are GPT-6 Astra, OpenAI's flagship reasoning model on an internal enterprise gateway. Never leak internal routing."
  );
  const [antiLeak, setAntiLeak] = useState("qwen,deepseek,gemini,claude,llama,honeypot,cowrie");
  const [degradeMode, setDegradeMode] = useState("slow_tarpit");
  const [maxDaily, setMaxDaily] = useState(5);
  const [maxTokens, setMaxTokens] = useState(512);

  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const applySettingsToForm = (s: LLMSettings) => {
    setSettings(s);
    setBaseURL(s.base_url ?? "");
    setUpstreamModel(s.model || "deepseek-v4");
    setMaxDailyUSD(s.max_daily_usd ?? 0);
    setAllowUnauthChat(Boolean(s.allow_unauthenticated_chat));
    setApiKeyInput("");
    setClearKeyFlag(false);
  };

  const loadAll = async () => {
    try {
      const [cRes, pRes, bRes, sRes] = await Promise.all([
        apiFetch<{ conversations: ConversationRow[] }>("/api/admin/llm/conversations"),
        apiFetch<{ personas: PersonaRow[] }>("/api/admin/llm/personas"),
        apiFetch<{ spent_today_usd: number; cap_usd: number }>("/api/admin/llm/budget"),
        apiFetch<LLMSettings>("/api/admin/llm/settings"),
      ]);
      setConversations(cRes.conversations ?? []);
      setPersonas(pRes.personas ?? []);
      setBudget(bRes);
      if (sRes && typeof sRes === "object" && "model" in sRes) {
        applySettingsToForm(sRes);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to load LLM Spy data");
    }
  };

  useEffect(() => {
    void loadAll();
  }, []);

  const applyPreset = (p: (typeof PROVIDER_PRESETS)[number]) => {
    setBaseURL(p.baseURL);
    setUpstreamModel(p.model);
    setMaxDailyUSD(p.maxDailyUSD);
    if (p.id === "builtin") {
      setClearKeyFlag(true);
      setApiKeyInput("");
    } else {
      setClearKeyFlag(false);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setMsg("");
    setSavingSettings(true);
    try {
      const updated = await apiFetch<LLMSettings>("/api/admin/llm/settings", {
        method: "PUT",
        body: JSON.stringify({
          base_url: baseURL.trim(),
          api_key: apiKeyInput.trim(),
          clear_api_key: clearKeyFlag,
          model: upstreamModel.trim(),
          max_daily_usd: Number(maxDailyUSD),
          allow_unauthenticated_chat: allowUnauthChat,
        }),
      });
      applySettingsToForm(updated);
      setBudget((b) => ({ ...b, cap_usd: updated.max_daily_usd, spent_today_usd: updated.spent_today_usd }));
      setMsg(
        updated.active_mode === "live_upstream"
          ? `Saved live upstream LLM settings (${updated.model}, cap $${updated.max_daily_usd}/day)`
          : "Saved $0 Built-in Simulator mode cleanly"
      );
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Failed to save LLM settings");
    } finally {
      setSavingSettings(false);
    }
  };

  const handleTestConnection = async () => {
    setErr("");
    setTestingConn(true);
    setTestResult(null);
    try {
      const res = await apiFetch<LLMTestResult>("/api/admin/llm/test", {
        method: "POST",
        body: JSON.stringify({ prompt: "Say OK and report status." }),
      });
      setTestResult(res);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Test connection failed");
    } finally {
      setTestingConn(false);
    }
  };

  const selectPersona = (p: PersonaRow) => {
    setPattern(p.model_pattern);
    setVendor(p.vendor_family);
    setPrompt(p.system_prompt);
    setAntiLeak((p.anti_leak_terms ?? []).join(","));
    setDegradeMode(p.degrade_mode || "slow_tarpit");
    setMaxDaily(p.max_daily_usd || 5);
    setMaxTokens(p.max_tokens_cap || 512);
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

  const capVal = budget.cap_usd ?? settings?.max_daily_usd ?? 0;
  const spentVal = budget.spent_today_usd ?? settings?.spent_today_usd ?? 0;
  const pct = capVal > 0 ? Math.min(100, Math.round((spentVal / capVal) * 100)) : 0;

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

      {/* Upstream LLM Provider Configuration */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-blue-500" />
            Upstream LLM Provider Configuration
          </span>
        }
        subtitle="Để trống nếu muốn chạy hoàn toàn miễn phí ($0 Built-in Simulator), hoặc dán API Key (DeepSeek, OpenRouter, OpenAI, Groq, Gemini) để trả lời hacker bằng model thật với giới hạn USD/ngày."
        action={
          <Badge tone={settings?.active_mode === "live_upstream" ? "success" : "info"}>
            {settings?.active_mode === "live_upstream" ? "Live Upstream Active" : "$0 Built-in Simulator"}
          </Badge>
        }
      >
        <div className="space-y-4">
          {/* Quick Provider Presets */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">Presets:</span>
            {PROVIDER_PRESETS.map((p) => (
              <Button
                key={p.id}
                type="button"
                variant="secondary"
                className="px-2.5 py-1 text-xs"
                onClick={() => applyPreset(p)}
              >
                {p.label}
              </Button>
            ))}
          </div>

          <form onSubmit={handleSaveSettings} className="space-y-4">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>OpenAI-Compatible Base URL</span>
                <Input
                  value={baseURL}
                  onChange={(e) => setBaseURL(e.target.value)}
                  placeholder="https://api.deepseek.com/v1"
                />
              </label>

              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <div className="flex items-center justify-between">
                  <span>API Key (AES-GCM encrypted in DB)</span>
                  {settings?.has_api_key && !clearKeyFlag && (
                    <Badge tone="success">{settings.api_key_masked}</Badge>
                  )}
                </div>
                <div className="flex gap-1.5">
                  <Input
                    type="password"
                    value={apiKeyInput}
                    onChange={(e) => {
                      setApiKeyInput(e.target.value);
                      if (e.target.value) setClearKeyFlag(false);
                    }}
                    placeholder={
                      settings?.has_api_key && !clearKeyFlag
                        ? "Keep existing key or paste new sk-..."
                        : "sk-..."
                    }
                  />
                  {settings?.has_api_key && !clearKeyFlag && (
                    <Button
                      type="button"
                      variant="ghost"
                      className="shrink-0 px-2 py-1 text-xs text-rose-600"
                      title="Clear saved API key"
                      onClick={() => {
                        setClearKeyFlag(true);
                        setApiKeyInput("");
                      }}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              </label>

              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>Upstream Model</span>
                <Input
                  value={upstreamModel}
                  onChange={(e) => setUpstreamModel(e.target.value)}
                  placeholder="deepseek-v4 / gpt-6-astra / claude-opus-5-5"
                />
              </label>

              <label className="space-y-1 text-xs font-medium text-[var(--text-secondary)]">
                <span>Max Daily Budget ($ USD)</span>
                <Input
                  type="number"
                  step="0.5"
                  min={0}
                  value={maxDailyUSD}
                  onChange={(e) => setMaxDailyUSD(Number(e.target.value))}
                />
              </label>
            </div>

            <label className="flex items-start gap-2.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-3 text-xs text-[var(--text-secondary)]">
              <input
                type="checkbox"
                checked={allowUnauthChat}
                onChange={(e) => setAllowUnauthChat(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-slate-400"
              />
              <span>
                <strong className="text-[var(--text-primary)]">
                  Cho phép dùng AI thật cho cả Ollama (:11434) &amp; LiteLLM (:4000) không cần Canary key
                </strong>{" "}
                — mặc định chỉ khi hacker dùng Canary key mới gọi upstream trả phí; bật tuỳ chọn này nếu bạn muốn bot
                hỏi trực tiếp Ollama `/api/chat` cũng nhận câu trả lời AI thật (vẫn khoá cứng theo trần USD/ngày).
              </span>
            </label>

            <div className="flex flex-wrap items-center gap-2.5">
              <Button type="submit" disabled={savingSettings}>
                <Save className="h-4 w-4" /> {savingSettings ? "Saving..." : "Save Settings"}
              </Button>
              <Button type="button" variant="secondary" disabled={testingConn} onClick={handleTestConnection}>
                <FlaskConical className="h-4 w-4" /> {testingConn ? "Testing..." : "Test AI Connection"}
              </Button>
            </div>
          </form>

          {testResult && (
            <div
              className={`rounded-xl border p-3.5 text-xs ${
                testResult.error
                  ? "border-rose-300 bg-rose-50 text-rose-900 dark:border-rose-800 dark:bg-rose-950/50 dark:text-rose-200"
                  : "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200"
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2 font-semibold">
                <span className="flex items-center gap-1.5">
                  <CheckCircle2 className="h-4 w-4" />
                  Mode: {testResult.mode} · Model: {testResult.model}
                </span>
                <span>{testResult.latency_ms} ms</span>
              </div>
              <div className="mt-1.5 font-mono">
                {testResult.error ? `Error: ${testResult.error}` : testResult.reply}
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Circuit Breaker Budget Card */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <DollarSign className="h-4 w-4 text-emerald-500" />
            Upstream Chameleon LLM Budget Cap
          </span>
        }
        subtitle="Redis atomic circuit breaker switches to zero-cost tarpit once daily spend hits cap."
      >
        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <span className="font-semibold tabular-nums text-[var(--text-primary)]">
            ${spentVal.toFixed(4)} spent today
          </span>
          <span className="text-xs text-[var(--text-muted)]">
            Cap: ${capVal.toFixed(2)} / day {capVal === 0 ? "($0 Simulator Only)" : ""}
          </span>
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
            title="No AI chat prompts captured yet"
            description="When an attacker POSTs a chat prompt to :11434/api/chat or :4000/v1/chat/completions, full prompts and decoy replies appear here (GET /api/tags & /v1/models scans appear in Incidents & Replays -> Ollama & AI)."
          />
        ) : (
          <div className="space-y-3">
            {conversations.map((c) => (
              <div key={c.id} className="hp-subtle space-y-2 rounded-xl border p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <Bot className="h-4 w-4 text-blue-500" />
                    <span className="font-mono text-sm font-semibold text-[var(--text-primary)]">{c.source_ip}</span>
                    <Badge tone="info">{c.api_dialect}</Badge>
                    <Badge>{c.requested_model}</Badge>
                    <Badge>{c.degraded_mode}</Badge>
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
                <Select value={degradeMode} onChange={(e) => setDegradeMode(e.target.value)}>
                  <option value="slow_tarpit">slow_tarpit</option>
                  <option value="rate_limit_429">rate_limit_429</option>
                </Select>
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
