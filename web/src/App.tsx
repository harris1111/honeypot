import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  Biohazard,
  Bot,
  KeyRound,
  LogOut,
  Menu,
  Moon,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  Sun,
  Terminal,
  X,
} from "lucide-react";
import { apiFetch, setCSRFToken, type AuthStatus, type LiveEventTick } from "./lib/api";
import { Badge, Button, Card, CopyButton, Input } from "./components/ui/primitives";
import { OverviewPage } from "./pages/OverviewPage";
import { NodesContainersPage } from "./pages/NodesContainersPage";
import { IncidentsExplorerPage } from "./pages/IncidentsExplorerPage";
import { ActiveGuardPage } from "./pages/ActiveGuardPage";
import { LlmSpyPage } from "./pages/LlmSpyPage";
import { CanaryFactoryPage } from "./pages/CanaryFactoryPage";
import { MalwareVaultPage } from "./pages/MalwareVaultPage";

export type NavTab =
  | "Overview"
  | "Incidents & Replays"
  | "Nodes & Traps"
  | "Canary Factory"
  | "LLM Spy & Studio"
  | "Active Guard"
  | "Malware Vault";

type ThemeMode = "light" | "dark";

interface NavGroup {
  group: string;
  items: {
    id: NavTab;
    label: string;
    subtitle: string;
    icon: typeof Activity;
  }[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    group: "Monitor",
    items: [
      {
        id: "Overview",
        label: "Overview",
        subtitle: "24h trap activity, recent SSH sessions, top attacker IPs & quick triage stats",
        icon: Activity,
      },
      {
        id: "Incidents & Replays",
        label: "Incidents & Replays",
        subtitle: "SSH commands typed by intruders, asciinema terminal playbacks, raw payloads & campaigns",
        icon: Terminal,
      },
    ],
  },
  {
    group: "Deception & Lures",
    items: [
      {
        id: "Nodes & Traps",
        label: "Nodes & Traps",
        subtitle: "Sensor health, Cowrie/Heralding trap containers, CVE packs & safe PoC self-tests",
        icon: Server,
      },
      {
        id: "Canary Factory",
        label: "Canary Factory",
        subtitle: "Mint traceable OpenAI/Anthropic honey keys & copyable .env lure snippets",
        icon: KeyRound,
      },
      {
        id: "LLM Spy & Studio",
        label: "LLM Spy & Studio",
        subtitle: "Fake AI gateway transcripts, probe detections & Chameleon model persona prompts",
        icon: Bot,
      },
    ],
  },
  {
    group: "Defense & Forensics",
    items: [
      {
        id: "Active Guard",
        label: "Active Guard",
        subtitle: "Human-approved IP/JA4 bans, protected CIDR allowlist, policy rules & Cloudflare WAF",
        icon: ShieldAlert,
      },
      {
        id: "Malware Vault",
        label: "Malware Vault",
        subtitle: "Quarantined payloads captured from downloads, YARA hits & encrypted ZIP export",
        icon: Biohazard,
      },
    ],
  },
];

function getInitialTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem("hp_theme");
    if (saved === "light" || saved === "dark") {
      return saved;
    }
    if (typeof window !== "undefined" && window.matchMedia?.("(prefers-color-scheme: dark)").matches) {
      return "dark";
    }
  } catch {
    // Ignore storage access errors.
  }
  return "light";
}

function applyTheme(mode: ThemeMode) {
  if (typeof document !== "undefined") {
    document.documentElement.classList.toggle("dark", mode === "dark");
    document.documentElement.dataset.theme = mode;
  }
  try {
    localStorage.setItem("hp_theme", mode);
  } catch {
    // Ignore storage errors.
  }
}

export function ThemeToggle({ theme, onToggle }: { theme: ThemeMode; onToggle: () => void }) {
  const isDark = theme === "dark";
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-label={isDark ? "Switch to Light theme" : "Switch to Dark theme"}
      data-testid="theme-toggle"
      className="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-2.5 py-1.5 text-xs font-medium text-[var(--text-secondary)] transition hover:border-[var(--border-strong)] hover:text-[var(--text-primary)]"
    >
      {isDark ? <Sun className="h-3.5 w-3.5 text-amber-400" /> : <Moon className="h-3.5 w-3.5 text-blue-600" />}
      <span>{isDark ? "Light" : "Dark"}</span>
    </button>
  );
}

export default function App() {
  const [theme, setTheme] = useState<ThemeMode>(() => getInitialTheme());
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [tab, setTab] = useState<NavTab>("Overview");
  const [selectedReplayId, setSelectedReplayId] = useState<string>("");
  const [liveEvents, setLiveEvents] = useState<LiveEventTick[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const [tickerOpen, setTickerOpen] = useState(false);

  const [username, setUsername] = useState("operator");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [setupResult, setSetupResult] = useState<{ totp_secret: string; totp_uri: string } | null>(null);
  const [authError, setAuthError] = useState("");
  const [authBusy, setAuthBusy] = useState(false);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const toggleTheme = () => setTheme((prev) => (prev === "dark" ? "light" : "dark"));

  const loadStatus = async () => {
    try {
      const s = await apiFetch<AuthStatus>("/api/admin/auth/status");
      if (s.csrf_token) setCSRFToken(s.csrf_token);
      setAuth(s);
    } catch {
      setAuth({ initialized: true, logged_in: false, username: "", csrf_token: "" });
    }
  };

  useEffect(() => {
    void loadStatus();
  }, []);

  useEffect(() => {
    if (!auth?.logged_in || typeof WebSocket === "undefined") {
      setWsConnected(false);
      return;
    }
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}/api/admin/ws`);
    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onmessage = (msg) => {
      try {
        const tick = JSON.parse(msg.data) as LiveEventTick;
        setLiveEvents((prev) => [tick, ...prev].slice(0, 20));
      } catch {
        // Ignore malformed ticks.
      }
    };
    return () => ws.close();
  }, [auth?.logged_in]);

  const handleSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setAuthBusy(true);
    try {
      const res = await apiFetch<{ totp_secret: string; totp_uri: string }>("/api/admin/auth/setup", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setSetupResult(res);
      await loadStatus();
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Setup failed");
    } finally {
      setAuthBusy(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError("");
    setAuthBusy(true);
    try {
      const res = await apiFetch<{ csrf_token: string }>("/api/admin/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password, totp_code: totpCode }),
      });
      setCSRFToken(res.csrf_token);
      setTotpCode("");
      await loadStatus();
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Login failed");
    } finally {
      setAuthBusy(false);
    }
  };

  const handleLogout = async () => {
    await apiFetch("/api/admin/auth/logout", { method: "POST" });
    setCSRFToken("");
    await loadStatus();
  };

  const activeNavMeta = useMemo(
    () => NAV_GROUPS.flatMap((g) => g.items).find((item) => item.id === tab) ?? NAV_GROUPS[0].items[0],
    [tab]
  );

  const openReplay = (replayId: string) => {
    setSelectedReplayId(replayId);
    setTab("Incidents & Replays");
  };

  if (!auth) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6 text-sm text-[var(--text-muted)]">
        Connecting to Hive Admin Console...
      </div>
    );
  }

  if (!auth.logged_in) {
    return (
      <div className="relative flex min-h-screen items-center justify-center px-4 py-10">
        <div className="absolute right-6 top-6">
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
        </div>
        <Card className="w-full max-w-md p-6">
          <div className="mb-5 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-blue-600/15 text-blue-600 dark:text-blue-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-[var(--text-primary)]">DECEPTION HIVE</h1>
              <p className="text-sm text-[var(--text-muted)]">
                {auth.initialized
                  ? "Sign in with your operator password and authenticator code."
                  : "First-time setup: create the primary operator account."}
              </p>
            </div>
          </div>

          {authError && (
            <div className="mb-4 rounded-lg border border-rose-300 bg-rose-50 px-3 py-2 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200">
              {authError}
            </div>
          )}

          {setupResult && (
            <div className="mb-4 space-y-2 rounded-lg border border-emerald-300 bg-emerald-50 p-3.5 text-sm text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200">
              <div className="font-semibold">Account created — save your TOTP key</div>
              <p className="text-xs opacity-90">
                Add this Base32 secret to Google Authenticator, 1Password, or Bitwarden before signing in:
              </p>
              <div className="flex items-center justify-between gap-2 rounded-md border border-emerald-200 bg-white/80 px-2.5 py-1.5 font-mono text-xs text-slate-900 dark:border-emerald-800 dark:bg-slate-950/70 dark:text-emerald-100">
                <span className="truncate select-all">{setupResult.totp_secret}</span>
                <CopyButton value={setupResult.totp_secret} label="Copy key" />
              </div>
            </div>
          )}

          <form onSubmit={auth.initialized ? handleLogin : handleSetup} className="space-y-3.5">
            <label className="block space-y-1 text-sm">
              <span className="font-medium text-[var(--text-secondary)]">Username</span>
              <Input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" required />
            </label>
            <label className="block space-y-1 text-sm">
              <span className="font-medium text-[var(--text-secondary)]">Password</span>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={auth.initialized ? "current-password" : "new-password"}
                placeholder={auth.initialized ? "Enter password" : "Minimum 8 characters"}
                required
              />
            </label>
            {auth.initialized && (
              <label className="block space-y-1 text-sm">
                <span className="font-medium text-[var(--text-secondary)]">6-Digit Authenticator Code (TOTP)</span>
                <Input
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  inputMode="numeric"
                  placeholder="123456"
                  required
                />
              </label>
            )}
            <Button type="submit" className="w-full" disabled={authBusy}>
              {authBusy ? "Please wait..." : auth.initialized ? "Sign In" : "Create Operator Account"}
            </Button>
          </form>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col lg:flex-row">
      {/* Mobile Sidebar Backdrop */}
      {mobileNavOpen && (
        <div
          className="fixed inset-0 z-30 bg-slate-950/50 lg:hidden"
          onClick={() => setMobileNavOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Left Sidebar Navigation */}
      <aside
        className={`hp-surface fixed inset-y-0 left-0 z-40 flex w-72 shrink-0 flex-col border-r transition-transform lg:static lg:translate-x-0 ${
          mobileNavOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-600 text-white shadow-xs">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-wide text-[var(--text-primary)]">DECEPTION HIVE</div>
              <div className="text-xs text-[var(--text-muted)]">Threat Telemetry &amp; Defense</div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => setMobileNavOpen(false)}
            className="rounded-md p-1 text-[var(--text-muted)] hover:bg-[var(--bg-subtle)] lg:hidden"
            aria-label="Close navigation"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4" aria-label="Primary Navigation">
          {NAV_GROUPS.map((grp) => (
            <div key={grp.group}>
              <div className="mb-1.5 px-3 text-xs font-semibold uppercase tracking-wider text-[var(--text-muted)]">
                {grp.group}
              </div>
              <div className="space-y-1">
                {grp.items.map((item) => {
                  const Icon = item.icon;
                  const active = tab === item.id;
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setTab(item.id);
                        setMobileNavOpen(false);
                      }}
                      className={`flex w-full items-center gap-2.5 rounded-lg px-3 py-2.5 text-left text-sm font-medium transition ${
                        active
                          ? "bg-blue-600/12 text-blue-700 dark:bg-blue-500/20 dark:text-blue-200"
                          : "text-[var(--text-secondary)] hover:bg-[var(--bg-subtle)] hover:text-[var(--text-primary)]"
                      }`}
                    >
                      <Icon
                        className={`h-4 w-4 shrink-0 ${
                          active ? "text-blue-600 dark:text-blue-400" : "text-[var(--text-muted)]"
                        }`}
                      />
                      <span>{item.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-[var(--border-subtle)] p-4">
          <div className="hp-subtle flex items-center justify-between rounded-lg border px-3 py-2 text-xs">
            <div className="min-w-0">
              <div className="font-semibold text-[var(--text-primary)] truncate">{auth.username || "operator"}</div>
              <div className="text-[var(--text-muted)]">mTLS Hive Operator</div>
            </div>
            <Button variant="ghost" onClick={handleLogout} className="px-2 py-1 text-xs" title="Sign out">
              <LogOut className="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="hp-surface sticky top-0 z-20 flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3.5 sm:px-6">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setMobileNavOpen(true)}
              className="rounded-lg border border-[var(--border-subtle)] p-2 text-[var(--text-secondary)] hover:bg-[var(--bg-subtle)] lg:hidden"
              aria-label="Open navigation"
            >
              <Menu className="h-4 w-4" />
            </button>
            <div>
              <h1 className="text-lg font-bold tracking-tight text-[var(--text-primary)]">{activeNavMeta.label}</h1>
              <p className="text-xs sm:text-sm text-[var(--text-muted)]">{activeNavMeta.subtitle}</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={wsConnected ? "success" : "default"}>
              <span className={`h-2 w-2 rounded-full ${wsConnected ? "bg-emerald-500 animate-pulse" : "bg-slate-400"}`} />
              {wsConnected ? "Live Stream" : "Stream Idle"}
            </Badge>
            <Button
              type="button"
              variant="secondary"
              className="px-2.5 py-1.5 text-xs"
              onClick={() => setTickerOpen((v) => !v)}
            >
              Feed ({liveEvents.length})
            </Button>
            <Button
              type="button"
              variant="secondary"
              className="px-2.5 py-1.5 text-xs"
              onClick={() => setRefreshNonce((n) => n + 1)}
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
            <ThemeToggle theme={theme} onToggle={toggleTheme} />
          </div>
        </header>

        {tickerOpen && (
          <div className="border-b border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-4 py-3 sm:px-6">
            <div className="mb-2 flex items-center justify-between text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
              <span>Live Attack Ticker (latest 20 events)</span>
              <button type="button" onClick={() => setTickerOpen(false)} className="hover:text-[var(--text-primary)]">
                Hide
              </button>
            </div>
            {liveEvents.length === 0 ? (
              <div className="text-xs text-[var(--text-muted)]">Waiting for incoming sensor events on WebSocket stream...</div>
            ) : (
              <div className="flex max-h-40 flex-col gap-1.5 overflow-y-auto">
                {liveEvents.map((ev, idx) => (
                  <div
                    key={`${ev.event_uuid}-${idx}`}
                    className="hp-surface flex flex-wrap items-center justify-between gap-2 rounded-lg border px-3 py-1.5 text-xs"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone={ev.severity >= 80 ? "danger" : ev.severity >= 50 ? "warning" : "info"}>
                        {ev.trap_kind}
                      </Badge>
                      <span className="font-mono font-semibold text-[var(--text-primary)]">{ev.source_ip}</span>
                      <span className="font-mono text-[var(--text-secondary)]">{ev.http_path || ev.cve_id || ev.persona}</span>
                    </div>
                    <span className="text-[var(--text-muted)]">{ev.observed}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <main className="mx-auto w-full max-w-7xl flex-1 p-4 sm:p-6">
          {tab === "Overview" && (
            <OverviewPage
              key={`overview-${refreshNonce}`}
              liveEvents={liveEvents}
              onNavigate={setTab}
              onOpenReplay={openReplay}
            />
          )}
          {tab === "Incidents & Replays" && (
            <IncidentsExplorerPage key={`inc-${refreshNonce}`} initialReplayId={selectedReplayId} />
          )}
          {tab === "Nodes & Traps" && <NodesContainersPage key={`nodes-${refreshNonce}`} />}
          {tab === "Canary Factory" && <CanaryFactoryPage key={`canary-${refreshNonce}`} />}
          {tab === "LLM Spy & Studio" && <LlmSpyPage key={`llm-${refreshNonce}`} />}
          {tab === "Active Guard" && <ActiveGuardPage key={`guard-${refreshNonce}`} />}
          {tab === "Malware Vault" && <MalwareVaultPage key={`malware-${refreshNonce}`} />}
        </main>
      </div>
    </div>
  );
}
