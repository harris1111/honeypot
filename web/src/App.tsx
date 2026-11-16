import { useEffect, useState } from "react";
import { Shield, Server, Activity, Terminal, Bot, KeyRound, Bug, LogOut } from "lucide-react";
import { apiFetch, AuthStatus, LiveEventTick, setCSRFToken } from "./lib/api";
import { Button, Card } from "./components/ui/primitives";
import { OverviewPage } from "./pages/OverviewPage";
import { NodesContainersPage } from "./pages/NodesContainersPage";
import { ActiveGuardPage } from "./pages/ActiveGuardPage";
import { IncidentsExplorerPage } from "./pages/IncidentsExplorerPage";
import { LlmSpyPage } from "./pages/LlmSpyPage";
import { CanaryFactoryPage } from "./pages/CanaryFactoryPage";
import { MalwareVaultPage } from "./pages/MalwareVaultPage";

type TabKey = "overview" | "nodes" | "guard" | "incidents" | "llm" | "canary" | "malware";

const TABS: { key: TabKey; label: string; Icon: any }[] = [
  { key: "overview", label: "Overview", Icon: Activity },
  { key: "nodes", label: "Nodes & Traps", Icon: Server },
  { key: "guard", label: "Active Guard", Icon: Shield },
  { key: "incidents", label: "Incidents & Replays", Icon: Terminal },
  { key: "llm", label: "LLM Spy & Studio", Icon: Bot },
  { key: "canary", label: "Canary Factory", Icon: KeyRound },
  { key: "malware", label: "Malware Vault", Icon: Bug },
];

export function App() {
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [tab, setTab] = useState<TabKey>("overview");
  const [username, setUsername] = useState("operator");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [setupInfo, setSetupInfo] = useState<{ totp_uri: string; totp_secret: string } | null>(null);
  const [errMsg, setErrMsg] = useState("");
  const [liveFeed, setLiveFeed] = useState<LiveEventTick[]>([]);

  const checkStatus = () => {
    apiFetch<AuthStatus>("/api/admin/auth/status")
      .then((s) => {
        if (s.csrf_token) setCSRFToken(s.csrf_token);
        setAuth(s);
      })
      .catch(() => setAuth({ initialized: false, logged_in: false, username: "", csrf_token: "" }));
  };

  useEffect(checkStatus, []);

  useEffect(() => {
    if (!auth?.logged_in || typeof WebSocket === "undefined") return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/admin/ws`);
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === "telemetry_batch" && Array.isArray(msg.events)) {
          setLiveFeed((prev) => [...msg.events.reverse(), ...prev].slice(0, 60));
        }
      } catch {
        // ignore malformed tick
      }
    };
    return () => ws.close();
  }, [auth?.logged_in]);

  const handleSetup = async () => {
    setErrMsg("");
    try {
      const res = await apiFetch<any>("/api/admin/auth/setup", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      setSetupInfo(res);
      checkStatus();
    } catch (e: any) {
      setErrMsg(e.message);
    }
  };

  const handleLogin = async () => {
    setErrMsg("");
    try {
      const res = await apiFetch<any>("/api/admin/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password, totp_code: totpCode }),
      });
      setCSRFToken(res.csrf_token);
      setSetupInfo(null);
      checkStatus();
    } catch (e: any) {
      setErrMsg(e.message);
    }
  };

  const handleLogout = async () => {
    await apiFetch("/api/admin/auth/logout", { method: "POST" });
    setCSRFToken("");
    checkStatus();
  };

  if (!auth) {
    return <div className="flex min-h-screen items-center justify-center text-sm text-slate-400">Connecting to Hive Admin Console...</div>;
  }

  if (!auth.logged_in) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-950 p-4">
        <Card
          title={!auth.initialized ? "Initialize Hive Operator (Argon2id + TOTP 2FA)" : "Hive Private Admin Login"}
          subtitle="Private Loopback / VPN Interface Only (:8443)"
          className="w-full max-w-md"
        >
          <div className="space-y-3 text-xs">
            {errMsg && <div className="rounded border border-red-800 bg-red-950/60 p-2 text-red-200">{errMsg}</div>}
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Username"
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password (>= 8 chars)"
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            />
            {auth.initialized && (
              <input
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                placeholder="6-digit TOTP 2FA code"
                className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 font-mono"
              />
            )}
            {setupInfo && (
              <div className="rounded border border-emerald-800 bg-emerald-950/40 p-2.5 text-emerald-200">
                <div className="font-semibold">Save this TOTP Secret in your authenticator:</div>
                <div className="mt-1 font-mono">{setupInfo.totp_secret}</div>
              </div>
            )}
            <div className="flex gap-2">
              {!auth.initialized ? (
                <Button onClick={handleSetup} className="w-full">Create Operator &amp; Generate TOTP</Button>
              ) : (
                <Button onClick={handleLogin} className="w-full">Authenticate with 2FA</Button>
              )}
            </div>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-slate-950 text-slate-100">
      <aside className="flex w-60 flex-col border-r border-slate-800 bg-slate-900/60 p-3">
        <div className="mb-4 px-2">
          <div className="text-sm font-bold tracking-tight text-cyan-400">DECEPTION HIVE</div>
          <div className="text-xs text-slate-500">Zero-Exposure Console</div>
        </div>
        <nav className="flex-1 space-y-1">
          {TABS.map(({ key, label, Icon }) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={`flex w-full items-center gap-2 rounded-lg px-3 py-2 text-left text-xs font-medium transition ${
                tab === key ? "bg-cyan-600/20 text-cyan-300 border border-cyan-800/60" : "text-slate-300 hover:bg-slate-800"
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </nav>
        <div className="border-t border-slate-800 pt-3">
          <div className="mb-2 px-2 text-xs text-slate-400">Operator: {auth.username}</div>
          <Button variant="ghost" onClick={handleLogout} className="w-full justify-start">
            <LogOut className="h-4 w-4" /> Logout
          </Button>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto p-6">
        {tab === "overview" && <OverviewPage liveFeed={liveFeed} />}
        {tab === "nodes" && <NodesContainersPage />}
        {tab === "guard" && <ActiveGuardPage />}
        {tab === "incidents" && <IncidentsExplorerPage />}
        {tab === "llm" && <LlmSpyPage />}
        {tab === "canary" && <CanaryFactoryPage />}
        {tab === "malware" && <MalwareVaultPage />}
      </main>
    </div>
  );
}

export default App;
