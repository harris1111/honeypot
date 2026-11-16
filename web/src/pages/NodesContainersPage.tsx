import { useEffect, useState } from "react";
import { Plus, RefreshCw, ShieldAlert, Square, Terminal } from "lucide-react";
import { apiFetch } from "../lib/api";
import { Badge, Button, Card, CopyButton, EmptyState, Input, Select } from "../components/ui/primitives";

interface NodeRow {
  id: string;
  name: string;
  region: string;
  public_ipv4: string;
  cert_serial: string;
  cert_expires_at: string;
  agent_version: string;
  status: string;
  last_heartbeat_at: string;
}

interface TrapRow {
  id: string;
  node_id: string;
  trap_kind: string;
  container_name: string;
  image: string;
  listen_port: number;
  protocol: string;
  desired_state: string;
  actual_state: string;
  updated_at: string;
}

const BUILTIN_CVE_PACKS = [
  { id: "CVE-2025-29927", label: "Next.js Middleware Auth Bypass" },
  { id: "CVE-2024-4577", label: "PHP-CGI Argument Injection RCE" },
  { id: "CVE-2021-44228", label: "Apache Log4Shell JNDI" },
  { id: "CVE-2025-32433", label: "Erlang/OTP SSH Pre-Auth RCE" },
  { id: "CVE-2024-6387", label: "OpenSSH regreSSHion" },
  { id: "CVE-2025-55182", label: "React Server Functions Desync" },
  { id: "CVE-2024-23897", label: "Jenkins CLI Arbitrary File Read" },
  { id: "CVE-2025-31324", label: "SAP NetWeaver Visual Composer" },
];

export function NodesContainersPage() {
  const [nodes, setNodes] = useState<NodeRow[]>([]);
  const [traps, setTraps] = useState<TrapRow[]>([]);
  const [statusMsg, setStatusMsg] = useState("");
  const [errMsg, setErrMsg] = useState("");

  // Enroll Remote Node state
  const [joinName, setJoinName] = useState("edge-sensor-02");
  const [joinRegion, setJoinRegion] = useState("us-east");
  const [joinRole, setJoinRole] = useState("sensor");
  const [joinResult, setJoinResult] = useState<{ join_token: string; install_cmd: string } | null>(null);

  // Deploy Trap state
  const [depNodeId, setDepNodeId] = useState("");
  const [depKind, setDepKind] = useState("cowrie");
  const [depName, setDepName] = useState("hp-trap-cowrie-ssh");
  const [depPort, setDepPort] = useState(22);

  // Safe PoC Preflight state
  const [pocIP, setPocIP] = useState("");
  const [pocHost, setPocHost] = useState("http://127.0.0.1:80");
  const [pocCVE, setPocCVE] = useState("CVE-2025-29927");
  const [pocCurl, setPocCurl] = useState("");

  const refresh = async () => {
    try {
      const [nRes, tRes] = await Promise.all([
        apiFetch<{ nodes: NodeRow[] }>("/api/admin/nodes"),
        apiFetch<{ traps: TrapRow[] }>("/api/admin/traps"),
      ]);
      const list = nRes.nodes ?? [];
      setNodes(list);
      setTraps(tRes.traps ?? []);
      if (!depNodeId && list.length > 0) {
        setDepNodeId(list[0].id);
      }
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : "Failed to load nodes and traps");
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const createJoinToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrMsg("");
    try {
      const res = await apiFetch<{ join_token: string; install_cmd: string }>("/api/admin/nodes/join-token", {
        method: "POST",
        body: JSON.stringify({ name: joinName, region: joinRegion, role: joinRole }),
      });
      setJoinResult(res);
      setStatusMsg(`Minted one-time join token for ${joinName}`);
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : "Join token generation failed");
    }
  };

  const deployTrap = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrMsg("");
    try {
      await apiFetch("/api/admin/traps/deploy", {
        method: "POST",
        body: JSON.stringify({
          node_id: depNodeId,
          trap_kind: depKind,
          container_name: depName,
          image: depKind === "heralding" ? "honeypot/heralding:24.04.2" : "honeypot/cowrie:latest",
          listen_port: Number(depPort),
          protocol: "tcp",
          config_json: "{}",
        }),
      });
      setStatusMsg(`Deploy command queued for ${depName}`);
      await refresh();
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : "Deploy failed");
    }
  };

  const nodeAction = async (id: string, action: "rotate-cert" | "revoke") => {
    setErrMsg("");
    try {
      await apiFetch(`/api/admin/nodes/${encodeURIComponent(id)}/${action}`, { method: "POST" });
      setStatusMsg(`Node ${action} triggered`);
      await refresh();
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : `Node ${action} failed`);
    }
  };

  const trapAction = async (id: string, action: "logs" | "restart" | "stop") => {
    setErrMsg("");
    try {
      await apiFetch(`/api/admin/traps/${encodeURIComponent(id)}/${action}`, { method: "POST" });
      setStatusMsg(`Trap ${action} dispatched`);
      await refresh();
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : `Trap ${action} failed`);
    }
  };

  const toggleCVE = async (cveId: string, enabled: boolean) => {
    setErrMsg("");
    try {
      await apiFetch("/api/admin/cves/toggle", {
        method: "POST",
        body: JSON.stringify({ node_id: "all", cve_id: cveId, enabled }),
      });
      setStatusMsg(`${cveId} ${enabled ? "enabled" : "disabled"} across sensors`);
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : "CVE toggle failed");
    }
  };

  const runPoCPreflight = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrMsg("");
    setPocCurl("");
    try {
      const res = await apiFetch<{ allowlisted: boolean; curl?: string }>("/api/admin/traps/poc-preflight", {
        method: "POST",
        body: JSON.stringify({ operator_ip: pocIP, sensor_host: pocHost, cve_id: pocCVE }),
      });
      if (res.curl) setPocCurl(res.curl);
    } catch (e) {
      setErrMsg(e instanceof Error ? e.message : "PoC preflight failed");
    }
  };

  return (
    <div className="space-y-6">
      {statusMsg && (
        <div className="rounded-lg border border-emerald-300 bg-emerald-50 px-4 py-2.5 text-sm text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-200">
          {statusMsg}
        </div>
      )}
      {errMsg && (
        <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-2.5 text-sm text-rose-900 dark:border-rose-800 dark:bg-rose-950/50 dark:text-rose-200">
          {errMsg}
        </div>
      )}

      {/* Sensor Architecture Explainer */}
      <div className="hp-subtle rounded-xl border p-4 text-sm text-[var(--text-secondary)]">
        <strong className="text-[var(--text-primary)]">How your sensors work:</strong> Each enrolled node runs two
        hardened Docker traps (<strong>Cowrie</strong> on <code className="font-mono">:22 / :23</code> for SSH &amp;
        Telnet plus <strong>Heralding</strong> on <code className="font-mono">:21 / :25 / :110 / :143</code>) alongside
        high-interaction Go L7 decoys for HTTP CVEs, Docker API, K8s Kubelet, MySQL, Postgres, Redis, and Ollama/LiteLLM.
      </div>

      {/* Connected Sensor Nodes */}
      <Card title={`Connected Sensor Nodes (${nodes.length})`} subtitle="mTLS 1.3 leaf certificates with automatic rotation.">
        {nodes.length === 0 ? (
          <EmptyState
            title="No sensors enrolled yet"
            description="Mint a one-time join token in the Enroll Remote Node card below and run sensor-agent on your VPS."
          />
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {nodes.map((n) => (
              <div key={n.id} className="hp-subtle rounded-xl border p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-base font-semibold text-[var(--text-primary)]">{n.name}</div>
                    <div className="font-mono text-xs text-[var(--text-muted)]">
                      {n.public_ipv4 || "unknown IP"} · {n.region}
                    </div>
                  </div>
                  <Badge tone={n.status === "online" ? "success" : "warning"}>{n.status}</Badge>
                </div>
                <div className="text-xs text-[var(--text-muted)]">
                  Last heartbeat: {n.last_heartbeat_at || "never"} · Cert expires: {n.cert_expires_at || "—"}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="secondary" className="px-2.5 py-1 text-xs" onClick={() => void nodeAction(n.id, "rotate-cert")}>
                    <RefreshCw className="h-3.5 w-3.5" /> Rotate Cert
                  </Button>
                  <Button variant="danger" className="px-2.5 py-1 text-xs" onClick={() => void nodeAction(n.id, "revoke")}>
                    <ShieldAlert className="h-3.5 w-3.5" /> Revoke
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Container Traps Table & Quick Deploy */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2" title={`Docker Trap Containers (${traps.length})`} subtitle="Managed strictly via docker-guard-proxy allowlist.">
          {traps.length === 0 ? (
            <EmptyState
              title="No Docker trap containers deployed"
              description="Deploy Cowrie SSH/Telnet or Heralding FTP/Mail traps using the form on the right."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-sm">
                <thead>
                  <tr className="border-b border-[var(--border-subtle)] text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                    <th className="py-2 pr-3">Container</th>
                    <th className="py-2 pr-3">Image</th>
                    <th className="py-2 pr-3">Port</th>
                    <th className="py-2 pr-3">State</th>
                    <th className="py-2 text-right">Controls</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[var(--border-subtle)]">
                  {traps.map((t) => (
                    <tr key={t.id}>
                      <td className="py-3 pr-3 font-mono text-xs font-semibold text-[var(--text-primary)]">{t.container_name}</td>
                      <td className="py-3 pr-3 font-mono text-xs text-[var(--text-secondary)]">{t.image}</td>
                      <td className="py-3 pr-3 font-mono text-xs text-[var(--text-primary)]">
                        {t.listen_port}/{t.protocol}
                      </td>
                      <td className="py-3 pr-3">
                        <Badge tone={t.actual_state === "running" ? "success" : "warning"}>{t.actual_state}</Badge>
                      </td>
                      <td className="py-3 text-right">
                        <div className="inline-flex gap-1.5">
                          <Button variant="ghost" className="px-2 py-1 text-xs" onClick={() => void trapAction(t.id, "logs")}>
                            <Terminal className="h-3.5 w-3.5" /> Logs
                          </Button>
                          <Button variant="secondary" className="px-2 py-1 text-xs" onClick={() => void trapAction(t.id, "restart")}>
                            Restart
                          </Button>
                          <Button variant="danger" className="px-2 py-1 text-xs" onClick={() => void trapAction(t.id, "stop")}>
                            <Square className="h-3 w-3" /> Stop
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>

        <Card title="Deploy Container Trap" subtitle="Push a Cowrie or Heralding container to an active sensor.">
          <form onSubmit={deployTrap} className="space-y-3">
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Target Node</span>
              <Select value={depNodeId} onChange={(e) => setDepNodeId(e.target.value)} required>
                <option value="">Select sensor node...</option>
                {nodes.map((n) => (
                  <option key={n.id} value={n.id}>
                    {n.name} ({n.public_ipv4 || n.region})
                  </option>
                ))}
              </Select>
            </label>
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Trap Profile</span>
              <Select
                value={depKind}
                onChange={(e) => {
                  const k = e.target.value;
                  setDepKind(k);
                  setDepName(k === "heralding" ? "hp-trap-heralding-ftp" : "hp-trap-cowrie-ssh");
                  setDepPort(k === "heralding" ? 21 : 22);
                }}
              >
                <option value="cowrie">cowrie (SSH :22 + Telnet :23)</option>
                <option value="heralding">heralding (FTP/SMTP/POP3/IMAP)</option>
              </Select>
            </label>
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Container Name</span>
              <Input value={depName} onChange={(e) => setDepName(e.target.value)} required />
            </label>
            <label className="block space-y-1 text-xs font-medium text-[var(--text-secondary)]">
              <span>Primary Host Port</span>
              <Input type="number" value={depPort} onChange={(e) => setDepPort(Number(e.target.value))} required />
            </label>
            <Button type="submit" className="w-full" disabled={!depNodeId}>
              <Plus className="h-4 w-4" /> Deploy Trap
            </Button>
          </form>
        </Card>
      </div>

      {/* CVE Packs & Safe PoC Preflight + Enroll Remote Node */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <Card title="CVE Decoy Packs & Safe PoC Self-Test" subtitle="Verify detections using an allowlisted operator IP.">
          <div className="mb-4 flex flex-wrap gap-2">
            {BUILTIN_CVE_PACKS.map((cve) => (
              <div
                key={cve.id}
                className="hp-subtle flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs"
              >
                <span className="font-mono font-semibold text-[var(--text-primary)]">{cve.id}</span>
                <button
                  type="button"
                  onClick={() => void toggleCVE(cve.id, true)}
                  className="text-emerald-600 hover:underline dark:text-emerald-400"
                >
                  On
                </button>
                <button
                  type="button"
                  onClick={() => void toggleCVE(cve.id, false)}
                  className="text-rose-600 hover:underline dark:text-rose-400"
                >
                  Off
                </button>
              </div>
            ))}
          </div>

          <form onSubmit={runPoCPreflight} className="space-y-3 border-t border-[var(--border-subtle)] pt-4">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <Input
                value={pocIP}
                onChange={(e) => setPocIP(e.target.value)}
                placeholder="Your Public IP (operator_ip)"
              />
              <Input
                value={pocHost}
                onChange={(e) => setPocHost(e.target.value)}
                placeholder="Sensor URL (e.g. http://ip:80)"
              />
              <Select value={pocCVE} onChange={(e) => setPocCVE(e.target.value)}>
                <option value="CVE-2025-29927">CVE-2025-29927</option>
                <option value="CVE-2024-4577">CVE-2024-4577</option>
                <option value="CVE-2021-44228">CVE-2021-44228</option>
              </Select>
            </div>
            <Button type="submit" variant="secondary">
              Check Allowlist &amp; Generate Safe PoC Command
            </Button>
            {pocCurl && (
              <div className="flex items-center justify-between gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-3 font-mono text-xs text-[var(--text-primary)]">
                <span className="break-all">{pocCurl}</span>
                <CopyButton value={pocCurl} />
              </div>
            )}
          </form>
        </Card>

        <Card>
          <header className="mb-4">
            <h2 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">Enroll Remote Node</h2>
            <p className="mt-0.5 text-sm text-[var(--text-muted)]">
              Generate a short-lived bootstrap token to connect a new VPS sensor or Nginx Guard over mTLS.
            </p>
          </header>
          <form onSubmit={createJoinToken} className="space-y-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
              <Input value={joinName} onChange={(e) => setJoinName(e.target.value)} placeholder="Node name" required />
              <Input value={joinRegion} onChange={(e) => setJoinRegion(e.target.value)} placeholder="Region" required />
              <Select value={joinRole} onChange={(e) => setJoinRole(e.target.value)}>
                <option value="sensor">sensor</option>
                <option value="nginx_guard">nginx_guard</option>
              </Select>
            </div>
            <Button type="submit">Mint One-Time Join Token</Button>
          </form>
          {joinResult && (
            <div className="mt-4 space-y-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] p-3 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold text-[var(--text-primary)]">Enrollment Command</span>
                <CopyButton value={joinResult.install_cmd} />
              </div>
              <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[var(--text-secondary)]">
                {joinResult.install_cmd}
              </pre>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
