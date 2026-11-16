import { useEffect, useState } from "react";
import { Card, Badge, Button } from "../components/ui/primitives";
import { apiFetch } from "../lib/api";

const KEV_LIST = [
  "CVE-2025-29927", "CVE-2025-55182", "CVE-2024-34351", "CVE-2025-31125", "CVE-2026-111497",
  "CVE-2024-4577", "CVE-2026-109618", "CVE-2021-3129", "CVE-2017-9841", "CVE-2021-41773",
  "CVE-2026-119977", "CVE-2022-22947", "CVE-2021-44228",
];

export function NodesContainersPage() {
  const [nodes, setNodes] = useState<any[]>([]);
  const [traps, setTraps] = useState<any[]>([]);
  const [nodeName, setNodeName] = useState("vps-sg-01");
  const [role, setRole] = useState("sensor");
  const [joinCmd, setJoinCmd] = useState("");
  const [operatorIP, setOperatorIP] = useState("");
  const [pocCurl, setPocCurl] = useState("");
  const [pocErr, setPocErr] = useState("");
  const [enabledCVEs, setEnabledCVEs] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(KEV_LIST.map((c) => [c, true]))
  );

  const load = () => {
    apiFetch<any>("/api/admin/nodes").then((d) => setNodes(d.nodes || [])).catch(() => {});
    apiFetch<any>("/api/admin/traps").then((d) => setTraps(d.traps || [])).catch(() => {});
  };
  useEffect(load, []);

  const createToken = async () => {
    const res = await apiFetch<any>("/api/admin/nodes/join-token", {
      method: "POST",
      body: JSON.stringify({ name: nodeName, role, region: "ap-southeast-1" }),
    });
    setJoinCmd(res.install_cmd);
  };

  const revokeNode = async (id: string) => {
    await apiFetch(`/api/admin/nodes/${id}/revoke`, { method: "POST" });
    load();
  };

  const toggleCVE = async (cve: string) => {
    const next = !enabledCVEs[cve];
    await apiFetch("/api/admin/cves/toggle", {
      method: "POST",
      body: JSON.stringify({ node_id: "all", cve_id: cve, enabled: next }),
    });
    setEnabledCVEs((prev) => ({ ...prev, [cve]: next }));
  };

  const generatePoC = async (cveID: string) => {
    setPocErr("");
    try {
      const res = await apiFetch<any>("/api/admin/traps/poc-preflight", {
        method: "POST",
        body: JSON.stringify({ cve_id: cveID, operator_ip: operatorIP, sensor_host: "http://sensor-public-ip" }),
      });
      setPocCurl(res.curl);
    } catch (e: any) {
      setPocErr(e.message || "Allowlist preflight blocked PoC");
    }
  };

  return (
    <div className="space-y-4">
      <Card title="Enroll Remote Node (mTLS 1.3 over :9443 — Zero VPN Required)">
        <div className="flex flex-wrap items-center gap-2">
          <input
            value={nodeName}
            onChange={(e) => setNodeName(e.target.value)}
            placeholder="Node name"
            className="rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs"
          />
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="rounded border border-slate-700 bg-slate-950 px-2.5 py-1.5 text-xs"
          >
            <option value="sensor">Sensor Node</option>
            <option value="nginx_guard">Nginx Guard Agent</option>
          </select>
          <Button onClick={createToken}>Generate Join Command</Button>
        </div>
        {joinCmd && (
          <pre className="mt-3 overflow-x-auto rounded border border-slate-800 bg-slate-950 p-2.5 text-xs text-emerald-300">
            <code>{joinCmd}</code>
          </pre>
        )}
      </Card>

      <Card title="Connected Sensor &amp; Guard Nodes">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-2">Name</th><th>IPv4</th><th>Status</th><th>Cert Serial</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr key={n.id} className="border-b border-slate-900">
                  <td className="py-2 font-medium text-slate-100">{n.name}</td>
                  <td className="font-mono">{n.public_ipv4 || "-"}</td>
                  <td><Badge tone={n.status === "online" ? "emerald" : n.status === "revoked" ? "red" : "amber"}>{n.status}</Badge></td>
                  <td className="font-mono text-slate-400">{n.cert_serial}</td>
                  <td className="flex gap-1.5 py-2">
                    <Button variant="secondary" onClick={() => apiFetch(`/api/admin/nodes/${n.id}/rotate-cert`, { method: "POST" })}>Rotate Cert</Button>
                    <Button variant="danger" onClick={() => revokeNode(n.id)}>Revoke Cert</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title="Trap Deployments &amp; Remote Container Orchestrator">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-800 text-slate-400">
              <tr><th className="py-2">Kind</th><th>Container / Service</th><th>Port</th><th>State</th><th>Controls</th></tr>
            </thead>
            <tbody>
              {traps.map((t) => (
                <tr key={t.id} className="border-b border-slate-900">
                  <td className="py-2"><Badge tone="cyan">{t.trap_kind}</Badge></td>
                  <td className="font-mono">{t.container_name}</td>
                  <td>{t.listen_port}/{t.protocol}</td>
                  <td>{t.actual_state}</td>
                  <td className="flex gap-1.5 py-2">
                    <Button variant="secondary" onClick={() => apiFetch(`/api/admin/traps/${t.id}/restart`, { method: "POST" }).then(load)}>Restart</Button>
                    <Button variant="danger" onClick={() => apiFetch(`/api/admin/traps/${t.id}/stop`, { method: "POST" }).then(load)}>Stop</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card
        title="CVE / KEV Pack Switchboard &amp; Allowlist-Verified PoC Self-Test"
        actions={
          <input
            value={operatorIP}
            onChange={(e) => setOperatorIP(e.target.value)}
            placeholder="Your public IP (for allowlist check)"
            className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-xs"
          />
        }
      >
        <div className="flex flex-wrap gap-2">
          {KEV_LIST.map((cve) => (
            <div key={cve} className="flex items-center gap-1.5 rounded border border-slate-800 bg-slate-950/70 px-2 py-1 text-xs">
              <button onClick={() => toggleCVE(cve)} className={enabledCVEs[cve] ? "text-emerald-300" : "text-slate-500 line-through"}>
                {cve}
              </button>
              <button onClick={() => generatePoC(cve)} className="text-cyan-400 hover:underline">PoC</button>
            </div>
          ))}
        </div>
        {pocErr && <div className="mt-2 rounded border border-red-800 bg-red-950/50 p-2 text-xs text-red-300">{pocErr}</div>}
        {pocCurl && <pre className="mt-2 overflow-x-auto rounded bg-slate-950 p-2 text-xs text-cyan-300"><code>{pocCurl}</code></pre>}
      </Card>
    </div>
  );
}
