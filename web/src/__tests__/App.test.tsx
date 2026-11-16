import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";

function mockJsonResponse(body: unknown, status = 200) {
  return Promise.resolve(
    new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  );
}

describe("Hive Admin Console UI & XSS Safety", () => {
  beforeEach(() => {
    const store = new Map<string, string>();
    const memoryStorage: Storage = {
      get length() {
        return store.size;
      },
      clear: () => store.clear(),
      getItem: (k: string) => store.get(k) ?? null,
      key: (i: number) => Array.from(store.keys())[i] ?? null,
      removeItem: (k: string) => {
        store.delete(k);
      },
      setItem: (k: string, v: string) => {
        store.set(k, String(v));
      },
    };
    Object.defineProperty(globalThis, "localStorage", { value: memoryStorage, configurable: true, writable: true });
    Object.defineProperty(window, "localStorage", { value: memoryStorage, configurable: true, writable: true });
    document.documentElement.classList.remove("dark");
    vi.restoreAllMocks();
    (globalThis as any).WebSocket = class {
      close() {}
    };
  });

  afterEach(() => {
    cleanup();
  });

  function installAuthenticatedFetchMock() {
    vi.spyOn(globalThis, "fetch").mockImplementation((input: RequestInfo | URL) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.includes("/api/admin/auth/status")) {
        return mockJsonResponse({
          initialized: true,
          logged_in: true,
          username: "operator",
          csrf_token: "test-csrf-token",
        });
      }
      if (url.includes("/api/admin/overview")) {
        return mockJsonResponse({
          events_24h: 42,
          ssh_sessions_24h: 3,
          open_incidents: 2,
          pending_triage: 1,
          malware_count: 1,
          canary_hits: 3,
          llm_spent_usd: 0.12,
          top_cves: [{ cve_id: "CVE-2025-29927", count: 14 }],
          events_by_trap: [
            { trap_kind: "cowrie", count: 28 },
            { trap_kind: "webcve", count: 14 },
          ],
          top_ips: [{ ip: "198.51.100.77", count: 28, country_code: "US" }],
          recent_ssh_sessions: [
            {
              id: "r1",
              source_ip: "198.51.100.77",
              username: "root",
              auth_succeeded: true,
              commands: ["uname -a", "cat /var/www/app/.env"],
              duration_ms: 1400,
              started_at: "2026-11-16T10:00:00Z",
            },
          ],
        });
      }
      if (url.includes("/api/admin/nodes")) return mockJsonResponse({ nodes: [] });
      if (url.includes("/api/admin/traps")) return mockJsonResponse({ traps: [] });
      if (url.includes("/api/admin/guard/decisions")) return mockJsonResponse({ decisions: [] });
      if (url.includes("/api/admin/guard/allowlist")) return mockJsonResponse({ allowlist: [] });
      if (url.includes("/api/admin/guard/rules")) return mockJsonResponse({ rules: [] });
      if (url.includes("/api/admin/guard/waf-expr")) return mockJsonResponse({ expression: "", enterprise_enabled: false });
      if (url.includes("/api/admin/audit-logs")) return mockJsonResponse({ logs: [] });
      if (url.includes("/api/admin/incidents")) return mockJsonResponse({ incidents: [] });
      if (url.includes("/api/admin/telemetry")) {
        return mockJsonResponse({
          events: [
            {
              id: "ev1",
              source_ip: "203.0.113.9",
              dest_port: 80,
              protocol: "http",
              trap_kind: "webcve",
              persona: "nextjs",
              cve_id: "CVE-2025-29927",
              is_kev: true,
              ja4: "t13d00_test",
              hassh: "",
              http_method: "GET",
              http_path: "<img src=x onerror=alert(1)>",
              raw_payload: "GET <img src=x onerror=alert(1)> HTTP/1.1",
              response_summary: "trapped",
              severity_score: 90,
              observed_at: "2026-11-16T10:00:00Z",
            },
          ],
          replays: [],
        });
      }
      if (url.includes("/api/admin/llm/conversations")) return mockJsonResponse({ conversations: [] });
      if (url.includes("/api/admin/llm/personas")) return mockJsonResponse({ personas: [] });
      if (url.includes("/api/admin/llm/budget")) return mockJsonResponse({ spent_today_usd: 0, cap_usd: 5 });
      if (url.includes("/api/admin/canaries")) return mockJsonResponse({ canaries: [] });
      if (url.includes("/api/admin/malware")) {
        return mockJsonResponse({
          artifacts: [
            {
              sha256: "a".repeat(64),
              md5: "b".repeat(32),
              file_size: 128,
              mime_type: "text/x-sh",
              source_urls: ["http://evil.c2.invalid/kinsing.sh"],
              yara_matches: ["Shell_Payload"],
              vt_malicious: 0,
              vt_total: 0,
              seen_count: 1,
              first_seen_at: "2026-11-16T10:00:00Z",
              last_seen_at: "2026-11-16T10:00:00Z",
            },
          ],
        });
      }
      return mockJsonResponse({});
    });
  }

  it("renders navigation, escapes attacker payloads without XSS, and toggles Light/Dark theme", async () => {
    installAuthenticatedFetchMock();
    render(<App />);

    await waitFor(() => expect(screen.getByText("DECEPTION HIVE")).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText(/uname -a/)).toBeInTheDocument());

    // Light / Dark theme toggle
    const toggleBtn = screen.getByTestId("theme-toggle");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    fireEvent.click(toggleBtn);
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem("hp_theme")).toBe("dark");
    fireEvent.click(toggleBtn);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(localStorage.getItem("hp_theme")).toBe("light");

    fireEvent.click(screen.getByText("Nodes & Traps"));
    await waitFor(() => expect(screen.getByText("Enroll Remote Node")).toBeInTheDocument());

    fireEvent.click(screen.getByText("Active Guard"));
    await waitFor(() => expect(screen.getByText(/Zero Blind Auto-Ban Default/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("Incidents & Replays"));
    await waitFor(() => expect(screen.getByText(/<img src=x onerror=alert\(1\)>/i)).toBeInTheDocument());
    expect(document.querySelectorAll("img").length).toBe(0);

    fireEvent.click(screen.getByText("LLM Spy & Studio"));
    await waitFor(() => expect(screen.getByText(/Chameleon Persona Studio/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("Canary Factory"));
    await waitFor(() => expect(screen.getByText(/Mint Signed Traceable Canary Keys/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("Malware Vault"));
    await waitFor(() => expect(screen.getByText("http://evil.c2.invalid/kinsing.sh")).toBeInTheDocument());
    const urlEl = screen.getByText("http://evil.c2.invalid/kinsing.sh");
    expect(urlEl.closest("a")).toBeNull();
  });
});
