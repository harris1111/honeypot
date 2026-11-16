import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import App from "../App";

function mockJson(data: unknown) {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    })
  );
}

describe("Hive Admin Console 7 Screens & XSS Hardening", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    (globalThis as any).WebSocket = undefined;
  });

  it("renders all 7 navigation screens and escapes XSS/malicious URLs safely", async () => {
    const fetchMock = vi.fn((url: RequestInfo | URL) => {
      const s = String(url);
      if (s.includes("/api/admin/auth/status")) {
        return mockJson({ initialized: true, logged_in: true, username: "operator", csrf_token: "csrf-1" });
      }
      if (s.includes("/api/admin/overview")) {
        return mockJson({ events_24h: 12, open_incidents: 2, pending_triage: 1, malware_count: 1, canary_hits: 3, llm_spent_usd: 0.42, top_cves: [] });
      }
      if (s.includes("/api/admin/telemetry")) {
        return mockJson({
          events: [{
            id: "ev-1", source_ip: "198.51.100.1", trap_kind: "webcve", cve_id: "CVE-2025-29927", is_kev: true,
            http_method: "POST", http_path: "/admin", raw_payload: "<img src=x onerror=alert(1)>", severity_score: 95,
          }],
          replays: [],
        });
      }
      if (s.includes("/api/admin/malware")) {
        return mockJson({
          artifacts: [{
            sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            yara_matches: ["Kinsing_Golang_Malware"],
            vt_malicious: 20, vt_total: 60, seen_count: 4,
            source_urls: ["http://evil.c2.invalid/kinsing.sh"],
          }],
        });
      }
      return mockJson({ nodes: [], traps: [], decisions: [], allowlist: [], rules: [], incidents: [], conversations: [], personas: [], canaries: [] });
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    await waitFor(() => expect(screen.getByText("DECEPTION HIVE")).toBeInTheDocument());

    // Switch through all 7 tabs
    fireEvent.click(screen.getByText("Nodes & Traps"));
    await waitFor(() => expect(screen.getByText(/Enroll Remote Node/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("Active Guard"));
    await waitFor(() => expect(screen.getByText(/Zero Blind Auto-Ban Default/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("Incidents & Replays"));
    await waitFor(() => expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument());
    expect(document.querySelectorAll("img").length).toBe(0);

    fireEvent.click(screen.getByText("LLM Spy & Studio"));
    await waitFor(() => expect(screen.getByText(/Chameleon Persona Studio/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("Canary Factory"));
    await waitFor(() => expect(screen.getByText(/Mint Signed Traceable Canary Keys/)).toBeInTheDocument());

    fireEvent.click(screen.getByText("Malware Vault"));
    await waitFor(() => expect(screen.getByText("http://evil.c2.invalid/kinsing.sh")).toBeInTheDocument());
    // Ensure malicious C2 URL is NOT rendered as a clickable external anchor
    const evilLink = document.querySelector('a[href="http://evil.c2.invalid/kinsing.sh"]');
    expect(evilLink).toBeNull();
  });
});
