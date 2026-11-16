let csrfToken = "";

export function setCSRFToken(tok: string) {
  csrfToken = tok;
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const method = (init.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD" && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const res = await fetch(path, { ...init, headers, credentials: "same-origin" });
  const text = await res.text();
  let parsed: any = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { error: text };
  }
  if (!res.ok) {
    throw new Error(parsed.error || `HTTP ${res.status}`);
  }
  return parsed as T;
}

export interface AuthStatus {
  initialized: boolean;
  logged_in: boolean;
  username: string;
  csrf_token: string;
}

export interface LiveEventTick {
  event_uuid: string;
  source_ip: string;
  trap_kind: string;
  persona: string;
  cve_id: string;
  is_kev: boolean;
  http_path: string;
  severity: number;
  observed: string;
}
