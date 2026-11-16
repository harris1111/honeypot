import { useEffect, useMemo, useState } from "react";
import { FastForward, Pause, Play, RotateCcw, SkipBack, SkipForward, Terminal, X } from "lucide-react";
import { apiFetch } from "../lib/api";
import { Badge, Button, CopyButton } from "./ui/primitives";

interface ReplayDetail {
  id: string;
  source_ip: string;
  hassh: string;
  username: string;
  auth_succeeded: boolean;
  commands: string[];
  asciicast_v2: string;
  duration_ms: number;
  started_at: string;
}

interface ParsedFrame {
  offsetSec: number;
  text: string;
}

function parseAsciicastFrames(cast: string, fallbackCommands: string[], sourceIP: string, username: string): ParsedFrame[] {
  const frames: ParsedFrame[] = [];
  if (cast && cast.trim() !== "") {
    const lines = cast.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      if (i === 0 && line.startsWith("{")) continue; // header JSON
      try {
        const arr = JSON.parse(line);
        if (Array.isArray(arr) && arr.length >= 3 && arr[1] === "o" && typeof arr[2] === "string") {
          const t = typeof arr[0] === "number" && Number.isFinite(arr[0]) ? Math.max(0, arr[0]) : 0;
          if (arr[2].length > 0) {
            frames.push({ offsetSec: t, text: arr[2] });
          }
        }
      } catch {
        // Ignore malformed frame lines safely.
      }
    }
  }

  // Fallback synthesis if recording has minimal frames but recorded commands exist
  if (frames.length <= 1 && fallbackCommands.length > 0) {
    const promptUser = username?.trim() || "root";
    const prompt = `${promptUser}@prod-ai-gw-01:~# `;
    const out: ParsedFrame[] = [{ offsetSec: 0, text: `Connected from ${sourceIP}\r\n` }];
    fallbackCommands.forEach((cmd, idx) => {
      out.push({ offsetSec: (idx + 1) * 0.45, text: `${prompt}${cmd}\r\n` });
    });
    return out;
  }

  return frames;
}

function normalizeDisplayText(chunks: string[]): string {
  return chunks.join("").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}

export function TerminalReplayModal({
  replayId,
  onClose,
}: {
  replayId: string;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<ReplayDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const [stepIdx, setStepIdx] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [paceMode, setPaceMode] = useState<"smart" | "1x" | "2x" | "4x">("smart");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setErr("");
    setDetail(null);
    setStepIdx(0);

    apiFetch<ReplayDetail>(`/api/admin/replays/${encodeURIComponent(replayId)}`)
      .then((res) => {
        if (cancelled) return;
        setDetail(res);
        setLoading(false);
        const totalFrames = parseAsciicastFrames(
          res.asciicast_v2,
          res.commands ?? [],
          res.source_ip,
          res.username
        ).length;
        setStepIdx(totalFrames > 0 ? 1 : 0);
        setPlaying(totalFrames > 1);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e instanceof Error ? e.message : "Failed to load SSH replay");
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [replayId]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const frames = useMemo(() => {
    if (!detail) return [];
    return parseAsciicastFrames(detail.asciicast_v2, detail.commands ?? [], detail.source_ip, detail.username);
  }, [detail]);

  useEffect(() => {
    if (!playing || frames.length === 0 || stepIdx >= frames.length) {
      if (stepIdx >= frames.length && frames.length > 0 && playing) {
        setPlaying(false);
      }
      return;
    }

    let delayMs = 380;
    if (paceMode !== "smart") {
      const prevTime = stepIdx > 0 ? frames[stepIdx - 1].offsetSec : 0;
      const nextTime = frames[stepIdx]?.offsetSec ?? prevTime;
      const deltaSec = Math.max(0.05, Math.min(2.5, nextTime - prevTime));
      const speedMult = paceMode === "4x" ? 4 : paceMode === "2x" ? 2 : 1;
      delayMs = Math.max(40, Math.round((deltaSec * 1000) / speedMult));
    }

    const timer = window.setTimeout(() => {
      setStepIdx((prev) => Math.min(frames.length, prev + 1));
    }, delayMs);

    return () => window.clearTimeout(timer);
  }, [playing, stepIdx, frames, paceMode]);

  const visibleOutput = useMemo(
    () => normalizeDisplayText(frames.slice(0, stepIdx).map((f) => f.text)),
    [frames, stepIdx]
  );

  const commandsText = (detail?.commands ?? []).join("\n");

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 p-3 backdrop-blur-xs sm:p-6"
      onClick={onClose}
      data-testid="terminal-replay-modal"
      role="dialog"
      aria-modal="true"
      aria-label="SSH Terminal Session Replay"
    >
      <div
        className="hp-surface flex max-h-[92vh] w-full max-w-5xl flex-col overflow-hidden rounded-2xl border shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <header className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border-subtle)] px-5 py-4">
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <Terminal className="h-4 w-4 text-emerald-500" />
              <h2 className="text-base font-bold text-[var(--text-primary)]">
                SSH / Telnet Terminal Replay {detail ? `— ${detail.source_ip}` : ""}
              </h2>
              {detail && (
                <>
                  <Badge tone="info">user: {detail.username || "root"}</Badge>
                  <Badge tone={detail.auth_succeeded ? "success" : "warning"}>
                    {detail.auth_succeeded ? "Auth Succeeded" : "Auth Attempt"}
                  </Badge>
                </>
              )}
            </div>
            {detail && (
              <div className="text-xs text-[var(--text-muted)]">
                HASSH: <code className="font-mono">{detail.hassh || "n/a"}</code> · Duration:{" "}
                <span className="tabular-nums">{(detail.duration_ms / 1000).toFixed(2)}s</span> · Started:{" "}
                {detail.started_at}
              </div>
            )}
          </div>
          <Button type="button" variant="ghost" className="px-2.5 py-1.5 text-xs" onClick={onClose}>
            <X className="h-4 w-4" /> Close
          </Button>
        </header>

        {/* Modal Body */}
        <div className="flex-1 space-y-4 overflow-y-auto p-5">
          {loading && <div className="py-10 text-center text-sm text-[var(--text-muted)]">Loading SSH terminal recording...</div>}
          {err && (
            <div className="rounded-lg border border-rose-300 bg-rose-50 px-4 py-3 text-sm text-rose-800 dark:border-rose-800 dark:bg-rose-950/60 dark:text-rose-200">
              {err}
            </div>
          )}

          {!loading && !err && detail && (
            <>
              {/* Executed Commands Summary */}
              <div className="hp-subtle rounded-xl border p-3.5">
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
                    Captured Shell Commands ({detail.commands?.length ?? 0})
                  </span>
                  {commandsText && <CopyButton value={commandsText} label="Copy Commands" />}
                </div>
                {detail.commands && detail.commands.length > 0 ? (
                  <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                    {detail.commands.map((cmd, idx) => (
                      <code
                        key={idx}
                        className="max-w-full break-all rounded-md border border-[var(--border-subtle)] bg-[var(--bg-surface)] px-2 py-0.5 font-mono text-xs text-[var(--text-primary)]"
                      >
                        $ {cmd}
                      </code>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs text-[var(--text-muted)]">Session opened without typed commands.</div>
                )}
              </div>

              {/* Terminal Viewport */}
              <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#090f1a] shadow-inner">
                <div className="flex items-center justify-between border-b border-slate-800 bg-slate-900/90 px-4 py-2 text-xs text-slate-300">
                  <div className="flex items-center gap-2 font-mono">
                    <span className="h-2.5 w-2.5 rounded-full bg-rose-500" />
                    <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
                    <span className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
                    <span className="ml-2 text-slate-400">
                      {detail.username || "root"}@prod-ai-gw-01
                    </span>
                  </div>
                  <span className="font-mono tabular-nums text-slate-400">
                    Step {stepIdx} / {frames.length}
                  </span>
                </div>
                <pre className="h-80 overflow-auto whitespace-pre-wrap break-all p-4 font-mono text-xs leading-relaxed text-emerald-300 sm:text-[13px]">
                  {visibleOutput || "(No terminal output frames recorded for this session)"}
                </pre>
              </div>

              {/* Player Controls */}
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex flex-wrap items-center gap-1.5">
                  <Button
                    type="button"
                    variant="primary"
                    className="px-3 py-1.5 text-xs"
                    disabled={frames.length === 0}
                    onClick={() => {
                      if (stepIdx >= frames.length) {
                        setStepIdx(1);
                        setPlaying(true);
                      } else {
                        setPlaying((p) => !p);
                      }
                    }}
                  >
                    {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
                    {playing ? "Pause" : stepIdx >= frames.length ? "Play Again" : "Play"}
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    className="px-2.5 py-1.5 text-xs"
                    disabled={frames.length === 0}
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx(1);
                    }}
                  >
                    <RotateCcw className="h-3.5 w-3.5" /> Restart
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    className="px-2.5 py-1.5 text-xs"
                    disabled={stepIdx <= 1}
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx((s) => Math.max(1, s - 1));
                    }}
                  >
                    <SkipBack className="h-3.5 w-3.5" /> Prev
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    className="px-2.5 py-1.5 text-xs"
                    disabled={stepIdx >= frames.length}
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx((s) => Math.min(frames.length, s + 1));
                    }}
                  >
                    <SkipForward className="h-3.5 w-3.5" /> Next
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    className="px-2.5 py-1.5 text-xs"
                    disabled={frames.length === 0}
                    onClick={() => {
                      setPlaying(false);
                      setStepIdx(frames.length);
                    }}
                  >
                    <FastForward className="h-3.5 w-3.5" /> Show All
                  </Button>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-medium text-[var(--text-muted)]">Speed:</span>
                  {(
                    [
                      { id: "smart", label: "Smart Pace" },
                      { id: "1x", label: "1x" },
                      { id: "2x", label: "2x" },
                      { id: "4x", label: "4x" },
                    ] as const
                  ).map((m) => (
                    <button
                      key={m.id}
                      type="button"
                      onClick={() => setPaceMode(m.id)}
                      className={`rounded-md border px-2 py-1 text-xs font-medium transition ${
                        paceMode === m.id
                          ? "border-blue-600 bg-blue-600 text-white"
                          : "border-[var(--border-subtle)] bg-[var(--bg-subtle)] text-[var(--text-secondary)]"
                      }`}
                    >
                      {m.label}
                    </button>
                  ))}
                </div>
              </div>

              {frames.length > 1 && (
                <input
                  type="range"
                  min={1}
                  max={frames.length}
                  value={Math.max(1, stepIdx)}
                  onChange={(e) => {
                    setPlaying(false);
                    setStepIdx(Number(e.target.value));
                  }}
                  aria-label="Replay frame position"
                  className="w-full accent-blue-600"
                />
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
