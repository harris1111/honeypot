import { Bot, Database, Globe, KeyRound, ShieldAlert, Terminal, X } from "lucide-react";
import type { NavTab } from "../App";
import { Badge, Button } from "./ui/primitives";

export function QuickGuideModal({
  onClose,
  onNavigate,
  onOpenTrapLogs,
}: {
  onClose: () => void;
  onNavigate: (tab: NavTab) => void;
  onOpenTrapLogs: (trapKind: string) => void;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/65 p-4 backdrop-blur-xs"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Quick Guide"
    >
      <div
        className="hp-surface flex max-h-[90vh] w-full max-w-4xl flex-col overflow-hidden rounded-2xl border shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between border-b border-[var(--border-subtle)] px-5 py-4">
          <div>
            <h2 className="text-base font-bold text-[var(--text-primary)]">
              Hướng dẫn sử dụng Deception Hive Console
            </h2>
            <p className="text-xs text-[var(--text-muted)]">
              Tóm tắt nơi xem log từng loại bẫy, cách cấu hình LLM AI và cách chặn IP an toàn.
            </p>
          </div>
          <Button type="button" variant="ghost" className="px-2 py-1 text-xs" onClick={onClose}>
            <X className="h-4 w-4" /> Đóng
          </Button>
        </header>

        <div className="flex-1 space-y-5 overflow-y-auto p-5 text-sm">
          <div>
            <h3 className="mb-2.5 text-sm font-semibold text-[var(--text-primary)]">
              1. Hệ thống có 5 nhóm bẫy — xem log từng loại ở đâu?
            </h3>
            <p className="mb-3 text-xs text-[var(--text-muted)]">
              Do bot SSH/Telnet thường quét nhiều nhất, trang{" "}
              <strong className="text-[var(--text-primary)]">Incidents &amp; Replays</strong> có sẵn tab lọc riêng
              để bạn xem Ollama, Web CVE, Docker/K8s/DB mà không bị log SSH che khuất:
            </p>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {[
                {
                  icon: Terminal,
                  title: "SSH & Telnet (Cowrie)",
                  ports: ":22, :23",
                  trap: "cowrie",
                  desc: "Ghi lại toàn bộ mật khẩu brute-force, câu lệnh hacker chạy và phát lại terminal (.cast).",
                },
                {
                  icon: Bot,
                  title: "Ollama & LiteLLM AI (Chameleon)",
                  ports: ":11434, :4000, /v1/*",
                  trap: "llmproxy",
                  desc: "Bắt các request hỏi /api/tags, /api/chat, /v1/models, /v1/chat/completions và test key giả.",
                },
                {
                  icon: Globe,
                  title: "Web & CVE Packs",
                  ports: ":80, :443",
                  trap: "webcve",
                  desc: "Bắt exploit Next.js (CVE-2025-29927), PHP-CGI (CVE-2024-4577), Log4Shell, React RSC, /.git/.env.",
                },
                {
                  icon: Database,
                  title: "Docker, Kubernetes & DB",
                  ports: ":2375, :6443, :10250, :3306, :5432, :6379",
                  trap: "infratrap",
                  desc: "Bắt truy cập trái phép Docker socket, Kubelet pods, Redis AUTH, PostgreSQL & MySQL.",
                },
              ].map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.trap} className="hp-subtle flex flex-col justify-between rounded-xl border p-3.5">
                    <div>
                      <div className="flex items-center justify-between gap-2">
                        <span className="flex items-center gap-1.5 font-semibold text-[var(--text-primary)]">
                          <Icon className="h-4 w-4 text-blue-500" />
                          {item.title}
                        </span>
                        <Badge>{item.ports}</Badge>
                      </div>
                      <p className="mt-1.5 text-xs text-[var(--text-secondary)]">{item.desc}</p>
                    </div>
                    <div className="mt-3">
                      <Button
                        type="button"
                        variant="secondary"
                        className="px-2.5 py-1 text-xs"
                        onClick={() => {
                          onOpenTrapLogs(item.trap);
                          onClose();
                        }}
                      >
                        Mở log {item.trap} →
                      </Button>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="mt-2.5 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-[var(--border-subtle)] bg-[var(--bg-subtle)] px-3.5 py-2.5 text-xs">
              <span className="text-[var(--text-secondary)]">
                Ngoài ra còn bẫy <strong>FTP / SMTP / POP3 / IMAP (Heralding)</strong> ở port{" "}
                <code className="font-mono">:21, :25, :110, :143</code> và tab{" "}
                <strong>Non-SSH Only</strong> để gộp tất cả bẫy trừ SSH.
              </span>
              <Button
                type="button"
                variant="secondary"
                className="px-2.5 py-1 text-xs"
                onClick={() => {
                  onOpenTrapLogs("non_ssh");
                  onClose();
                }}
              >
                Xem Non-SSH Only →
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="hp-subtle rounded-xl border p-4 space-y-2">
              <div className="flex items-center gap-2 font-semibold text-[var(--text-primary)]">
                <Bot className="h-4 w-4 text-emerald-500" />
                2. Cách cấu hình AI / LLM (LLM Spy &amp; Studio)
              </div>
              <ul className="list-disc space-y-1 pl-4 text-xs text-[var(--text-secondary)]">
                <li>
                  <strong>Chế độ $0 (mặc định):</strong> Không cần API key — trả về danh sách model giả và câu trả lời
                  giả lập hoặc Slow SSE Tarpit để kìm chân attacker mà tốn <strong>$0</strong>.
                </li>
                <li>
                  <strong>Chế độ dùng AI thật:</strong> Vào mục <strong>LLM Spy &amp; Studio</strong>, chọn preset
                  (DeepSeek, OpenRouter, OpenAI, Gemini...), dán API Key + đặt trần <code>Max Daily USD</code> (ví dụ
                  <code>$2/ngày</code>) rồi bấm <strong>Test AI Connection</strong>.
                </li>
              </ul>
              <Button
                type="button"
                variant="secondary"
                className="px-2.5 py-1 text-xs"
                onClick={() => {
                  onNavigate("LLM Spy & Studio");
                  onClose();
                }}
              >
                Mở cấu hình LLM →
              </Button>
            </div>

            <div className="hp-subtle rounded-xl border p-4 space-y-2">
              <div className="flex items-center gap-2 font-semibold text-[var(--text-primary)]">
                <KeyRound className="h-4 w-4 text-amber-500" />
                3. Canary Key &amp; Active Guard
              </div>
              <ul className="list-disc space-y-1 pl-4 text-xs text-[var(--text-secondary)]">
                <li>
                  Trong SSH trap (<code>/var/www/app/.env</code>, <code>litellm_config.yaml</code>) đã rải sẵn key bẫy.
                  Bạn có thể tạo thêm ở <strong>Canary Factory</strong>; khi attacker mang key này gọi AI gateway, hệ
                  thống tăng hit count và cảnh báo ngay.
                </li>
                <li>
                  <strong>Active Guard</strong> mặc định không tự ban mù — mọi quyết định chặn IP/JA4 đợi bạn bấm
                  Approve ở hàng đợi, và luôn bảo vệ các IP trong Allowlist.
                </li>
              </ul>
              <Button
                type="button"
                variant="secondary"
                className="px-2.5 py-1 text-xs"
                onClick={() => {
                  onNavigate("Active Guard");
                  onClose();
                }}
              >
                <ShieldAlert className="h-3.5 w-3.5" /> Mở Active Guard →
              </Button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
