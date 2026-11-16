import React from "react";

export function Card({ title, subtitle, actions, children, className = "" }: {
  title?: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`rounded-xl border border-slate-800 bg-slate-900/75 p-4 shadow-sm ${className}`}>
      {(title || actions) && (
        <div className="mb-3 flex items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
          <div>
            {title && <h2 className="text-sm font-semibold text-slate-100">{title}</h2>}
            {subtitle && <p className="text-xs text-slate-400">{subtitle}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Badge({ children, tone = "slate" }: {
  children: React.ReactNode;
  tone?: "slate" | "emerald" | "amber" | "red" | "cyan" | "purple";
}) {
  const styles: Record<string, string> = {
    slate: "bg-slate-800 text-slate-200 border-slate-700",
    emerald: "bg-emerald-950/70 text-emerald-300 border-emerald-800",
    amber: "bg-amber-950/70 text-amber-300 border-amber-800",
    red: "bg-red-950/70 text-red-300 border-red-800",
    cyan: "bg-cyan-950/70 text-cyan-300 border-cyan-800",
    purple: "bg-purple-950/70 text-purple-300 border-purple-800",
  };
  return (
    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium ${styles[tone]}`}>
      {children}
    </span>
  );
}

export function Button({ children, variant = "primary", className = "", ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
}) {
  const styles: Record<string, string> = {
    primary: "bg-cyan-600 hover:bg-cyan-500 text-white",
    secondary: "bg-slate-800 hover:bg-slate-700 text-slate-100 border border-slate-700",
    danger: "bg-red-700 hover:bg-red-600 text-white",
    ghost: "hover:bg-slate-800 text-slate-300",
  };
  return (
    <button
      {...props}
      className={`inline-flex items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition disabled:opacity-50 ${styles[variant]} ${className}`}
    >
      {children}
    </button>
  );
}
