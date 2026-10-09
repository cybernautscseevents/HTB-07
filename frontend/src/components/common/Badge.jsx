import React from 'react';

export function SeverityBadge({ severity, size = "normal" }) {
  const norm = (severity || "UNKNOWN").toUpperCase();
  
  const styles = {
    CRITICAL: "bg-red-500/15 text-red-400 border border-red-500/30",
    HIGH: "bg-orange-500/15 text-orange-400 border border-orange-500/30",
    MEDIUM: "bg-amber-500/15 text-amber-400 border border-amber-500/30",
    LOW: "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30",
    UNKNOWN: "bg-purple-500/15 text-purple-300 border border-purple-500/35",
    NONE: "bg-slate-700/30 text-slate-400 border border-slate-700",
  };

  const style = styles[norm] || styles.UNKNOWN;
  const padding = size === "sm" ? "px-1.5 py-0.5 text-xs font-semibold" : "px-2.5 py-1 text-xs font-semibold";

  return (
    <span className={`inline-flex items-center gap-1 rounded tracking-wide uppercase font-mono-tech ${padding} ${style}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${
        norm === 'CRITICAL' ? 'bg-red-400' :
        norm === 'HIGH' ? 'bg-orange-400' :
        norm === 'MEDIUM' ? 'bg-amber-400' :
        norm === 'LOW' ? 'bg-cyan-400' :
        norm === 'UNKNOWN' ? 'bg-purple-400' : 'bg-slate-400'
      }`} />
      {norm}
    </span>
  );
}

export function RiskScoreBadge({ score }) {
  let colorStyle = "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
  if (score >= 80) {
    colorStyle = "text-red-400 bg-red-500/15 border-red-500/30";
  } else if (score >= 60) {
    colorStyle = "text-orange-400 bg-orange-500/15 border-orange-500/30";
  } else if (score >= 40) {
    colorStyle = "text-amber-400 bg-amber-500/15 border-amber-500/30";
  } else if (score > 0) {
    colorStyle = "text-cyan-400 bg-cyan-500/15 border-cyan-500/30";
  } else {
    colorStyle = "text-slate-400 bg-slate-800/40 border-slate-700";
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold font-mono-tech border ${colorStyle}`}>
      {score}
    </span>
  );
}

export function AuditStatusBadge({ status }) {
  const norm = (status || "").toUpperCase();
  const styles = {
    GOOD: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    PASS: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    WARNING: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    WARN: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    INCOMPLETE: "bg-red-500/15 text-red-400 border-red-500/30",
    MISSING: "bg-rose-500/15 text-rose-400 border-rose-500/30",
    UNCERTAIN: "bg-purple-500/15 text-purple-300 border-purple-500/30",
  };

  const style = styles[norm] || "bg-slate-700/40 text-slate-300 border-slate-600";

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold tracking-wider uppercase border ${style}`}>
      {norm}
    </span>
  );
}

export function ContextBadge({ value }) {
  let style = "bg-slate-800/60 text-slate-300 border-slate-700";

  if (value === "Production" || value === "Direct") {
    style = "bg-blue-500/10 text-blue-300 border-blue-500/25";
  } else if (value === "Development") {
    style = "bg-slate-700/40 text-slate-400 border-slate-600";
  } else if (value === "Transitive") {
    style = "bg-purple-500/10 text-purple-300 border-purple-500/20";
  } else if (value === "Unknown") {
    style = "bg-amber-500/10 text-amber-300 border-amber-500/30";
  }

  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-mono-tech border ${style}`}>
      {value}
    </span>
  );
}
