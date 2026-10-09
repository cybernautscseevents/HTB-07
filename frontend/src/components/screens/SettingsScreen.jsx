import React, { useState } from 'react';
import { RefreshCwIcon } from '../common/Icons';


export function SettingsScreen({ backendStatus, onRefreshBackendStatus }) {
  const [isPinging, setIsPinging] = useState(false);
  const [density, setDensity] = useState('normal');

  const handleTestConnection = async () => {
    setIsPinging(true);
    await onRefreshBackendStatus();
    setTimeout(() => setIsPinging(false), 500);
  };

  return (
    <div className="space-y-6 max-w-4xl pb-16">
      {/* Title */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 tracking-tight">Platform Settings</h2>
        <p className="text-xs text-slate-400 mt-1">
          Configuration for vulnerability feeds, API integrations, and display density.
        </p>
      </div>

      {/* Security Intelligence Feeds */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-6 space-y-4">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100 font-mono-tech">
          Security Intelligence & Feeds
        </h3>

        <div className="divide-y divide-[#182338]">
          {/* OSV Feed */}
          <div className="py-3.5 flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">OSV (Open Source Vulnerabilities) API</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Upstream open vulnerability database (api.osv.dev)
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full ${backendStatus?.osvConnected ? 'bg-emerald-400' : 'bg-slate-500'}`} />
              <span className={`text-xs font-mono-tech font-bold ${backendStatus?.osvConnected ? 'text-emerald-400' : 'text-slate-500'}`}>
                {backendStatus?.osvConnected ? 'Connected' : 'Unavailable'}
              </span>
            </div>
          </div>

          {/* Backend API Connection */}
          <div className="py-3.5 flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">Local Auditor Backend API</div>
              <div className="text-[11px] text-slate-400 font-mono-tech mt-0.5">
                Target: {backendStatus?.url || 'Backend URL unavailable'}
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className={`text-xs font-mono-tech font-bold ${backendStatus?.isOnline ? 'text-emerald-400' : 'text-amber-400'}`}>
                {backendStatus?.isOnline ? 'Online' : 'Offline'}
              </span>
              <button
                onClick={handleTestConnection}
                disabled={isPinging}
                className="px-3 py-1 rounded bg-[#162138] hover:bg-[#1f2e4c] border border-[#253659] text-xs text-slate-200 font-mono-tech flex items-center gap-1.5 transition-colors"
              >
                <RefreshCwIcon className={`w-3.5 h-3.5 ${isPinging ? 'animate-spin' : ''}`} />
                <span>Test Connection</span>
              </button>
            </div>
          </div>
        </div>
      </div>

      <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-6 space-y-3">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100 font-mono-tech">
              Groq AI
            </h3>
            <p className="text-[11px] text-slate-400 mt-1">
              AI explanations and chat grounded in the selected scan.
            </p>
          </div>
        </div>
        <p className="text-xs text-slate-300 leading-relaxed">
          Set <code className="text-blue-300">GROQ_API_KEY</code> in <code className="text-blue-300">backend/sbomback/.env</code> and restart the backend. The key stays on the backend and is never sent to the browser. When you request an AI response, scan metrics, up to 15 highest-priority findings, and your chat messages are sent to Groq.
        </p>
      </div>

      {/* Display & Presentation Settings */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-6 space-y-4">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100 font-mono-tech">
          Display & Theme Preferences
        </h3>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs font-bold text-slate-200">Visual Theme</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Cybersecurity DevSecOps dark charcoal palette
              </div>
            </div>
            <span className="text-xs font-mono-tech text-blue-400 px-3 py-1 rounded bg-blue-500/10 border border-blue-500/20">
              Dark Charcoal (Locked)
            </span>
          </div>

          <div className="flex items-center justify-between pt-3 border-t border-[#182338]">
            <div>
              <div className="text-xs font-bold text-slate-200">Table Row Density</div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Adjust table padding for high-density desktop screens
              </div>
            </div>
            <div className="flex items-center gap-1 bg-[#0d1320] border border-[#1c2742] p-1 rounded-lg text-xs font-mono-tech">
              {['compact', 'normal', 'spacious'].map((d) => (
                <button
                  key={d}
                  onClick={() => setDensity(d)}
                  className={`px-2.5 py-1 rounded capitalize transition-colors ${
                    density === d ? 'bg-blue-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Application Metadata & Honest Hackathon Disclosure */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-6 space-y-3">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-100 font-mono-tech">
          System Integrity & Compliance
        </h3>
        <p className="text-xs text-slate-300 leading-relaxed">
          <strong>SBOM Risk & Trust Auditor</strong> analyzes Software Bill of Materials against open vulnerability data and NTIA Minimum Elements guidelines. It does not make exaggerated claims of static source-code call-graph reachability or automatic code refactoring; risk prioritization is strictly based on manifest dependency relationships, production scopes, and verified vulnerability intelligence.
        </p>
      </div>
    </div>
  );
}
