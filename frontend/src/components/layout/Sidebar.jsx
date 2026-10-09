import React from 'react';
import { 
  ShieldIcon, 
  BugIcon, 
  PackageIcon, 
  AwardIcon,
  FileTextIcon,
  SettingsIcon, 
  HistoryIcon, 
  UploadCloudIcon 
} from '../common/Icons';

export function Sidebar({ currentTab, setTab, scanData, backendStatus, user, onLogout }) {
  const navItems = [
    { id: 'overview', label: 'Overview', icon: ShieldIcon, badge: null },
    { id: 'scans', label: 'Scans', icon: HistoryIcon, badge: null },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: BugIcon, badge: scanData ? scanData.vulnerabilitiesCount : null, badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/30' },
    { id: 'components', label: 'Components', icon: PackageIcon, badge: scanData ? scanData.totalComponents : null, badgeColor: 'bg-slate-800 text-slate-300' },
    { id: 'quality', label: 'SBOM Quality', icon: AwardIcon, badge: scanData ? `${scanData.sbomTrust.score}%` : null, badgeColor: 'bg-amber-500/20 text-amber-300 border border-amber-500/30' },
    { id: 'reports', label: 'Reports', icon: FileTextIcon, badge: null },
    { id: 'comparison', label: 'SBOM Comparison', icon: PackageIcon, badge: null },
  ];

  return (
    <aside className="w-64 bg-[#0c111d] border-r border-[#1a2337] flex flex-col justify-between shrink-0 select-none min-h-screen">
      {/* Branding Header */}
      <div>
        <div className="p-5 border-b border-[#1a2337] flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-600/15 border border-blue-500/30 flex items-center justify-center text-blue-400 shadow-inner">
            <ShieldIcon className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <div className="text-[11px] tracking-[0.2em] font-mono-tech text-blue-400 font-semibold uppercase leading-none mb-1">
              SBOM
            </div>
            <div className="text-sm font-bold tracking-wider text-slate-100 uppercase leading-none">
              RISK & TRUST
            </div>
            <div className="text-[10px] tracking-[0.25em] font-mono-tech text-slate-400 uppercase leading-tight mt-0.5">
              AUDITOR
            </div>
          </div>
        </div>

        {/* Primary Action Button */}
        <div className="p-4">
          <button
            onClick={() => setTab('upload')}
            className={`w-full py-2.5 px-3 rounded-lg flex items-center justify-center gap-2 text-xs font-semibold uppercase tracking-wider transition-all duration-150 ${
              currentTab === 'upload'
                ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/30 border border-blue-400'
                : 'bg-blue-600/15 hover:bg-blue-600/25 text-blue-300 border border-blue-500/30'
            }`}
          >
            <UploadCloudIcon className="w-4 h-4" />
            <span>Analyze New SBOM</span>
          </button>
        </div>

        {/* Navigation Links */}
        <nav className="px-3 space-y-1">
          <div className="px-3 py-2 text-[10px] uppercase tracking-wider font-semibold text-slate-400">
            Audit Navigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-[#162035] text-blue-400 border border-[#233355] font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#121929]'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-blue-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== null && (
                  <span className={`text-[10px] px-2 py-0.5 rounded font-mono-tech ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        {/* Configuration Section */}
        <div className="px-3 pt-4 space-y-1">
          <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider font-semibold text-slate-400">
            Configuration
          </div>
          <button
            onClick={() => setTab('settings')}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-xs font-medium transition-colors ${
              currentTab === 'settings'
                ? 'bg-[#162035] text-blue-400 border border-[#233355]'
                : 'text-slate-400 hover:text-slate-200 hover:bg-[#121929]'
            }`}
          >
            <SettingsIcon className="w-4 h-4 text-slate-400" />
            <span>Settings</span>
          </button>
        </div>
      </div>

      {/* Bottom Area: System Status */}
      <div className="p-4 border-t border-[#1a2337] bg-[#090e18] space-y-3">
        <div className="flex items-center justify-between gap-2 rounded bg-[#101726] border border-[#1b263b] p-2">
          <span className="min-w-0 truncate text-[11px] text-slate-300" title={user?.email}>{user?.email}</span>
          <button
            type="button"
            onClick={onLogout}
            className="shrink-0 text-[10px] font-semibold uppercase tracking-wide text-slate-400 hover:text-red-300"
          >
            Sign out
          </button>
        </div>
        <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
          System Status
        </div>
        
        {/* OSV Intelligence Status */}
        <div className="flex items-center justify-between text-xs p-2 rounded bg-[#101726] border border-[#1b263b]">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${backendStatus?.osvConnected ? 'bg-emerald-400' : 'bg-slate-500'}`} />
            <span className="text-slate-300 font-mono-tech text-[11px]">OSV Intelligence</span>
          </div>
          <span className={`text-[10px] font-semibold uppercase tracking-wider ${backendStatus?.osvConnected ? 'text-emerald-400' : 'text-slate-500'}`}>
            {backendStatus?.osvConnected ? 'Connected' : 'Unavailable'}
          </span>
        </div>

        {/* Backend API Health Status */}
        <div className="flex items-center justify-between text-xs p-2 rounded bg-[#101726] border border-[#1b263b]">
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full ${backendStatus?.isOnline ? 'bg-emerald-400' : 'bg-amber-400'}`} />
            <span className="text-slate-300 font-mono-tech text-[11px]">Backend API</span>
          </div>
          <span className={`text-[10px] font-semibold uppercase tracking-wider ${backendStatus?.isOnline ? 'text-emerald-400' : 'text-amber-400'}`}>
            {backendStatus?.isOnline ? 'Online' : 'Offline'}
          </span>
        </div>

        <div className="text-[10px] text-slate-400 font-mono-tech text-center pt-1">
          v1.0.0 • Hacktopia DevSecOps
        </div>
      </div>
    </aside>
  );
}
