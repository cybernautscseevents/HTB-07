import React from 'react';
import { SearchIcon } from '../common/Icons';

export function Header({
  currentTab,
  scanData,
  searchQuery,
  setSearchQuery,
  onNewScanClick
}) {
  const titles = {
    overview: 'Security Overview',
    scans: 'Scans & Audit History',
    vulnerabilities: 'Vulnerabilities Management',
    detail: 'Vulnerability Deep Dive',
    components: 'Components Inventory',
    quality: 'SBOM Quality & Trust Audit',
    reports: 'Compliance & Risk Reports',
    settings: 'Platform Settings',
    upload: 'Analyze an SBOM',
  };

  return (
    <header className="h-16 bg-[#0c111d] border-b border-[#1a2337] px-8 flex items-center justify-between shrink-0 select-none z-10">

      {/* Title & Breadcrumb Context */}
      <div className="flex items-center gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold text-slate-100 tracking-tight">
              {titles[currentTab] || 'Dashboard'}
            </h1>

            {scanData?.sbomFormat && (
              <span className="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-mono-tech">
                {scanData.sbomFormat}
              </span>
            )}
          </div>

          <div className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
            {scanData && (
              <>
                <span className="font-medium text-slate-300">
                  {scanData.scanName || 'Unnamed scan'}
                </span>
                {scanData.sbomFile && (
                  <>
                    <span>•</span>
                    <span className="font-mono-tech">{scanData.sbomFile}</span>
                  </>
                )}
                {scanData.scanDate && (
                  <>
                    <span>•</span>
                    <span className="font-mono-tech text-slate-400">
                      {new Date(scanData.scanDate).toLocaleString()}
                    </span>
                  </>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Global Actions */}
      <div className="flex items-center gap-4">

        {/* Quick Search */}
        <div className="relative w-64">
          <SearchIcon className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />

          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search package, CVE, GHSA..."
            className="w-full bg-[#111726] border border-[#1f2a3f] rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono-tech transition-colors"
          />
        </div>

        {/* New Scan */}
        <button
          onClick={onNewScanClick}
          className="text-xs font-medium px-3 py-1.5 bg-[#141b2d] hover:bg-[#1a243c] border border-[#22304d] text-slate-200 rounded-lg transition-colors"
        >
          New Scan
        </button>

      </div>
    </header>
  );
}