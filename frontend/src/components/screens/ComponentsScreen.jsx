import React, { useState, useMemo } from 'react';
import { ContextBadge, RiskScoreBadge } from '../common/Badge';
import { SearchIcon, XIcon } from '../common/Icons';

const EMPTY_COMPONENTS = [];

export function ComponentsScreen({ components, onSelectComponent, onFilterVulnerabilitiesByPackage }) {
  const safeComponents = Array.isArray(components) ? components : EMPTY_COMPONENTS;
  const [search, setSearch] = useState('');
  const [depFilter, setDepFilter] = useState('ALL');
  const [envFilter, setEnvFilter] = useState('ALL');
  const [vulnFilter, setVulnFilter] = useState('ALL');


  const filtered = useMemo(() => {
    return safeComponents.filter((comp) => {
      const q = search.toLowerCase().trim();
      if (q) {
        const matchName = comp.name.toLowerCase().includes(q);
        const matchPurl = comp.purl ? comp.purl.toLowerCase().includes(q) : false;
        const matchSupplier = comp.supplier ? comp.supplier.toLowerCase().includes(q) : false;
        const matchLicense = comp.license ? comp.license.toLowerCase().includes(q) : false;
        if (!matchName && !matchPurl && !matchSupplier && !matchLicense) return false;
      }

      if (depFilter !== 'ALL' && String(comp.dependencyType || '').toUpperCase() !== depFilter.toUpperCase()) return false;
      if (envFilter !== 'ALL' && String(comp.environment || '').toUpperCase() !== envFilter.toUpperCase()) return false;
      if (vulnFilter === 'VULNERABLE' && comp.vulnerabilitiesCount === 0) return false;
      if (vulnFilter === 'CLEAN' && comp.vulnerabilitiesCount > 0) return false;

      return true;
    });
  }, [safeComponents, search, depFilter, envFilter, vulnFilter]);

  const directCount = safeComponents.filter(c => String(c.dependencyType || '').toUpperCase() === 'DIRECT').length;
  const transitiveCount = safeComponents.filter(c => String(c.dependencyType || '').toUpperCase() === 'TRANSITIVE').length;
  const prodCount = safeComponents.filter(c => String(c.environment || '').toUpperCase() === 'PRODUCTION').length;
  const devCount = safeComponents.filter(c => String(c.environment || '').toUpperCase() === 'DEVELOPMENT').length;
  const vulnTotal = safeComponents.filter(c => c.vulnerabilitiesCount > 0).length;

  if (safeComponents.length === 0) {
    return (
      <div className="p-12 text-center text-slate-400">
        No analyzed components are available.
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Title */}
      <div>
        <h2 className="text-xl font-bold text-slate-100 tracking-tight">Components Inventory</h2>
        <p className="text-xs text-slate-400 mt-1">
          Extracted Software Bill of Materials (SBOM) packages and supply chain assets.
        </p>
      </div>

      {/* Summary Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
          <div className="text-[11px] font-mono-tech uppercase text-slate-400">Total Components</div>
          <div className="text-2xl font-bold font-mono-tech text-slate-100 mt-1">{safeComponents.length}</div>
        </div>
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
          <div className="text-[11px] font-mono-tech uppercase text-slate-400">Direct Dependencies</div>
          <div className="text-2xl font-bold font-mono-tech text-blue-400 mt-1">{directCount}</div>
        </div>
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
          <div className="text-[11px] font-mono-tech uppercase text-slate-400">Transitive Dependencies</div>
          <div className="text-2xl font-bold font-mono-tech text-purple-400 mt-1">{transitiveCount}</div>
        </div>
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
          <div className="text-[11px] font-mono-tech uppercase text-slate-400">Production Scope</div>
          <div className="text-2xl font-bold font-mono-tech text-emerald-400 mt-1">{prodCount}</div>
        </div>
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
          <div className="text-[11px] font-mono-tech uppercase text-slate-400">Development Scope</div>
          <div className="text-2xl font-bold font-mono-tech text-slate-300 mt-1">{devCount}</div>
        </div>
        <div className="bg-[#101726] border border-red-500/20 rounded-xl p-4">
          <div className="text-[11px] font-mono-tech uppercase text-red-400">Vulnerable Packages</div>
          <div className="text-2xl font-bold font-mono-tech text-red-400 mt-1">{vulnTotal}</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
          <div className="relative flex-1">
            <SearchIcon className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search component name, PURL, license, supplier..."
              className="w-full bg-[#0d1320] border border-[#1f2a3f] rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono-tech focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={depFilter}
            onChange={(e) => setDepFilter(e.target.value)}
            className="bg-[#0d1320] border border-[#1f2a3f] text-slate-300 rounded-lg px-3 py-2 text-xs font-mono-tech"
          >
            <option value="ALL">All Dependencies</option>
            <option value="DIRECT">Direct Only</option>
            <option value="TRANSITIVE">Transitive Only</option>
            <option value="UNKNOWN">Unknown Type</option>
          </select>

          <select
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            className="bg-[#0d1320] border border-[#1f2a3f] text-slate-300 rounded-lg px-3 py-2 text-xs font-mono-tech"
          >
            <option value="ALL">All Environments</option>
            <option value="PRODUCTION">Production</option>
            <option value="DEVELOPMENT">Development</option>
          </select>

          <select
            value={vulnFilter}
            onChange={(e) => setVulnFilter(e.target.value)}
            className="bg-[#0d1320] border border-[#1f2a3f] text-slate-300 rounded-lg px-3 py-2 text-xs font-mono-tech"
          >
            <option value="ALL">All Components</option>
            <option value="VULNERABLE">Vulnerable Only</option>
            <option value="CLEAN">Clean Only</option>
          </select>

          {(search || depFilter !== 'ALL' || envFilter !== 'ALL' || vulnFilter !== 'ALL') && (
            <button
              onClick={() => {
                setSearch('');
                setDepFilter('ALL');
                setEnvFilter('ALL');
                setVulnFilter('ALL');
              }}
              className="px-3 py-2 rounded-lg bg-[#192338] hover:bg-[#23314f] text-slate-300 text-xs font-mono-tech flex items-center gap-1"
            >
              <XIcon className="w-3.5 h-3.5" />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Components Table */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl overflow-hidden">
        {filtered.length === 0 ? (
          <div className="p-12 text-center text-sm text-slate-400">
            {safeComponents.length === 0
              ? 'No analyzed components are available.'
              : 'No components match the selected filters.'}
          </div>
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b0f1a] text-slate-400 uppercase font-mono-tech text-[11px] border-b border-[#182338]">
              <tr>
                <th className="py-3 px-4">Component</th>
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Ecosystem</th>
                <th className="py-3 px-4">Dependency Type</th>
                <th className="py-3 px-4">Environment</th>
                <th className="py-3 px-4">License</th>
                <th className="py-3 px-4 text-center">Vulnerabilities</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#162035]">
              {filtered.map((comp) => (
                <tr 
                  key={comp.id} 
                  onClick={() => onSelectComponent && onSelectComponent(comp)}
                  className="hover:bg-[#151e33] transition-colors cursor-pointer group"
                >

                  <td className="py-3.5 px-4">
                    <div className="font-mono-tech font-bold text-slate-100">{comp.name}</div>
                    <div className="text-[10px] text-slate-400 font-mono-tech truncate max-w-xs">{comp.purl}</div>
                  </td>
                  <td className="py-3.5 px-4 font-mono-tech text-slate-400">
                    {comp.version}
                  </td>
                  <td className="py-3.5 px-4 font-mono-tech text-slate-300 uppercase">
                    {comp.ecosystem}
                  </td>
                  <td className="py-3.5 px-4">
                    <ContextBadge type="dep" value={comp.dependencyType} />
                  </td>
                  <td className="py-3.5 px-4">
                    <ContextBadge type="env" value={comp.environment} />
                  </td>
                  <td className="py-3.5 px-4 font-mono-tech text-slate-400">
                    <span className="px-2 py-0.5 rounded bg-[#131a29] border border-[#1c273d]">
                      {comp.license}
                    </span>
                  </td>
                  <td className="py-3.5 px-4 text-center">
                    {comp.vulnerabilitiesCount > 0 ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded font-mono-tech font-bold text-xs bg-red-500/15 text-red-400 border border-red-500/30">
                        {comp.vulnerabilitiesCount} CVE
                      </span>
                    ) : (
                      <span className="text-slate-400 font-mono-tech text-xs">0</span>
                    )}
                  </td>
                  <td className="py-3.5 px-4">
                    <RiskScoreBadge score={comp.riskScore} />
                  </td>
                  <td className="py-3.5 px-4 text-right">
                    {comp.vulnerabilitiesCount > 0 ? (
                      <button
                        onClick={() => onFilterVulnerabilitiesByPackage(comp.name)}
                        className="px-2.5 py-1 rounded bg-[#1c2742] hover:bg-blue-600 hover:text-white text-blue-300 border border-[#2b3d63] text-xs font-medium transition-colors"
                      >
                        View Vulns
                      </button>
                    ) : (
                      <span className="text-slate-400 text-xs">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </div>
    </div>
  );
}
