import React, { useState, useMemo } from 'react';
import { SeverityBadge, RiskScoreBadge, ContextBadge } from '../common/Badge';
import { SearchIcon, FilterIcon, XIcon } from '../common/Icons';

const EMPTY_VULNERABILITIES = [];

export function VulnerabilitiesScreen({ vulnerabilities = [], scanData, onSelectVulnerability, initialSearchQuery = "" }) {
  const safeVulnerabilities = Array.isArray(vulnerabilities) ? vulnerabilities : EMPTY_VULNERABILITIES;
  const [search, setSearch] = useState(initialSearchQuery);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [depTypeFilter, setDepTypeFilter] = useState('ALL');
  const [envFilter, setEnvFilter] = useState('ALL');
  const [fixFilter, setFixFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('risk-desc');

  // Filter logic
  const filtered = useMemo(() => {
    return safeVulnerabilities.filter((vuln) => {
      // Search text match
      const query = search.toLowerCase().trim();
      if (query) {
        const matchesPkg = vuln.package.toLowerCase().includes(query);
        const matchesId = vuln.id.toLowerCase().includes(query);
        const matchesCve = vuln.cve ? vuln.cve.toLowerCase().includes(query) : false;
        const matchesSummary = vuln.summary ? vuln.summary.toLowerCase().includes(query) : false;
        if (!matchesPkg && !matchesId && !matchesCve && !matchesSummary) return false;
      }

      // Severity filter
      if (severityFilter !== 'ALL' && vuln.severity !== severityFilter) return false;

      // Dependency type filter
      if (depTypeFilter !== 'ALL' && vuln.dependencyType !== depTypeFilter) return false;

      // Environment filter
      if (envFilter !== 'ALL' && vuln.environment !== envFilter) return false;

      // Fix available filter
      if (fixFilter === 'FIX_ONLY' && !vuln.fixAvailable) return false;
      if (fixFilter === 'NO_FIX' && vuln.fixAvailable) return false;

      return true;
    }).sort((a, b) => {
      if (sortBy === 'risk-desc') return b.riskScore - a.riskScore;
      if (sortBy === 'risk-asc') return a.riskScore - b.riskScore;
      if (sortBy === 'priority') return a.priority - b.priority;
      if (sortBy === 'package') return a.package.localeCompare(b.package);
      return 0;
    });
  }, [safeVulnerabilities, search, severityFilter, depTypeFilter, envFilter, fixFilter, sortBy]);

  const hasActiveFilters = search || severityFilter !== 'ALL' || depTypeFilter !== 'ALL' || envFilter !== 'ALL' || fixFilter !== 'ALL';

  const resetFilters = () => {
    setSearch('');
    setSeverityFilter('ALL');
    setDepTypeFilter('ALL');
    setEnvFilter('ALL');
    setFixFilter('ALL');
    setSortBy('risk-desc');
  };

  // Severity metrics for top counts
  const counts = {
    critical: safeVulnerabilities.filter(v => v.severity === 'CRITICAL').length,
    high: safeVulnerabilities.filter(v => v.severity === 'HIGH').length,
    medium: safeVulnerabilities.filter(v => v.severity === 'MEDIUM').length,
    low: safeVulnerabilities.filter(v => v.severity === 'LOW').length,
    unknown: safeVulnerabilities.filter(v => v.severity === 'UNKNOWN').length,
  };

  if (!scanData) {
    return (
      <div className="p-12 text-center text-slate-400">
        Analyze an SBOM to view its vulnerability findings.
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-12">
      {/* Header & Summary Counts */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">Vulnerabilities Management</h2>
          <p className="text-xs text-slate-400 mt-1">
            Triaged vulnerability catalog with contextual exposure and remediation paths.
          </p>
        </div>

        {/* Severity Quick Filters */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          <button
            onClick={() => setSeverityFilter('ALL')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono-tech transition-colors ${
              severityFilter === 'ALL'
                ? 'bg-blue-600 text-white font-bold'
                : 'bg-[#101726] border border-[#1e2a42] text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({safeVulnerabilities.length})
          </button>
          <button
            onClick={() => setSeverityFilter('CRITICAL')}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-mono-tech transition-colors ${
              severityFilter === 'CRITICAL'
                ? 'bg-red-600 text-white font-bold'
                : 'bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20'
            }`}
          >
            Critical ({counts.critical})
          </button>
          <button
            onClick={() => setSeverityFilter('HIGH')}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-mono-tech transition-colors ${
              severityFilter === 'HIGH'
                ? 'bg-orange-600 text-white font-bold'
                : 'bg-orange-500/10 border border-orange-500/30 text-orange-400 hover:bg-orange-500/20'
            }`}
          >
            High ({counts.high})
          </button>
          <button
            onClick={() => setSeverityFilter('MEDIUM')}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-mono-tech transition-colors ${
              severityFilter === 'MEDIUM'
                ? 'bg-amber-600 text-white font-bold'
                : 'bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20'
            }`}
          >
            Medium ({counts.medium})
          </button>
          <button
            onClick={() => setSeverityFilter('LOW')}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-mono-tech transition-colors ${
              severityFilter === 'LOW'
                ? 'bg-cyan-600 text-white font-bold'
                : 'bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20'
            }`}
          >
            Low ({counts.low})
          </button>
          <button
            onClick={() => setSeverityFilter('UNKNOWN')}
            className={`px-2.5 py-1.5 rounded-lg text-xs font-mono-tech transition-colors ${
              severityFilter === 'UNKNOWN'
                ? 'bg-purple-600 text-white font-bold'
                : 'bg-purple-500/10 border border-purple-500/30 text-purple-300 hover:bg-purple-500/20'
            }`}
          >
            Unknown ({counts.unknown})
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4 space-y-3">
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
          {/* Search box */}
          <div className="relative flex-1">
            <SearchIcon className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search package, CVE, GHSA, description..."
              className="w-full bg-[#0d1320] border border-[#1f2a3f] rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono-tech transition-colors"
            />
          </div>

          {/* Dependency Type Filter */}
          <select
            value={depTypeFilter}
            onChange={(e) => setDepTypeFilter(e.target.value)}
            className="bg-[#0d1320] border border-[#1f2a3f] text-slate-300 rounded-lg px-3 py-2 text-xs font-mono-tech focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Dependencies</option>
            <option value="Direct">Direct Only</option>
            <option value="Transitive">Transitive Only</option>
            <option value="Unknown">Unknown Type</option>
          </select>

          {/* Environment Filter */}
          <select
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            className="bg-[#0d1320] border border-[#1f2a3f] text-slate-300 rounded-lg px-3 py-2 text-xs font-mono-tech focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Environments</option>
            <option value="Production">Production Only</option>
            <option value="Development">Development Only</option>
            <option value="Unknown">Unknown Scope</option>
          </select>

          {/* Fix Filter */}
          <select
            value={fixFilter}
            onChange={(e) => setFixFilter(e.target.value)}
            className="bg-[#0d1320] border border-[#1f2a3f] text-slate-300 rounded-lg px-3 py-2 text-xs font-mono-tech focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Fix States</option>
            <option value="FIX_ONLY">Fix Available</option>
            <option value="NO_FIX">No Patch Available</option>
          </select>

          {/* Sorting */}
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="bg-[#0d1320] border border-[#1f2a3f] text-slate-300 rounded-lg px-3 py-2 text-xs font-mono-tech focus:outline-none focus:border-blue-500"
          >
            <option value="risk-desc">Sort: Risk Score ↓</option>
            <option value="risk-asc">Sort: Risk Score ↑</option>
            <option value="priority">Sort: Priority #</option>
            <option value="package">Sort: Package Name</option>
          </select>

          {/* Reset Filters */}
          {hasActiveFilters && (
            <button
              onClick={resetFilters}
              className="px-3 py-2 rounded-lg bg-[#192338] hover:bg-[#23314f] text-slate-300 text-xs font-mono-tech flex items-center gap-1.5 transition-colors whitespace-nowrap"
            >
              <XIcon className="w-3.5 h-3.5" />
              <span>Clear</span>
            </button>
          )}
        </div>

        <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono-tech pt-1">
          <span>Showing {filtered.length} of {safeVulnerabilities.length} vulnerabilities</span>
          {counts.unknown > 0 && (
            <span className="text-purple-400">
              ⚠ UNKNOWN DOES NOT MEAN SAFE: {counts.unknown} finding{counts.unknown === 1 ? '' : 's'} have unknown severity.
            </span>
          )}
        </div>
      </div>

      {/* Full-Width Table */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl overflow-hidden">
        {filtered.length === 0 ? (
          /* Empty state */
          <div className="p-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center mx-auto">
              <FilterIcon className="w-6 h-6" />
            </div>
            <h3 className="text-sm font-bold text-slate-200">No vulnerabilities match your criteria</h3>
            <p className="text-xs text-slate-400 max-w-sm mx-auto">
              Try adjusting your search terms or clearing the selected severity/environment filters.
            </p>
            <button
              onClick={resetFilters}
              className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold"
            >
              Reset All Filters
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-[#0b0f1a] text-slate-400 uppercase font-mono-tech text-[11px] border-b border-[#182338]">
                <tr>
                  <th className="py-3 px-4">Package</th>
                  <th className="py-3 px-4">Installed</th>
                  <th className="py-3 px-4">Vulnerability</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Dependency Context</th>
                  <th className="py-3 px-4">Exploitability</th>
                  <th className="py-3 px-4">Fix Available</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#162035]">
                {filtered.map((vuln) => (
                  <tr
                    key={vuln.id}
                    onClick={() => onSelectVulnerability(vuln)}
                    className="hover:bg-[#151e33] transition-colors cursor-pointer group"
                  >
                    <td className="py-3.5 px-4 font-mono-tech font-bold text-slate-100 group-hover:text-blue-400 transition-colors">
                      {vuln.package}
                    </td>
                    <td className="py-3.5 px-4 font-mono-tech text-slate-400">
                      {vuln.installedVersion}
                    </td>
                    <td className="py-3.5 px-4 font-mono-tech">
                      <div className="text-slate-200 font-semibold">{vuln.id}</div>
                      {vuln.cve && <div className="text-[10px] text-slate-400">{vuln.cve}</div>}
                    </td>
                    <td className="py-3.5 px-4">
                      <SeverityBadge severity={vuln.severity} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskScoreBadge score={vuln.riskScore} />
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <ContextBadge type="dep" value={vuln.dependencyType} />
                        <ContextBadge type="env" value={vuln.environment} />
                      </div>
                    </td>
                    <td className="py-3.5 px-4 text-slate-300">
                      <span className="text-[11px] font-mono-tech">{vuln.exploitability}</span>
                    </td>
                    <td className="py-3.5 px-4 font-mono-tech">
                      {vuln.fixAvailable ? (
                        <span className="text-emerald-400 font-medium">{vuln.fixedVersion}</span>
                      ) : (
                        <span className="text-slate-400">No patch</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`text-[11px] font-mono-tech font-semibold ${
                        vuln.confidence === 'High' ? 'text-emerald-400' :
                        vuln.confidence === 'Medium' ? 'text-amber-400' : 'text-purple-400'
                      }`}>
                        {vuln.confidence}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`text-[11px] px-2 py-0.5 rounded font-mono-tech ${
                        vuln.status === 'Active' ? 'bg-red-500/10 text-red-300 border border-red-500/20' :
                        vuln.status === 'Uncertain' ? 'bg-purple-500/10 text-purple-300 border border-purple-500/20' :
                        'bg-slate-700 text-slate-300'
                      }`}>
                        {vuln.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectVulnerability(vuln);
                        }}
                        className="px-2.5 py-1 rounded bg-[#1c2742] group-hover:bg-blue-600 group-hover:text-white text-blue-300 border border-[#2b3d63] text-xs font-medium transition-colors"
                      >
                        Details
                      </button>
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
