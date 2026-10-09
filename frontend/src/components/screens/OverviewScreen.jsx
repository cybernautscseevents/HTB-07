import React, { useState } from 'react';
import {
  SeverityBadge,
  RiskScoreBadge,
  AuditStatusBadge,
} from '../common/Badge';
import {
  CheckCircleIcon,
  AlertTriangleIcon,
  DownloadIcon,
} from '../common/Icons';
import { GroqAssistant } from '../common/GroqAssistant';
import { exportScan } from '../../services/api';
import { downloadBlob, saveBlob } from '../../services/download';

export function OverviewScreen({
  scanData,
  updatedSbom,
  updatedSbomLoading,
  updatedSbomError,
  vulnerabilities = [],
  onSelectVulnerability,
  onNavigateTab,
}) {
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('priority');
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState('');
  const [exportSuccess, setExportSuccess] = useState(false);
  const [sbomDownloadError, setSbomDownloadError] = useState('');

  const handleUpdatedSbomDownload = async () => {
    if (!updatedSbom) return;
    try {
      await saveBlob(
        new Blob([JSON.stringify(updatedSbom.sbom, null, 2)], { type: 'application/json' }),
        updatedSbom.fileName,
      );
      setSbomDownloadError('');
    } catch (error) {
      if (error.name !== 'AbortError') {
        setSbomDownloadError(error.message || 'Could not save the updated SBOM.');
      }
    }
  };

  const handleCsvExport = async () => {
    if (!scanData?.id || isExporting) return;

    setIsExporting(true);
    setExportError('');
    setExportSuccess(false);
    try {
      const { blob, fileName } = await exportScan(scanData.id, 'csv');
      downloadBlob(blob, fileName);
      setExportSuccess(true);
      window.setTimeout(() => setExportSuccess(false), 3000);
    } catch (error) {
      setExportError(error.message || 'Failed to export the scan results.');
    } finally {
      setIsExporting(false);
    }
  };

  // No scan has been performed yet
  if (!scanData) {
    return (
      <div className="flex min-h-[400px] items-center justify-center">
        <div className="text-center">
          <h2 className="text-lg font-semibold text-slate-100">
            No scan data available
          </h2>
          <p className="mt-2 text-sm text-slate-400">
            Upload and analyze an SBOM to view the security overview.
          </p>
        </div>
      </div>
    );
  }

  const safeVulnerabilities = Array.isArray(vulnerabilities)
    ? vulnerabilities
    : [];

  const severityCounts = scanData.severityCounts || {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  };

  const overallRisk = scanData.overallRisk || {
    score: 0,
    level: 'UNKNOWN',
    rationale: 'No risk assessment is available.',
    directProductionVulns: 0,
    transitiveVulns: 0,
  };

  const sbomTrust = scanData.sbomTrust || {
    score: 0,
    rating: 'UNKNOWN',
    highlights: [],
  };

  const qualityBreakdown = Array.isArray(scanData.qualityBreakdown)
    ? scanData.qualityBreakdown
    : [];

  const uncertainFindings = Array.isArray(scanData.uncertainFindings)
    ? scanData.uncertainFindings
    : [];

  // Filter & sort vulnerabilities
  const filteredVulns = [...safeVulnerabilities]
    .filter(
      (v) =>
        severityFilter === 'ALL' ||
        String(v.severity || '').toUpperCase() === severityFilter
    )
    .sort((a, b) => {
      if (sortBy === 'risk') {
        return (b.riskScore || 0) - (a.riskScore || 0);
      }

      return (a.priority || 999) - (b.priority || 999);
    });

  const totalVulnerabilities =
    scanData.vulnerabilitiesCount ?? safeVulnerabilities.length;

  const totalComponents =
    scanData.totalComponents ??
    scanData.componentsCount ??
    scanData.components_count ??
    0;

  const riskScore = Number(overallRisk.score) || 0;

  const vulnerabilityPercent = (count) => {
    if (!totalVulnerabilities) return 0;
    return Math.min(100, (count / totalVulnerabilities) * 100);
  };

  const riskLevelClass =
    String(overallRisk.level).toUpperCase() === 'CRITICAL'
      ? 'bg-red-500/15 text-red-400 border-red-500/30'
      : String(overallRisk.level).toUpperCase() === 'HIGH'
        ? 'bg-orange-500/15 text-orange-400 border-orange-500/30'
        : String(overallRisk.level).toUpperCase() === 'MEDIUM'
          ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
          : 'bg-slate-500/15 text-slate-300 border-slate-500/30';

  return (
    <div className="space-y-6 pb-12">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">
            Security Overview
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Risk posture and SBOM confidence for the current application.
          </p>
        </div>
        <button
          type="button"
          onClick={handleCsvExport}
          disabled={!scanData.id || isExporting}
          className="px-4 py-2 rounded-lg bg-[#141d30] hover:bg-[#1a2640] border border-[#223354] text-slate-200 text-xs font-semibold flex items-center gap-2 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <DownloadIcon className="w-4 h-4 text-blue-400" />
          <span>{isExporting ? 'Exporting…' : 'Download CSV'}</span>
        </button>
      </div>

      {exportSuccess && (
        <p role="status" className="text-xs text-emerald-300">
          CSV report downloaded successfully.
        </p>
      )}
      {exportError && (
        <p role="alert" className="text-xs text-red-300">
          {exportError}
        </p>
      )}

      <section className="rounded-xl border border-blue-500/25 bg-blue-500/5 p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-slate-100">Updated SBOM</h3>
            <p className="mt-1 text-xs text-slate-400">
              {updatedSbomLoading
                ? 'Preparing a suggested SBOM from this scan’s OSV fixed-version results…'
                : updatedSbom
                  ? `${updatedSbom.summary.updatedComponents} component(s) have a suggested fixed version.`
                  : 'Run a new SBOM analysis to prepare its updated file for download.'}
            </p>
          </div>
          {updatedSbom && (
            <button
              type="button"
              onClick={handleUpdatedSbomDownload}
              className="rounded-lg border border-blue-500/40 bg-blue-600/15 px-4 py-2.5 text-xs font-semibold text-blue-200 hover:bg-blue-600/25"
            >
              Download updated SBOM (.json)
            </button>
          )}
        </div>
        {(updatedSbomError || sbomDownloadError) && (
          <p role="alert" className="mt-3 text-xs text-red-300">
            {updatedSbomError || sbomDownloadError}
          </p>
        )}
        {updatedSbom && (
          <>
            <p className="mt-3 text-xs text-amber-200">{updatedSbom.note}</p>
            {updatedSbom.changes.length > 0 && (
              <ul className="mt-3 space-y-1 text-xs text-slate-300">
                {updatedSbom.changes.map((change) => (
                  <li key={`${change.name}-${change.fromVersion}`}>
                    {change.name}: {change.fromVersion} → {change.toVersion}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </section>

      <GroqAssistant key={scanData.id} scanData={scanData} />

      {/* Top Metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400 font-mono-tech">
            Total Components
          </div>
          <div className="text-2xl font-bold font-mono-tech text-slate-100 mt-2">
            {totalComponents}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            {scanData.format || 'SBOM'} inventory
          </div>
        </div>

        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400 font-mono-tech">
            Vulnerabilities
          </div>
          <div className="text-2xl font-bold font-mono-tech text-red-400 mt-2">
            {totalVulnerabilities}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            OSV matched
          </div>
        </div>

        <div className="bg-[#101726] border border-red-500/20 rounded-xl p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-red-400 font-mono-tech flex items-center justify-between">
            <span>Critical</span>
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
          </div>
          <div className="text-2xl font-bold font-mono-tech text-red-400 mt-2">
            {severityCounts.critical}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Critical-severity findings
          </div>
        </div>

        <div className="bg-[#101726] border border-orange-500/20 rounded-xl p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-orange-400 font-mono-tech">
            High
          </div>
          <div className="text-2xl font-bold font-mono-tech text-orange-400 mt-2">
            {severityCounts.high}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            High-severity findings
          </div>
        </div>

        <div className="bg-[#101726] border border-amber-500/20 rounded-xl p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-amber-400 font-mono-tech">
            Medium
          </div>
          <div className="text-2xl font-bold font-mono-tech text-amber-400 mt-2">
            {severityCounts.medium}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Medium-severity findings
          </div>
        </div>

        <div className="bg-[#101726] border border-purple-500/20 rounded-xl p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-purple-400 font-mono-tech flex items-center justify-between">
            <span>Unknown</span>
            <AlertTriangleIcon className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono-tech text-purple-300 mt-2">
            {severityCounts.unknown}
          </div>
          <div className="text-[11px] text-purple-400/80 mt-1">
            Severity not provided
          </div>
        </div>
      </div>

      {/* Risk + Trust */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Overall Risk */}
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider font-semibold text-slate-400 font-mono-tech">
                Overall Risk Posture
              </div>

              <div className="flex items-baseline gap-3 mt-2">
                <span className="text-4xl font-extrabold font-mono-tech text-red-400">
                  {riskScore}
                </span>

                <span className="text-sm font-semibold text-slate-400 font-mono-tech">
                  / 100
                </span>

                <span
                  className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono-tech uppercase border ${riskLevelClass}`}
                >
                  {overallRisk.level}
                </span>
              </div>
            </div>

            <div className="w-20 h-20 rounded-full border-4 border-[#1b253b] flex items-center justify-center bg-[#0d1320]">
              <span className="font-mono-tech font-bold text-sm text-red-400">
                {riskScore}%
              </span>
            </div>
          </div>

          <div className="mt-4 p-3 rounded-lg bg-[#0d1320] border border-[#182338]">
            <p className="text-xs text-slate-300 leading-relaxed">
              "{overallRisk.rationale}"
            </p>
          </div>

          <div className="grid grid-cols-2 gap-3 mt-4 pt-4 border-t border-[#182338]">
            <div>
              <div className="text-[11px] text-slate-400">
                Direct Production Vulns
              </div>
              <div className="text-sm font-bold font-mono-tech text-slate-200 mt-0.5">
                {overallRisk.directProductionVulns || 0} Direct findings
              </div>
            </div>

            <div>
              <div className="text-[11px] text-slate-400">
                Transitive Vulns
              </div>
              <div className="text-sm font-bold font-mono-tech text-slate-200 mt-0.5">
                {overallRisk.transitiveVulns || 0} Transitive findings
              </div>
            </div>
          </div>
        </div>

        {/* SBOM Trust */}
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-6">
          <div className="flex items-start justify-between">
            <div>
              <div className="text-xs uppercase tracking-wider font-semibold text-slate-400 font-mono-tech">
                SBOM Trust & Quality Score
              </div>

              <div className="flex items-baseline gap-3 mt-2">
                <span className="text-4xl font-extrabold font-mono-tech text-amber-400">
                  {sbomTrust.score}
                </span>

                <span className="text-sm font-semibold text-slate-400 font-mono-tech">
                  / 100
                </span>

                <span className="px-2.5 py-0.5 rounded text-xs font-bold font-mono-tech uppercase bg-amber-500/15 text-amber-300 border border-amber-500/30">
                  {sbomTrust.rating}
                </span>
              </div>
            </div>

            <button
              onClick={() => onNavigateTab?.('quality')}
              className="text-xs text-blue-400 hover:text-blue-300 border border-blue-500/30 px-3 py-1.5 rounded-lg"
            >
              Audit Breakdown →
            </button>
          </div>

          <div className="mt-4 space-y-2">
            {sbomTrust.highlights.length === 0 ? (
              <p className="text-xs text-slate-500">
                No trust assessment details returned by the backend.
              </p>
            ) : (
              sbomTrust.highlights.map((h, i) => (
                <div key={i} className="flex items-center gap-2.5 text-xs">
                  {h.status === 'pass' ? (
                    <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <AlertTriangleIcon className="w-4 h-4 text-amber-400 shrink-0" />
                  )}

                  <span
                    className={
                      h.status === 'pass'
                        ? 'text-slate-300'
                        : 'text-amber-300/90 font-medium'
                    }
                  >
                    {h.text}
                  </span>
                </div>
              ))
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-[#182338] flex items-center justify-between text-xs text-slate-400">
            <span>NTIA Minimum Elements:</span>
            <span className="text-amber-400 font-mono-tech font-semibold">
              {sbomTrust.verifiedElements ?? '—'}
            </span>
          </div>
        </div>
      </div>

      {/* Vulnerability Table */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl overflow-hidden">
        <div className="p-5 border-b border-[#182338] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-bold text-slate-100">
              Top Priority Vulnerabilities
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Ranked using the risk information returned by the backend.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5 bg-[#0d1320] border border-[#1e2a42] rounded-lg p-1 text-xs font-mono-tech">
              <span className="text-slate-400 px-2 text-[11px]">
                Filter:
              </span>

              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-0.5 rounded text-xs ${
                    severityFilter === sev
                      ? 'bg-blue-600 text-white font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            <button
              onClick={() =>
                setSortBy(sortBy === 'priority' ? 'risk' : 'priority')
              }
              className="text-xs px-3 py-1.5 rounded-lg bg-[#141b2e] border border-[#233355] text-slate-300"
            >
              Sort: {sortBy === 'priority' ? 'Priority #' : 'Risk Score ↓'}
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0b0f1a] text-slate-400 uppercase font-mono-tech text-[11px] border-b border-[#182338]">
              <tr>
                <th className="py-3 px-4">Priority</th>
                <th className="py-3 px-4">Package</th>
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Vulnerability</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Dependency</th>
                <th className="py-3 px-4">Fix</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-[#162035]">
              {filteredVulns.slice(0, 6).map((vuln) => (
                <tr
                  key={vuln.id}
                  onClick={() => onSelectVulnerability?.(vuln)}
                  className="hover:bg-[#151e33] transition-colors cursor-pointer"
                >
                  <td className="py-3.5 px-4 font-mono-tech font-bold text-slate-300">
                    #{vuln.priority ?? '—'}
                  </td>

                  <td className="py-3.5 px-4 font-mono-tech font-bold text-slate-100">
                    {vuln.package || vuln.name || 'Unknown'}
                  </td>

                  <td className="py-3.5 px-4 font-mono-tech text-slate-400">
                    {vuln.installedVersion || vuln.version || '—'}
                  </td>

                  <td className="py-3.5 px-4 font-mono-tech text-slate-200">
                    <div>{vuln.id || vuln.vulnerabilityId || 'Unknown'}</div>
                    {vuln.cve && (
                      <div className="text-[10px] text-slate-400">
                        {vuln.cve}
                      </div>
                    )}
                  </td>

                  <td className="py-3.5 px-4">
                    <SeverityBadge
                      severity={vuln.severity || 'UNKNOWN'}
                      size="sm"
                    />
                  </td>

                  <td className="py-3.5 px-4">
                    <RiskScoreBadge score={vuln.riskScore || 0} />
                  </td>

                  <td className="py-3.5 px-4">
                    <span className="text-slate-300 font-medium">
                      {vuln.dependencyType || 'Unknown'}
                    </span>
                    {vuln.environment && (
                      <span className="text-slate-400 text-[10px] ml-1">
                        / {vuln.environment}
                      </span>
                    )}
                  </td>

                  <td className="py-3.5 px-4 font-mono-tech">
                    {vuln.fixedVersion ? (
                      <span className="text-emerald-400 font-medium">
                        {vuln.fixedVersion}
                      </span>
                    ) : (
                      <span className="text-slate-400">No patch</span>
                    )}
                  </td>

                  <td className="py-3.5 px-4">
                    <span className="text-[11px] font-mono-tech text-slate-300">
                      {vuln.confidence || 'Unknown'}
                    </span>
                  </td>

                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectVulnerability?.(vuln);
                      }}
                      className="px-2.5 py-1 rounded bg-[#1c2742] text-blue-300 border border-[#2b3d63]"
                    >
                      Review
                    </button>
                  </td>
                </tr>
              ))}

              {filteredVulns.length === 0 && (
                <tr>
                  <td
                    colSpan="10"
                    className="py-10 text-center text-sm text-slate-500"
                  >
                    No vulnerabilities found for this filter.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="p-3 bg-[#0d1320] border-t border-[#182338] text-center">
          <button
            onClick={() => onNavigateTab?.('vulnerabilities')}
            className="text-xs text-blue-400 hover:text-blue-300"
          >
            View all {safeVulnerabilities.length} vulnerabilities →
          </button>
        </div>
      </div>

      {/* Risk Distribution + Quality */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-5">
          <h3 className="text-sm font-bold text-slate-100">
            Vulnerability Risk Distribution
          </h3>

          <p className="text-xs text-slate-400 mb-4">
            Categorized by severity returned from OSV analysis.
          </p>

          <div className="space-y-3">
            {[
              {
                label: 'Critical',
                count: severityCounts.critical,
                color: 'bg-red-500',
              },
              {
                label: 'High',
                count: severityCounts.high,
                color: 'bg-orange-500',
              },
              {
                label: 'Medium',
                count: severityCounts.medium,
                color: 'bg-amber-500',
              },
              {
                label: 'Low',
                count: severityCounts.low,
                color: 'bg-cyan-500',
              },
              {
                label: 'Unknown',
                count: severityCounts.unknown,
                color: 'bg-purple-500',
              },
            ].map((item) => (
              <div key={item.label} className="space-y-1">
                <div className="flex justify-between text-xs font-mono-tech">
                  <span className="text-slate-300">{item.label}</span>
                  <span className="text-slate-400">
                    {item.count} ({Math.round(vulnerabilityPercent(item.count))}%)
                  </span>
                </div>

                <div className="w-full h-2 bg-[#0d1320] rounded-full overflow-hidden border border-[#1c2742]">
                  <div
                    className={`h-full ${item.color} rounded-full`}
                    style={{
                      width: `${vulnerabilityPercent(item.count)}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-5">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-sm font-bold text-slate-100">
              SBOM Quality Indicators
            </h3>

            <button
              onClick={() => onNavigateTab?.('quality')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              Full Audit →
            </button>
          </div>

          <p className="text-xs text-slate-400 mb-3">
            Evaluation of data completeness across standards.
          </p>

          <div className="space-y-2.5">
            {qualityBreakdown.length === 0 ? (
              <p className="text-xs text-slate-500">
                No quality assessment returned by the backend.
              </p>
            ) : (
              qualityBreakdown.slice(0, 5).map((q) => (
                <div
                  key={q.label}
                  className="flex items-center justify-between text-xs"
                >
                  <div className="w-48 text-slate-300 truncate">
                    {q.label}
                  </div>

                  <div className="flex-1 mx-4">
                    <div className="w-full h-2 bg-[#0d1320] rounded-full overflow-hidden border border-[#1c2742]">
                      <div
                        className={`h-full rounded-full ${
                          q.score >= 90
                            ? 'bg-emerald-400'
                            : q.score >= 70
                              ? 'bg-amber-400'
                              : 'bg-red-400'
                        }`}
                        style={{
                          width: `${Math.max(
                            0,
                            Math.min(100, Number(q.score) || 0)
                          )}%`,
                        }}
                      />
                    </div>
                  </div>

                  <div className="w-20 text-right">
                    <AuditStatusBadge status={q.status} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Uncertain Findings */}
      <div className="bg-[#161226] border border-purple-500/30 rounded-xl p-6">
        <div className="flex items-start gap-4">
          <div className="w-10 h-10 rounded-lg bg-purple-500/20 border border-purple-500/40 flex items-center justify-center">
            <AlertTriangleIcon className="w-5 h-5 text-purple-400" />
          </div>

          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold uppercase tracking-wider text-purple-300 font-mono-tech">
                Uncertain Findings
              </h3>

              <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono-tech bg-purple-500/20 text-purple-200 border border-purple-500/30">
                {uncertainFindings.length} Items Require Review
              </span>
            </div>

            <p className="text-xs text-slate-200 mt-2 font-medium">
              {uncertainFindings.length > 0
                ? 'Some findings could not be confidently contextualized from the uploaded SBOM.'
                : 'No uncertain findings were returned by the backend.'}
            </p>

            {uncertainFindings.length > 0 && (
              <>
                <div className="mt-3 p-3 rounded-lg bg-[#0d091a] border border-purple-500/25">
                  <div className="text-xs font-bold text-amber-300 uppercase tracking-wide font-mono-tech">
                    ⚠ CORE SECURITY PRINCIPLE: UNKNOWN DOES NOT MEAN SAFE.
                  </div>

                  <p className="text-xs text-slate-300 mt-1">
                    Insufficient SBOM context prevents confident risk
                    classification.
                  </p>
                </div>

                <div className="mt-4 flex items-center gap-3">
                  <button
                    onClick={() =>
                      onNavigateTab?.('vulnerabilities')
                    }
                    className="px-3.5 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold"
                  >
                    Review Uncertain Findings
                  </button>

                  <button
                    onClick={() => onNavigateTab?.('quality')}
                    className="px-3 py-1.5 rounded-lg text-purple-300 text-xs font-medium border border-purple-500/30"
                  >
                    Inspect SBOM Gaps
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}