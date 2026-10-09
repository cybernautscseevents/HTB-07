import React, { useState } from 'react';
import { DownloadIcon, CheckCircleIcon, ShieldIcon } from '../common/Icons';
import { SeverityBadge } from '../common/Badge';
import { exportScan } from '../../services/api';
import { downloadBlob } from '../../services/download';

export function ReportsScreen({
  scanData,
  vulnerabilities = [],
  components = []
}) {
  const [downloadSuccess, setDownloadSuccess] = useState(null);
  const [downloadError, setDownloadError] = useState(null);
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async (format) => {
    if (!scanData?.id || isExporting) return;

    setIsExporting(true);
    setDownloadSuccess(null);
    setDownloadError(null);
    try {
      const { blob, fileName } = await exportScan(scanData.id, format);
      downloadBlob(blob, fileName);
      setDownloadSuccess(`${format.toUpperCase()} report exported successfully.`);
      window.setTimeout(() => setDownloadSuccess(null), 3000);
    } catch (error) {
      setDownloadError(error.message || 'Failed to export the scan results.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleDownloadJSON = () => handleExport('json');

  const handleDownloadCSV = () => handleExport('csv');

  const criticalVulns = vulnerabilities.filter(
    (v) =>
      v.severity === 'CRITICAL' ||
      v.severity === 'HIGH'
  );

  const riskLevel =
    scanData?.overallRisk?.level || 'UNKNOWN';

  const riskScore =
    scanData?.overallRisk?.score ?? 0;

  const trustScore =
    scanData?.sbomTrust?.score ?? 0;

  const uncertainFindings =
    scanData?.uncertainFindings?.length ?? 0;

  const totalComponents =
    scanData?.totalComponents ?? components.length;

  const vulnerabilitiesCount =
    scanData?.vulnerabilitiesCount ?? vulnerabilities.length;

  return (
    <div className="space-y-6 max-w-5xl pb-16">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">

        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">
            Security & Trust Reports
          </h2>

          <p className="text-xs text-slate-400 mt-1">
            Generate and export audit reports from the current SBOM analysis.
          </p>
        </div>

        <div className="flex items-center gap-3">

          <button
            onClick={handleDownloadCSV}
            disabled={!scanData?.id || isExporting}
            className="px-4 py-2 rounded-lg bg-[#141d30] hover:bg-[#1a2640] border border-[#223354] text-slate-200 text-xs font-semibold flex items-center gap-2 transition-colors"
          >
            <DownloadIcon className="w-4 h-4 text-blue-400" />
            <span>{isExporting ? 'Exporting…' : 'Export CSV'}</span>
          </button>

          <button
            onClick={handleDownloadJSON}
            disabled={!scanData?.id || isExporting}
            className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-blue-600/30 flex items-center gap-2 transition-colors"
          >
            <DownloadIcon className="w-4 h-4" />
            <span>Export Full JSON Report</span>
          </button>

        </div>
      </div>

      {/* Success Notification */}
      {downloadSuccess && (
        <div className="p-3 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircleIcon className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{downloadSuccess}</span>
        </div>
      )}

      {downloadError && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-xs">
          {downloadError}
        </div>
      )}

      {/* No Scan */}
      {!scanData ? (
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-10 text-center">

          <ShieldIcon className="w-8 h-8 text-slate-600 mx-auto mb-3" />

          <h3 className="text-sm font-semibold text-slate-300">
            No scan available
          </h3>

          <p className="text-xs text-slate-500 mt-1">
            Upload and analyze an SBOM before generating a report.
          </p>

        </div>
      ) : (
        <div className="bg-[#101726] border border-[#1b253b] rounded-xl p-6 space-y-6">

          {/* Executive Report Summary */}
          <div className="border-b border-[#182338] pb-4 flex items-center justify-between">

            <div>
              <div className="text-xs font-mono-tech text-blue-400 uppercase tracking-wider font-semibold">
                Executive Audit Brief
              </div>

              <h3 className="text-lg font-bold text-slate-100 mt-1">
                {scanData.scanName || 'SBOM Security Audit'}
              </h3>

              <div className="text-xs text-slate-400 font-mono-tech mt-1">
                File: {scanData.sbomFile || '—'}
                {' • '}
                Evaluated: {scanData.scanDate ? new Date(scanData.scanDate).toLocaleString() : '—'}
              </div>
            </div>

            <div className="text-right">

              <span className="px-3 py-1 rounded text-xs font-bold font-mono-tech uppercase bg-blue-500/15 text-blue-400 border border-blue-500/30">
                Risk: {riskLevel} ({riskScore}/100)
              </span>

            </div>
          </div>

          {/* Statistics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">

            <div className="p-3.5 rounded-lg bg-[#0d1320] border border-[#182338]">
              <div className="text-[11px] font-mono-tech text-slate-400 uppercase">
                Total Inventory
              </div>

              <div className="text-xl font-bold font-mono-tech text-slate-100 mt-1">
                {totalComponents} Packages
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0d1320] border border-[#182338]">
              <div className="text-[11px] font-mono-tech text-slate-400 uppercase">
                Identified Vulns
              </div>

              <div className="text-xl font-bold font-mono-tech text-red-400 mt-1">
                {vulnerabilitiesCount} Advisories
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0d1320] border border-[#182338]">
              <div className="text-[11px] font-mono-tech text-slate-400 uppercase">
                SBOM Trust Rating
              </div>

              <div className="text-xl font-bold font-mono-tech text-amber-400 mt-1">
                {trustScore}%
              </div>
            </div>

            <div className="p-3.5 rounded-lg bg-[#0d1320] border border-[#182338]">
              <div className="text-[11px] font-mono-tech text-slate-400 uppercase">
                Uncertain Findings
              </div>

              <div className="text-xl font-bold font-mono-tech text-purple-400 mt-1">
                {uncertainFindings} Items
              </div>
            </div>

          </div>

          {/* Dynamic Assessment */}
          <div className="p-4 rounded-lg bg-[#0d1320] border border-[#182338] space-y-2">

            <div className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono-tech flex items-center gap-2">
              <ShieldIcon className="w-4 h-4 text-blue-400" />
              <span>Auditor Assessment</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">

              {vulnerabilitiesCount === 0 ? (
                <>
                  No vulnerabilities were returned for the components in this
                  SBOM. The report reflects the results currently available
                  from the vulnerability analysis.
                </>
              ) : (
                <>
                  The current SBOM contains {vulnerabilitiesCount}
                  {' '}identified vulnerability findings.{' '}

                  {criticalVulns.length > 0
                    ? `${criticalVulns.length} findings are classified as HIGH or CRITICAL and should receive priority review.`
                    : 'No HIGH or CRITICAL findings were identified.'
                  }

                  {' '}Risk and trust scores shown above are calculated from
                  the current backend analysis.
                </>
              )}

            </p>

          </div>

          {/* Priority Action Items */}
          <div>

            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono-tech mb-3">
              Priority Action Plan
            </h4>

            <div className="overflow-x-auto rounded-lg border border-[#182338]">

              <table className="w-full text-left text-xs">

                <thead className="bg-[#0b0f1a] text-slate-400 font-mono-tech uppercase text-[11px] border-b border-[#182338]">

                  <tr>
                    <th className="py-2.5 px-3">
                      Priority
                    </th>

                    <th className="py-2.5 px-3">
                      Component
                    </th>

                    <th className="py-2.5 px-3">
                      Vulnerability
                    </th>

                    <th className="py-2.5 px-3">
                      Severity
                    </th>

                    <th className="py-2.5 px-3">
                      Recommended Remediation
                    </th>
                  </tr>

                </thead>

                <tbody className="divide-y divide-[#162035]">

                  {criticalVulns.length === 0 ? (

                    <tr>
                      <td
                        colSpan="5"
                        className="py-8 text-center text-slate-500"
                      >
                        No HIGH or CRITICAL vulnerabilities found.
                      </td>
                    </tr>

                  ) : (

                    criticalVulns.slice(0, 5).map((v, index) => (

                      <tr
                        key={v.id || `${v.package}-${index}`}
                        className="hover:bg-[#131b2e]"
                      >

                        <td className="py-2.5 px-3 font-mono-tech font-bold text-slate-300">
                          #{v.priority ?? index + 1}
                        </td>

                        <td className="py-2.5 px-3 font-mono-tech font-bold text-slate-100">
                          {v.package || v.component || '-'}
                        </td>

                        <td className="py-2.5 px-3 font-mono-tech text-slate-300">
                          {v.id || '-'}
                        </td>

                        <td className="py-2.5 px-3">
                          <SeverityBadge
                            severity={v.severity}
                            size="sm"
                          />
                        </td>

                        <td className="py-2.5 px-3 font-mono-tech text-emerald-400 font-medium">
                          {v.remediationCommand ||
                            (v.fixedVersion
                              ? `Upgrade to ${v.fixedVersion}`
                              : 'Review available remediation')}
                        </td>

                      </tr>

                    ))

                  )}

                </tbody>

              </table>

            </div>

          </div>

        </div>
      )}

    </div>
  );
}