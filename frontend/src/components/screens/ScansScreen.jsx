import React from 'react';
import { RiskScoreBadge } from '../common/Badge';
import { HistoryIcon, UploadCloudIcon, CheckCircleIcon } from '../common/Icons';

export function ScansScreen({
  scans = [],
  onNewScan,
  onSelectScan,
  currentScanId
}) {
  return (
    <div className="space-y-6 pb-12">

      {/* Header & New Scan Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 tracking-tight">
            Scans & Audit History
          </h2>

          <p className="text-xs text-slate-400 mt-1">
            Historical SBOM security audits and risk assessments.
          </p>
        </div>

        <button
          onClick={onNewScan}
          className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-bold uppercase tracking-wider shadow-lg shadow-blue-600/30 flex items-center gap-2 transition-colors shrink-0"
        >
          <UploadCloudIcon className="w-4 h-4" />
          <span>New Scan</span>
        </button>
      </div>

      {/* History Table */}
      <div className="bg-[#101726] border border-[#1b253b] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">

          <table className="w-full text-left text-xs">

            <thead className="bg-[#0b0f1a] text-slate-400 uppercase font-mono-tech text-[11px] border-b border-[#182338]">
              <tr>
                <th className="py-3 px-4">Scan</th>
                <th className="py-3 px-4">SBOM File</th>
                <th className="py-3 px-4">Format</th>
                <th className="py-3 px-4 text-center">Components</th>
                <th className="py-3 px-4 text-center">Vulnerabilities</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Trust</th>
                <th className="py-3 px-4">Date</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>

            <tbody className="divide-y divide-[#162035]">

              {scans.length === 0 ? (
                <tr>
                  <td
                    colSpan="10"
                    className="py-12 text-center text-slate-500"
                  >
                    <div className="flex flex-col items-center gap-2">
                      <HistoryIcon className="w-6 h-6 text-slate-600" />

                      <span className="text-sm">
                        No scans available
                      </span>

                      <span className="text-xs text-slate-600">
                        Upload an SBOM to create your first audit.
                      </span>
                    </div>
                  </td>
                </tr>
              ) : (

                scans.map((scan) => {

                  const isActive =
                    scan.isCurrent || scan.id === currentScanId;

                  return (
                    <tr
                      key={scan.id}
                      onClick={() => onSelectScan(scan)}
                      className={`hover:bg-[#151e33] transition-colors cursor-pointer ${
                        isActive ? 'bg-blue-900/10' : ''
                      }`}
                    >

                      {/* Scan */}
                      <td className="py-3.5 px-4">
                        <div className="font-bold text-slate-100 font-mono-tech flex items-center gap-2">

                          <span>
                            {scan.name || 'Unnamed scan'}
                          </span>

                          {isActive && (
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                              Active
                            </span>
                          )}

                        </div>
                      </td>

                      {/* SBOM File */}
                      <td className="py-3.5 px-4 font-mono-tech text-slate-400">
                        {scan.fileName || scan.sbomFile || '—'}
                      </td>

                      {/* Format */}
                      <td className="py-3.5 px-4 font-mono-tech text-slate-300">
                        {scan.format || '—'}
                      </td>

                      {/* Components */}
                      <td className="py-3.5 px-4 text-center font-mono-tech font-bold text-slate-200">
                        {scan.components ?? scan.summary?.totalComponents ?? '—'}
                      </td>

                      {/* Vulnerabilities */}
                      <td className="py-3.5 px-4 text-center font-mono-tech font-bold text-red-400">
                        {scan.vulnerabilities ?? scan.summary?.vulnerabilities ?? '—'}
                      </td>

                      {/* Risk */}
                      <td className="py-3.5 px-4">
                        <RiskScoreBadge
                          score={scan.riskScore ?? scan.risk?.score ?? 0}
                        />
                      </td>

                      {/* Trust */}
                      <td className="py-3.5 px-4 font-mono-tech">
                        <span
                          className={`font-bold ${
                            (scan.trust ?? scan.trustScore ?? 0) >= 80
                              ? 'text-emerald-400'
                              : 'text-amber-400'
                          }`}
                        >
                          {scan.trust ?? scan.trustScore ?? '—'}{(scan.trust ?? scan.trustScore) !== undefined ? '%' : ''}
                        </span>
                      </td>

                      {/* Date */}
                      <td className="py-3.5 px-4 font-mono-tech text-slate-400">
                        {scan.createdAt ? new Date(scan.createdAt).toLocaleString() : scan.date || '—'}
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400 font-medium">

                          <CheckCircleIcon className="w-3.5 h-3.5" />

                          <span>
                            {scan.status || 'Completed'}
                          </span>

                        </span>
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectScan(scan);
                          }}
                          className="px-3 py-1 rounded bg-[#1c2742] hover:bg-blue-600 hover:text-white text-blue-300 border border-[#2b3d63] text-xs font-medium transition-colors"
                        >
                          {isActive ? 'View Live' : 'Load Audit'}
                        </button>
                      </td>

                    </tr>
                  );
                })
              )}

            </tbody>
          </table>
        </div>
      </div>

      {/* Persistence Note */}
      <div className="p-4 rounded-xl bg-[#0d121f] border border-[#182236] text-xs text-slate-400 flex items-center justify-between">

        <div className="flex items-center gap-2">
          <HistoryIcon className="w-4 h-4 text-slate-400" />

          <span>
            Scan history is loaded from the backend.
          </span>
        </div>

        <span className="text-slate-400 font-mono-tech text-[11px]">
          Backend: /api/scans
        </span>

      </div>

    </div>
  );
}