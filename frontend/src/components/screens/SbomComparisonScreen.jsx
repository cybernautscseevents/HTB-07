import React, { useState } from 'react';
import { compareSboms, generateUpdatedSbom } from '../../services/api';
import { saveBlob } from '../../services/download';

const inputClass = 'block w-full rounded-lg border border-[#253659] bg-[#0d1320] p-3 text-xs text-slate-300 file:mr-3 file:rounded file:border-0 file:bg-blue-600/20 file:px-3 file:py-2 file:text-xs file:font-semibold file:text-blue-300';

function ChangeList({ title, items, color, renderItem }) {
  return (
    <section className="rounded-xl border border-[#1b253b] bg-[#101726] p-5">
      <h3 className={`text-sm font-bold ${color}`}>{title} <span className="text-slate-500">({items.length})</span></h3>
      {items.length ? (
        <ul className="mt-4 divide-y divide-[#1b253b]">
          {items.map((item, index) => <li key={`${item.identity}-${index}`} className="py-3 text-xs text-slate-300">{renderItem(item)}</li>)}
        </ul>
      ) : <p className="mt-3 text-xs text-slate-500">No changes.</p>}
    </section>
  );
}

export function SbomComparisonScreen() {
  const [baselineFile, setBaselineFile] = useState(null);
  const [updatedFile, setUpdatedFile] = useState(null);
  const [result, setResult] = useState(null);
  const [generatedSbom, setGeneratedSbom] = useState(null);
  const [error, setError] = useState('');
  const [pending, setPending] = useState(false);

  const handleCompare = async (event) => {
    event.preventDefault();
    if (!baselineFile || !updatedFile || pending) return;
    setPending(true);
    setError('');
    setResult(null);
    setGeneratedSbom(null);
    try {
      const [baseline, updated] = await Promise.all([baselineFile.text(), updatedFile.text()]);
      setResult(await compareSboms(
        { fileName: baselineFile.name, content: baseline },
        { fileName: updatedFile.name, content: updated },
      ));
    } catch (requestError) {
      setError(requestError.message || 'SBOM comparison failed.');
    } finally {
      setPending(false);
    }
  };

  const handleGenerateUpdated = async () => {
    if (!baselineFile || pending) return;
    setPending(true);
    setError('');
    setResult(null);
    setGeneratedSbom(null);
    try {
      const baselineContent = await baselineFile.text();
      const generated = await generateUpdatedSbom(baselineFile.name, baselineContent);
      const updatedContent = JSON.stringify(generated.sbom, null, 2);
      setGeneratedSbom(generated);
      const comparison = await compareSboms(
        { fileName: baselineFile.name, content: baselineContent },
        { fileName: generated.fileName, content: updatedContent },
      );
      setResult(comparison);
    } catch (requestError) {
      setError(requestError.message || 'Could not generate an updated SBOM.');
    } finally {
      setPending(false);
    }
  };

  const handleDownload = async () => {
    try {
      await saveBlob(
        new Blob([JSON.stringify(generatedSbom.sbom, null, 2)], { type: 'application/json' }),
        generatedSbom.fileName,
      );
      setError('');
    } catch (downloadError) {
      if (downloadError.name !== 'AbortError') {
        setError(downloadError.message || 'Could not save the updated SBOM.');
      }
    }
  };

  return (
    <div className="max-w-6xl space-y-6 pb-12">
      <div>
        <h2 className="text-xl font-bold tracking-tight text-slate-100">SBOM Comparison</h2>
        <p className="mt-1 text-xs text-slate-400">Compare two CycloneDX or SPDX JSON inventories to see package additions, removals, and version changes.</p>
      </div>

      <form onSubmit={handleCompare} className="grid gap-4 rounded-xl border border-[#1b253b] bg-[#101726] p-5 md:grid-cols-[1fr_1fr_auto] md:items-end">
        <label className="space-y-2 text-xs font-semibold text-slate-300">
          <span>Baseline SBOM</span>
          <input className={inputClass} type="file" accept=".json,.spdx,.cdx,application/json" onChange={(event) => { setBaselineFile(event.target.files?.[0] || null); setGeneratedSbom(null); setResult(null); }} required />
        </label>
        <label className="space-y-2 text-xs font-semibold text-slate-300">
          <span>Updated SBOM</span>
          <input className={inputClass} type="file" accept=".json,.spdx,.cdx,application/json" onChange={(event) => setUpdatedFile(event.target.files?.[0] || null)} required />
        </label>
        <button type="submit" disabled={!baselineFile || !updatedFile || pending} className="rounded-lg bg-blue-600 px-4 py-3 text-xs font-bold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50">
          {pending ? 'Comparing…' : 'Compare SBOMs'}
        </button>
      </form>

      <section className="rounded-xl border border-[#1b253b] bg-[#101726] p-5">
        <h3 className="text-sm font-bold text-slate-100">Generate an updated SBOM</h3>
        <p className="mt-1 text-xs text-slate-400">Use OSV-listed fixed versions to create a suggested updated copy of the baseline SBOM. No second upload is needed.</p>
        <button
          type="button"
          onClick={handleGenerateUpdated}
          disabled={!baselineFile || pending}
          className="mt-4 rounded-lg border border-blue-500/40 bg-blue-600/15 px-4 py-2.5 text-xs font-semibold text-blue-200 hover:bg-blue-600/25 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {pending ? 'Generating and comparing…' : 'Generate updated SBOM & compare'}
        </button>
      </section>

      <p className="text-[11px] text-slate-500">Inventory comparison only. This feature does not scan for or detect vulnerabilities.</p>

      {error && <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">{error}</p>}

      {generatedSbom && (
        <section className="rounded-xl border border-blue-500/25 bg-blue-500/5 p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100">Generated updated SBOM</h3>
              <p className="mt-1 text-xs text-slate-400">{generatedSbom.summary.updatedComponents} component(s) updated · {generatedSbom.fileName}</p>
            </div>
            <button
              type="button"
              onClick={handleDownload}
              className="rounded-lg border border-blue-500/40 bg-blue-600/15 px-4 py-2.5 text-xs font-semibold text-blue-200 hover:bg-blue-600/25"
            >
              Download updated SBOM (.json)
            </button>
          </div>
          <p className="mt-3 text-xs text-amber-200">{generatedSbom.note}</p>
          {generatedSbom.changes.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-slate-300">
              {generatedSbom.changes.map((change) => (
                <li key={`${change.name}-${change.fromVersion}`}>
                  {change.name}: {change.fromVersion} → {change.toVersion} ({change.fixedFindings} finding(s) with listed fixes)
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {result && (
        <>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {[
              ['Added', result.summary.added, 'text-emerald-300'],
              ['Removed', result.summary.removed, 'text-red-300'],
              ['Version changes', result.summary.versionChanges, 'text-amber-300'],
              ['Unchanged', result.summary.unchanged, 'text-slate-200'],
            ].map(([label, count, color]) => (
              <div key={label} className="rounded-xl border border-[#1b253b] bg-[#101726] p-4">
                <p className="text-[11px] uppercase tracking-wider text-slate-500">{label}</p>
                <p className={`mt-2 text-2xl font-bold ${color}`}>{count}</p>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-400">
            {result.baseline.fileName || 'Baseline'} ({result.baseline.format}) → {result.updated.fileName || 'Updated'} ({result.updated.format})
          </p>
          <div className="grid gap-4 lg:grid-cols-3">
            <ChangeList title="Added components" items={result.addedComponents} color="text-emerald-300" renderItem={(item) => <>{item.name} <span className="text-slate-500">{item.version || 'version unknown'} · {item.ecosystem || 'ecosystem unknown'}</span></>} />
            <ChangeList title="Removed components" items={result.removedComponents} color="text-red-300" renderItem={(item) => <>{item.name} <span className="text-slate-500">{item.version || 'version unknown'} · {item.ecosystem || 'ecosystem unknown'}</span></>} />
            <ChangeList title="Version changes" items={result.versionChanges} color="text-amber-300" renderItem={(item) => <>{item.name} <span className="text-slate-500">{item.fromVersion || 'unknown'} → {item.toVersion || 'unknown'}</span></>} />
          </div>
        </>
      )}
    </div>
  );
}
