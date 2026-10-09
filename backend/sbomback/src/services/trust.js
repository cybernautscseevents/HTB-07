// SBOM Trust / Quality score: how sufficient is the SBOM for reliable security analysis?
const pct = (n, d) => (d ? Math.round((n / d) * 100) : 0);
const dimStatus = (p) => (p >= 90 ? 'GOOD' : p >= 70 ? 'WARNING' : 'INCOMPLETE');
const ntiaStatus = (p) => (p >= 95 ? 'PASS' : p > 0 ? 'WARNING' : 'MISSING');
const WEIGHTS = { formatValidity: 15, componentIdentity: 15, versionCoverage: 20, purlCoverage: 15, relationshipCoverage: 15, metadataCompleteness: 10, hashCoverage: 10 };

function computeTrust(parsed, unassessedCount, findingsNeedingContext) {
  const comps = parsed.components;
  const n = comps.length;
  const withName = comps.filter((c) => c.name).length;
  const withVersion = comps.filter((c) => c.version).length;
  const withPurl = comps.filter((c) => c.purlParts).length;
  const withHash = comps.filter((c) => c.hasHash).length;
  const withSupplier = comps.filter((c) => c.supplier).length;
  const withLicense = comps.filter((c) => c.licenses.length).length;
  const inGraph = comps.filter((c) => parsed.mentioned.has(c.id)).length;

  const docMeta = pct([parsed.timestamp, parsed.documentName, parsed.hasTools].filter(Boolean).length, 3);
  const raw = {
    formatValidity: pct(parsed.checks.filter(([, ok]) => ok).length, parsed.checks.length),
    componentIdentity: pct(withName, n),
    versionCoverage: pct(withVersion, n),
    purlCoverage: pct(withPurl, n),
    relationshipCoverage: pct(inGraph, n),
    metadataCompleteness: Math.round(pct(withSupplier + withLicense, 2 * n) * 0.8 + docMeta * 0.2),
    hashCoverage: pct(withHash, n),
  };
  const labels = { formatValidity: 'Format Validity', componentIdentity: 'Component Identity', versionCoverage: 'Version Coverage',
    purlCoverage: 'PURL Coverage', relationshipCoverage: 'Relationship Coverage', metadataCompleteness: 'Metadata Completeness', hashCoverage: 'Hash Coverage' };
  const breakdown = Object.keys(raw).map((key) => ({ key, label: labels[key], percent: raw[key], status: dimStatus(raw[key]), weight: WEIGHTS[key] }));
  const score = Math.round(breakdown.reduce((s, b) => s + b.percent * b.weight, 0) / 100);
  const rating = score >= 90 ? 'GOOD' : score >= 70 ? 'GOOD_WITH_WARNINGS' : score >= 50 ? 'INCOMPLETE' : 'POOR';

  const ntia = [
    { key: 'supplier', label: 'Supplier', p: pct(withSupplier, n), detail: `${withSupplier}/${n} components` },
    { key: 'componentName', label: 'Component Name', p: raw.componentIdentity, detail: `${withName}/${n} components` },
    { key: 'version', label: 'Version', p: raw.versionCoverage, detail: `${withVersion}/${n} components` },
    { key: 'relationships', label: 'Dependency Relationships', p: raw.relationshipCoverage, detail: `${inGraph}/${n} components in the dependency graph` },
    { key: 'timestamp', label: 'Timestamp', p: parsed.timestamp ? 100 : 0, detail: parsed.timestamp || 'No timestamp in document' },
    { key: 'uniqueId', label: 'Unique Identifier', p: raw.purlCoverage, detail: `${withPurl}/${n} components have a purl` },
    { key: 'hash', label: 'Cryptographic Hash', p: raw.hashCoverage, detail: `${withHash}/${n} components` },
  ].map(({ p, ...rest }) => ({ ...rest, percent: p, status: ntiaStatus(p) }));

  const warnings = [];
  if (n - inGraph) warnings.push(`${n - inGraph} components have missing relationship information.`);
  const incompleteMeta = comps.filter((c) => !c.supplier || !c.licenses.length).length;
  if (incompleteMeta) warnings.push(`${incompleteMeta} components have incomplete metadata.`);
  if (n - withVersion) warnings.push(`${n - withVersion} components have no version and cannot be checked for vulnerabilities.`);
  if (n - withPurl) warnings.push(`${n - withPurl} components have no package URL (purl).`);
  if (findingsNeedingContext) warnings.push(`${findingsNeedingContext} findings have insufficient context.`);
  if (!parsed.timestamp) warnings.push('The document has no timestamp.');

  const checks = [
    { status: raw.formatValidity === 100 ? 'pass' : 'warn', text: `${raw.formatValidity === 100 ? 'Valid' : 'Partially valid'} ${parsed.format} document` },
    { status: raw.versionCoverage >= 95 ? 'pass' : 'warn', text: raw.versionCoverage >= 95 ? 'Component versions available' : 'Some component versions missing' },
    { status: raw.purlCoverage >= 95 ? 'pass' : 'warn', text: raw.purlCoverage >= 95 ? 'Package identifiers available' : 'Some package identifiers missing' },
    { status: raw.relationshipCoverage >= 95 ? 'pass' : 'warn', text: raw.relationshipCoverage >= 95 ? 'Dependency relationships complete' : 'Dependency relationships incomplete' },
    { status: raw.metadataCompleteness >= 90 ? 'pass' : 'warn', text: raw.metadataCompleteness >= 90 ? 'Component metadata complete' : 'Some component metadata missing' },
  ];
  return { score, rating, breakdown, ntia, warnings, checks,
    principle: 'UNKNOWN DOES NOT MEAN SAFE. Risk could not be confidently determined where required SBOM context is incomplete.' };
}

module.exports = { computeTrust };
