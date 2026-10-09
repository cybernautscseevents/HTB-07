const COLUMNS = ['priority', 'package', 'version', 'ecosystem', 'vulnerabilityId', 'aliases', 'severity', 'cvss', 'riskScore',
  'dependencyType', 'environment', 'fixAvailable', 'fixedVersion', 'confidence', 'status'];

// Prefix formula-trigger characters so spreadsheet apps do not execute package-controlled text.
const cell = (v) => {
  let s = v === null || v === undefined ? '' : Array.isArray(v) ? v.join(' ') : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

function toCsv(scan) {
  const rows = scan.findings.map((f) => [f.priority, f.package, f.version, f.ecosystem, f.vulnerabilityId, f.aliases, f.severity, f.cvss,
    f.riskScore, f.dependency.type, f.dependency.environment, f.fixAvailable, f.fixedVersion, f.confidence, f.status]);
  return [COLUMNS, ...rows].map((r) => r.map(cell).join(',')).join('\n') + '\n';
}

function toJson(scan) {
  return { exportedAt: new Date().toISOString(),
    disclaimer: 'Generated from OSV data and the supplied SBOM. Exploitability and reachability are not assessed. Unknown does not mean safe.',
    scan };
}

function reportSummary(scan) {
  const critical = scan.findings.filter((f) => f.severity === 'CRITICAL').map((f) => ({ id: f.id, vulnerabilityId: f.vulnerabilityId, package: f.package, version: f.version, riskScore: f.riskScore }));
  const actions = scan.findings.filter((f) => f.fixAvailable).slice(0, 5).map((f) => f.remediation.action);
  if (scan.uncertain.count) actions.push(`Review ${scan.uncertain.count} finding(s) that could not be confidently contextualized.`);
  if (scan.trust.warnings.length) actions.push('Improve SBOM completeness: ' + scan.trust.warnings[0]);
  return { scan: { id: scan.id, name: scan.name, fileName: scan.fileName, format: scan.format, createdAt: scan.createdAt },
    components: scan.summary.totalComponents, vulnerabilities: scan.summary.vulnerabilities,
    risk: scan.risk, trust: { score: scan.trust.score, rating: scan.trust.rating }, criticalFindings: critical, recommendedActions: actions };
}

module.exports = { toCsv, toJson, reportSummary };
