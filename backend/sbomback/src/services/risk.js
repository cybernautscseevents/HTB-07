// Contextual risk model. Transparent by design: every number can be explained by the returned factors.
const BASE = { CRITICAL: 95, HIGH: 80, MEDIUM: 55, LOW: 25, UNKNOWN: 50 }; // used when no CVSS score is available
const DEP = { DIRECT: 1, TRANSITIVE: 0.85, UNKNOWN: 0.92 };
const ENV = { PRODUCTION: 1, DEVELOPMENT: 0.6, UNKNOWN: 0.95 };

function assess({ severity, cvss }, comp, ctx, fixAvailable) {
  const base = cvss !== null ? cvss * 10 : BASE[severity];
  // UNKNOWN context is discounted only slightly: missing information must never lower risk to "safe".
  let score = base * DEP[ctx.dependencyType] * ENV[comp.environment] + (fixAvailable ? 0 : 4);
  score = Math.max(0, Math.min(100, Math.round(score)));

  const known = [severity !== 'UNKNOWN', ctx.dependencyType !== 'UNKNOWN', comp.environment !== 'UNKNOWN', !!comp.version].filter(Boolean).length;
  let confidence = ['UNKNOWN', 'LOW', 'LOW', 'MEDIUM', 'HIGH'][known];
  if (severity === 'UNKNOWN' || !comp.version) confidence = 'UNKNOWN';
  const missing = [];
  if (severity === 'UNKNOWN') missing.push('the advisory has no usable severity rating');
  if (ctx.dependencyType === 'UNKNOWN') missing.push('dependency relationship information is incomplete');
  if (comp.environment === 'UNKNOWN') missing.push('the SBOM does not state whether the component is production or development');
  const confidenceReason = missing.length
    ? `Risk could not be confidently determined because ${missing.join(' and ')}.`
    : 'Severity, dependency type and environment are all known.';

  const f = (key, label, status, detail) => ({ key, label, status, detail });
  const factors = [
    severity === 'UNKNOWN' ? f('severity', 'Severity unknown', 'unknown', 'No CVSS vector or severity label in the advisory')
      : f('severity', `${severity[0]}${severity.slice(1).toLowerCase()} severity`, ['CRITICAL', 'HIGH'].includes(severity) ? 'risk' : 'neutral', cvss !== null ? `CVSS v3 base score ${cvss}` : 'Advisory severity label'),
    ctx.dependencyType === 'UNKNOWN' ? f('dependency', 'Dependency type unknown', 'unknown', 'SBOM relationships do not place this component in the dependency graph')
      : f('dependency', ctx.dependencyType === 'DIRECT' ? 'Direct dependency' : 'Transitive dependency', ctx.dependencyType === 'DIRECT' ? 'risk' : 'neutral', ctx.dependencyType === 'DIRECT' ? 'Referenced directly by the application' : 'Pulled in through another package'),
    comp.environment === 'UNKNOWN' ? f('environment', 'Environment unknown', 'unknown', 'No production/development scope in the SBOM')
      : f('environment', comp.environment === 'PRODUCTION' ? 'Production dependency' : 'Development dependency', comp.environment === 'PRODUCTION' ? 'risk' : 'neutral', 'From SBOM scope information'),
    f('exploitability', 'Exploitability not assessed', 'unknown', 'Exploit/KEV/EPSS data is not queried in this MVP'),
    fixAvailable ? f('fix', 'Fix available', 'good', 'A fixed version is recorded in the advisory') : f('fix', 'No fix recorded', 'risk', 'Adds 4 points: remediation is harder'),
  ];
  return { riskScore: score, confidence, confidenceReason, factors };
}

const riskLabel = (n) => (n >= 90 ? 'CRITICAL' : n >= 70 ? 'HIGH' : n >= 40 ? 'MEDIUM' : 'LOW');

function overall(findings, unassessed) {
  if (!findings.length) {
    return { score: 0, label: unassessed ? 'UNKNOWN' : 'NO_KNOWN_FINDINGS',
      explanation: unassessed
        ? `No known vulnerabilities were returned, but ${unassessed} component(s) could not be checked. Unknown does not mean safe.`
        : 'No known vulnerabilities were returned for the components analyzed by the current vulnerability intelligence. This is not a guarantee of security.' };
  }
  const scores = findings.map((x) => x.riskScore).sort((a, b) => b - a);
  const top5 = scores.slice(0, 5);
  const score = Math.round(scores[0] * 0.6 + (top5.reduce((a, b) => a + b, 0) / top5.length) * 0.4);
  const c = (s) => findings.filter((x) => x.severity === s).length;
  const direct = findings.filter((x) => x.dependency.type === 'DIRECT').length;
  const parts = [c('CRITICAL') && `${c('CRITICAL')} critical`, c('HIGH') && `${c('HIGH')} high-severity`].filter(Boolean).join(' and ');
  return { score, label: riskLabel(score),
    explanation: parts
      ? `Risk is driven by ${parts} finding(s), ${direct} of ${findings.length} in direct dependencies.`
      : `No critical or high-severity findings; ${findings.length} finding(s) of lower severity or unknown severity.` };
}

module.exports = { assess, overall, riskLabel };
