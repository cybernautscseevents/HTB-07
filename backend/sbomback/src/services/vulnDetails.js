const { cvss3BaseScore, severityFromScore } = require('./cvss');
const { compareVersions } = require('./version');

const LABELS = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', LOW: 'LOW' };

function severityOf(v) {
  for (const s of v.severity || []) {
    const score = cvss3BaseScore(s.score);
    if (score !== null) return { severity: severityFromScore(score), cvss: score, source: 'CVSS v3 vector' };
  }
  const label = [v.database_specific && v.database_specific.severity,
    ...(v.affected || []).map((a) => a.ecosystem_specific && a.ecosystem_specific.severity)]
    .map((x) => LABELS[String(x || '').toUpperCase()]).find(Boolean);
  if (label) return { severity: label, cvss: null, source: 'Advisory severity label' };
  return { severity: 'UNKNOWN', cvss: null, source: null };
}

const norm = (s) => String(s || '').toLowerCase().replace(/[-_.]+/g, '-');

function affectedFor(v, comp) {
  const list = v.affected || [];
  const match = list.filter((a) => {
    const p = a.package || {};
    if (p.purl && comp.purl) return norm(p.purl.split('@')[0]) === norm(comp.purl.split('@')[0]);
    return norm(p.name) === norm(comp.name) || (comp.purlParts && norm(p.name) === norm([comp.purlParts.namespace, comp.purlParts.name].filter(Boolean).join(':')));
  });
  return match.length ? match : list;
}

function rangesAndFixes(v, comp) {
  const ranges = [];
  const fixed = new Set();
  affectedFor(v, comp).forEach((a) => (a.ranges || []).forEach((r) => {
    if (!['SEMVER', 'ECOSYSTEM'].includes(r.type)) return;
    let current = {};
    (r.events || []).forEach((e) => {
      if (e.introduced !== undefined) current = { introduced: e.introduced };
      if (e.fixed !== undefined) { ranges.push({ ...current, fixed: e.fixed }); fixed.add(e.fixed); current = {}; }
      if (e.last_affected !== undefined) { ranges.push({ ...current, lastAffected: e.last_affected }); current = {}; }
    });
    if (current.introduced !== undefined) ranges.push(current);
  }));
  return { ranges, fixedVersions: [...fixed] };
}

function pickFix(fixedVersions, installed) {
  if (!fixedVersions.length) return null;
  const sorted = [...fixedVersions].sort(compareVersions);
  const higher = installed ? sorted.find((f) => compareVersions(f, installed) > 0) : null;
  return higher || sorted[sorted.length - 1];
}

const describeRange = (r) => (r.introduced !== undefined ? `>= ${r.introduced === '0' ? '0 (all earlier versions)' : r.introduced}` : 'any version')
  + (r.fixed ? `, < ${r.fixed}` : r.lastAffected ? `, <= ${r.lastAffected}` : ', no fix recorded');

function remediationCommand(comp, fixed) {
  if (!fixed) return null;
  const p = comp.purlParts || {};
  switch (comp.ecosystem) {
    case 'npm': return `npm install ${p.name ? [p.namespace, p.name].filter(Boolean).join('/') : comp.name}@${fixed}`;
    case 'PyPI': return `pip install "${comp.name}==${fixed}"`;
    case 'Go': return `go get ${[p.namespace, comp.name].filter(Boolean).join('/')}@v${fixed.replace(/^v/, '')}`;
    case 'crates.io': return `cargo update -p ${comp.name} --precise ${fixed}`;
    case 'RubyGems': return `bundle update ${comp.name}`;
    case 'NuGet': return `dotnet add package ${comp.name} --version ${fixed}`;
    case 'Maven': return null; // no generic command; guidance text is returned instead
    default: return null;
  }
}

const remediationText = (comp, fixed) => (fixed
  ? `Upgrade ${comp.name} to ${fixed}${comp.ecosystem === 'Maven' ? ' by updating the dependency version in your build file (pom.xml / build.gradle)' : ''}`
  : `No fixed version is recorded for ${comp.name}. Check the advisory for mitigations or consider an alternative package.`);

module.exports = { severityOf, rangesAndFixes, pickFix, describeRange, remediationCommand, remediationText };
