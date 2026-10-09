const crypto = require('crypto');
const { parseSbom } = require('./sbomParser');
const { buildContext } = require('./graph');
const { severityOf, rangesAndFixes, pickFix, describeRange, remediationCommand, remediationText } = require('./vulnDetails');
const { assess, overall } = require('./risk');
const { computeTrust } = require('./trust');

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const ID_ORDER = [/^GHSA-/, /^CVE-/];
const primaryOf = (ids) => { for (const re of ID_ORDER) { const m = ids.find((i) => re.test(i)); if (m) return m; } return ids[0]; };

// Merge OSV records that describe the same issue (same id / shared aliases) for one component.
function mergeAliases(records) {
  const groups = [];
  records.forEach((r) => {
    const names = new Set([r.id, ...(r.aliases || [])]);
    const g = groups.find((x) => [...names].some((n) => x.names.has(n)));
    if (g) { names.forEach((n) => g.names.add(n)); g.records.push(r); } else groups.push({ names, records: [r] });
  });
  return groups;
}

async function analyze({ input, fileName, name }, { osv }) {
  const steps = [];
  const mark = (step) => steps.push({ step, status: 'done' });

  const parsed = parseSbom(input);
  mark('Validating SBOM'); mark('Extracting components');

  const ctxByKey = buildContext(parsed);
  parsed.components.forEach((c) => {
    const ctx = ctxByKey.get(c.key);
    c.dependencyType = ctx.dependencyType; c.dependencyPath = ctx.path;
  });

  const unassessed = parsed.components.filter((c) => !osv.canQuery(c));
  const idsByComp = await osv.queryComponents(parsed.components);
  const allIds = [...idsByComp.values()].flat();
  const details = await osv.getVulns(allIds);
  mark('Checking vulnerability intelligence');

  const findings = [];
  parsed.components.forEach((comp) => {
    const ids = idsByComp.get(comp.key) || [];
    const records = ids.map((id) => details.get(id) || { id, _missing: true });
    mergeAliases(records).forEach(({ records: grp }) => {
      const good = grp.find((r) => !r._missing) || grp[0];
      const all = [...new Set(grp.flatMap((r) => [r.id, ...(r.aliases || [])]))];
      const id = primaryOf(all);
      const sev = good._missing ? { severity: 'UNKNOWN', cvss: null, source: null } : severityOf(good);
      const { ranges, fixedVersions } = good._missing ? { ranges: [], fixedVersions: [] } : rangesAndFixes(good, comp);
      const fixedVersion = pickFix(fixedVersions, comp.version);
      const risk = assess(sev, comp, { dependencyType: comp.dependencyType }, !!fixedVersion);
      findings.push({
        id: crypto.createHash('sha1').update(`${id}|${comp.key}`).digest('hex').slice(0, 10),
        vulnerabilityId: id, aliases: all.filter((a) => a !== id), summary: good.summary || null,
        details: good.details || null, published: good.published || null,
        references: (good.references || []).slice(0, 8).map((r) => ({ type: r.type, url: r.url })),
        detailsUnavailable: !!good._missing,
        package: comp.name, version: comp.version, componentId: comp.key, ecosystem: comp.ecosystem,
        severity: sev.severity, cvss: sev.cvss, severitySource: sev.source,
        riskScore: risk.riskScore, confidence: risk.confidence, confidenceReason: risk.confidenceReason, factors: risk.factors,
        dependency: { type: comp.dependencyType, environment: comp.environment,
          label: `${comp.dependencyType === 'UNKNOWN' ? 'Unknown' : comp.dependencyType[0] + comp.dependencyType.slice(1).toLowerCase()} / ${comp.environment === 'UNKNOWN' ? 'Unknown' : comp.environment[0] + comp.environment.slice(1).toLowerCase()}`,
          path: comp.dependencyPath ? ['Application', ...comp.dependencyPath] : null },
        exploitability: { status: 'NOT_ASSESSED', note: 'Exploit, KEV and EPSS data are not queried in this MVP.' },
        fixAvailable: !!fixedVersion, fixedVersion, fixedVersions,
        affectedRanges: ranges.map(describeRange),
        remediation: { installed: comp.version, recommended: fixedVersion, action: remediationText(comp, fixedVersion), command: remediationCommand(comp, fixedVersion) },
        status: 'ACTIVE',
        uncertain: risk.confidence === 'LOW' || risk.confidence === 'UNKNOWN' || comp.dependencyType === 'UNKNOWN',
      });
    });
  });
  findings.sort((a, b) => b.riskScore - a.riskScore);
  findings.forEach((f, i) => { f.priority = i + 1; });
  mark('Calculating risk');

  const uncertainFindings = findings.filter((f) => f.uncertain).map((f) => ({
    findingId: f.id, vulnerabilityId: f.vulnerabilityId, package: f.package, reason: f.confidenceReason }));
  const trust = computeTrust(parsed, unassessed.length, uncertainFindings.length);
  mark('Calculating trust');

  const counts = Object.fromEntries(SEVERITIES.map((s) => [s.toLowerCase(), findings.filter((f) => f.severity === s).length]));
  const vulnKeys = new Set(findings.map((f) => f.componentId));
  const comps = parsed.components.map((c) => {
    const fs = findings.filter((f) => f.componentId === c.key);
    return { id: c.key, name: c.name, version: c.version, purl: c.purl, ecosystem: c.ecosystem, type: c.type,
      dependencyType: c.dependencyType, environment: c.environment, license: c.licenses[0] || null, supplier: c.supplier,
      vulnerabilityCount: fs.length, vulnerabilityIds: fs.map((f) => f.id),
      risk: fs.length ? Math.max(...fs.map((f) => f.riskScore)) : null,
      assessed: osv.canQuery(c), dependencyPath: c.dependencyPath ? ['Application', ...c.dependencyPath] : null };
  });
  const risk = overall(findings, unassessed.length);

  return {
    id: crypto.randomUUID(), name: name || (parsed.documentName) || fileName || 'Untitled scan', fileName: fileName || null,
    format: parsed.format, specVersion: parsed.specVersion, createdAt: new Date().toISOString(), status: 'COMPLETED',
    pipeline: steps, dataSource: { vulnerabilities: 'OSV (api.osv.dev)', exploitability: 'Not assessed', reachability: 'Not assessed' },
    summary: {
      totalComponents: comps.length, vulnerabilities: findings.length, vulnerableComponents: vulnKeys.size, ...counts,
      direct: comps.filter((c) => c.dependencyType === 'DIRECT').length, transitive: comps.filter((c) => c.dependencyType === 'TRANSITIVE').length,
      unknownDependencyType: comps.filter((c) => c.dependencyType === 'UNKNOWN').length,
      production: comps.filter((c) => c.environment === 'PRODUCTION').length, development: comps.filter((c) => c.environment === 'DEVELOPMENT').length,
      unknownEnvironment: comps.filter((c) => c.environment === 'UNKNOWN').length,
      unassessedComponents: unassessed.length,
    },
    risk: { score: risk.score, label: risk.label, explanation: risk.explanation },
    trust,
    uncertain: { count: uncertainFindings.length, findings: uncertainFindings,
      unassessedComponents: unassessed.map((c) => ({ componentId: c.key, name: c.name, reason: 'No version or package URL, so vulnerabilities cannot be looked up.' })),
      principle: 'UNKNOWN DOES NOT MEAN SAFE. Insufficient SBOM context prevents confident risk classification.' },
    distribution: SEVERITIES.map((s) => ({ severity: s, count: counts[s.toLowerCase()] })),
    findings, components: comps,
  };
}

module.exports = { analyze };
