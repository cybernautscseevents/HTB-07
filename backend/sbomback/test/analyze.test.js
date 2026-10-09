const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const mock = require('./mockOsv');

let server;
test.before(async () => {
  server = await mock.start();
  process.env.OSV_BASE_URL = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => server.close());

const sample = () => JSON.parse(fs.readFileSync(path.join(__dirname, '../samples/sample-cyclonedx.json'), 'utf8'));
const load = () => {
  const { createOsvClient } = require('../src/services/osvClient');
  return { analyze: require('../src/services/analyzer').analyze, osv: createOsvClient() };
};

test('analyzes a CycloneDX SBOM end to end', async () => {
  const { analyze, osv } = load();
  const scan = await analyze({ input: sample(), fileName: 'app-sbom.json' }, { osv });
  assert.equal(scan.format, 'CycloneDX');
  assert.equal(scan.summary.totalComponents, 5);
  assert.equal(scan.summary.vulnerabilities, 3, 'alias duplicates are merged');
  const min = scan.findings.find((f) => f.package === 'minimist');
  assert.equal(min.severity, 'CRITICAL');
  assert.equal(min.vulnerabilityId, 'GHSA-test-minimist');
  assert.deepEqual(min.aliases, ['CVE-2099-0002']);
  assert.equal(min.dependency.type, 'TRANSITIVE');
  assert.deepEqual(min.dependency.path, ['Application', 'mkdirp@0.5.1', 'minimist@0.0.8']);
  assert.equal(min.fixedVersion, '0.2.4');
  assert.equal(min.remediation.command, 'npm install minimist@0.2.4');
  const lodash = scan.findings.find((f) => f.package === 'lodash');
  assert.equal(lodash.dependency.label, 'Direct / Production');
  assert.equal(lodash.severity, 'HIGH'); // CVSS 7.5 computed from vector
  assert.equal(lodash.cvss, 7.5);
  const jest = scan.findings.find((f) => f.package === 'jest');
  assert.equal(jest.severity, 'MEDIUM');
  assert.ok(jest.riskScore < lodash.riskScore, 'dev dependency is scored lower');
  assert.equal(scan.findings[0].priority, 1);
});

test('unknown stays unknown, never safe', async () => {
  const { analyze, osv } = load();
  const scan = await analyze({ input: sample() }, { osv });
  assert.equal(scan.summary.unassessedComponents, 1);
  assert.equal(scan.uncertain.unassessedComponents[0].name, 'mystery-lib');
  assert.equal(scan.uncertain.count, 0); // every finding here has severity, dependency type and environment
  assert.equal(scan.findings.find((f) => f.package === 'minimist').confidence, 'HIGH');
  assert.equal(scan.risk.label === 'NO_KNOWN_FINDINGS', false);
});

test('trust score and NTIA checks', async () => {
  const { analyze, osv } = load();
  const { trust } = await analyze({ input: sample() }, { osv });
  assert.ok(trust.score > 0 && trust.score < 100);
  assert.equal(trust.ntia.find((x) => x.key === 'timestamp').status, 'PASS');
  assert.equal(trust.ntia.find((x) => x.key === 'hash').status, 'WARNING');
  assert.ok(trust.warnings.some((w) => /missing relationship/.test(w)));
});

test('SBOM without relationships yields UNKNOWN dependency type', async () => {
  const { analyze, osv } = load();
  const doc = sample(); delete doc.dependencies;
  const scan = await analyze({ input: doc }, { osv });
  assert.ok(scan.findings.every((f) => f.dependency.type === 'UNKNOWN'));
  assert.ok(scan.uncertain.count > 0);
});

test('SPDX is parsed', async () => {
  const { analyze, osv } = load();
  const doc = { spdxVersion: 'SPDX-2.3', SPDXID: 'SPDXRef-DOCUMENT', name: 'x', dataLicense: 'CC0-1.0', documentNamespace: 'urn:x',
    creationInfo: { created: '2026-01-01T00:00:00Z', creators: ['Tool: t'] },
    packages: [{ SPDXID: 'SPDXRef-app', name: 'app' }, { SPDXID: 'SPDXRef-lodash', name: 'lodash', versionInfo: '4.17.15',
      externalRefs: [{ referenceType: 'purl', referenceLocator: 'pkg:npm/lodash@4.17.15' }] }],
    relationships: [{ spdxElementId: 'SPDXRef-DOCUMENT', relatedSpdxElement: 'SPDXRef-app', relationshipType: 'DESCRIBES' },
      { spdxElementId: 'SPDXRef-app', relatedSpdxElement: 'SPDXRef-lodash', relationshipType: 'DEPENDS_ON' }] };
  const scan = await analyze({ input: JSON.stringify(doc) }, { osv });
  assert.equal(scan.format, 'SPDX');
  assert.equal(scan.summary.totalComponents, 1);
  assert.equal(scan.findings[0].dependency.type, 'DIRECT');
});

test('error cases', async () => {
  const { analyze, osv } = load();
  const code = async (input) => analyze({ input }, { osv }).then(() => null, (e) => e.code);
  assert.equal(await code('{not json'), 'INVALID_JSON');
  assert.equal(await code({ hello: 1 }), 'UNSUPPORTED_FORMAT');
  assert.equal(await code({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [] }), 'EMPTY_SBOM');
});

test('OSV outage is an error, not a clean result', async () => {
  const { analyze } = load();
  const { createOsvClient } = require('../src/services/osvClient');
  const config = require('../src/config');
  const old = config.osvBaseUrl; config.osvBaseUrl = 'http://127.0.0.1:1';
  const err = await analyze({ input: sample() }, { osv: createOsvClient() }).then(() => null, (e) => e);
  config.osvBaseUrl = old;
  assert.equal(err.code, 'OSV_UNAVAILABLE');
});

test('CSV export neutralizes formulas', () => {
  const { toCsv } = require('../src/services/exporter');
  const csv = toCsv({ findings: [{ priority: 1, package: '=cmd()', version: '1', ecosystem: 'npm', vulnerabilityId: 'X', aliases: [], severity: 'HIGH', cvss: 7, riskScore: 70,
    dependency: { type: 'DIRECT', environment: 'PRODUCTION' }, fixAvailable: true, fixedVersion: '2', confidence: 'HIGH', status: 'ACTIVE' }] });
  assert.match(csv, /'=cmd\(\)/);
});
