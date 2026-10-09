const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { createApiRouter } = require('../src/routes/api');

const fixture = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');

test('comparison endpoint reports added, removed, version-changed and unchanged packages', async (t) => {
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter({ osv: {} }));
  const server = app.listen(0);
  t.after(() => server.close());
  const address = server.address();

  const response = await fetch(`http://127.0.0.1:${address.port}/api/sbom/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      baseline: { fileName: 'baseline.json', content: fixture('comparison-baseline.json') },
      updated: { fileName: 'updated.json', content: fixture('comparison-updated.json') },
    }),
  });
  const result = await response.json();

  assert.equal(response.status, 200);
  assert.deepEqual(result.summary, { added: 1, removed: 1, versionChanges: 1, unchanged: 1 });
  assert.equal(result.addedComponents[0].name, 'minimist');
  assert.equal(result.removedComponents[0].name, 'left-pad');
  assert.deepEqual(
    [result.versionChanges[0].name, result.versionChanges[0].fromVersion, result.versionChanges[0].toVersion],
    ['lodash', '4.17.20', '4.17.21'],
  );
  assert.equal(result.baseline.fileName, 'baseline.json');
  assert.match(result.note, /does not detect vulnerabilities/i);
});

test('comparison endpoint rejects malformed JSON and non-SBOM JSON', async (t) => {
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter({ osv: {} }));
  app.use((error, req, res, next) => {
    if (error.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
    if (error.status && typeof error.toJSON === 'function') return res.status(error.status).json(error.toJSON());
    return next(error);
  });
  const server = app.listen(0);
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/api/sbom/compare`;

  const malformed = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{"baseline":',
  });
  assert.equal(malformed.status, 400);

  const unsupported = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baseline: { arbitrary: true }, updated: fixture('comparison-updated.json') }),
  });
  assert.equal(unsupported.status, 422);
  assert.equal((await unsupported.json()).error.code, 'UNSUPPORTED_SBOM_FORMAT');
});

test('comparison endpoint accepts SPDX SBOMs', async (t) => {
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter({ osv: {} }));
  app.use((error, req, res, next) => {
    if (error.status && typeof error.toJSON === 'function') return res.status(error.status).json(error.toJSON());
    return next(error);
  });
  const server = app.listen(0);
  t.after(() => server.close());
  const packageDoc = (versionInfo) => ({
    spdxVersion: 'SPDX-2.3',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'comparison-sbom',
    dataLicense: 'CC0-1.0',
    documentNamespace: 'https://example.test/sbom',
    creationInfo: { created: '2026-01-01T00:00:00Z', creators: ['Tool: fixture'] },
    packages: [{
      SPDXID: 'SPDXRef-package',
      name: 'lodash',
      versionInfo,
      externalRefs: [{ referenceType: 'purl', referenceLocator: `pkg:npm/lodash@${versionInfo}` }],
    }],
  });
  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/sbom/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baseline: packageDoc('4.17.20'), updated: packageDoc('4.17.21') }),
  });
  const result = await response.json();
  assert.equal(response.status, 200);
  assert.equal(result.baseline.format, 'SPDX');
  assert.equal(result.versionChanges[0].name, 'lodash');
});

test('generated SBOM applies an OSV fixed version and stays valid CycloneDX', async (t) => {
  const osv = {
    canQuery: () => true,
    async queryComponents(components) {
      return new Map(components.map((component) => [
        component.key,
        component.name === 'lodash' ? ['GHSA-test-lodash'] : [],
      ]));
    },
    async getVulns(ids) {
      return new Map(ids.map((id) => [id, {
        id,
        database_specific: { severity: 'HIGH' },
        affected: [{
          package: { name: 'lodash', ecosystem: 'npm', purl: 'pkg:npm/lodash' },
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
        }],
      }]));
    },
  };
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter({ osv }));
  const server = app.listen(0);
  t.after(() => server.close());

  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/sbom/generate-updated`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName: 'baseline.json', sbom: fixture('comparison-baseline.json') }),
  });
  const generated = await response.json();
  const updatedLodash = generated.sbom.components.find((component) => component.name === 'lodash');

  assert.equal(response.status, 200);
  assert.equal(generated.summary.updatedComponents, 1);
  assert.equal(updatedLodash.version, '4.17.21');
  assert.equal(updatedLodash.purl, 'pkg:npm/lodash@4.17.21');
  assert.equal(generated.sbom.components.find((component) => component.name === 'left-pad').version, '1.0.0');
  assert.equal(generated.fileName, 'updated-baseline.json');
  assert.match(generated.note, /review package compatibility/i);
});

test('generated SBOM can use vulnerability findings from the completed scan', async (t) => {
  const app = express();
  app.use(express.json());
  app.use('/api', createApiRouter({ osv: {} }));
  const server = app.listen(0);
  t.after(() => server.close());

  const response = await fetch(`http://127.0.0.1:${server.address().port}/api/sbom/generate-updated`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fileName: 'baseline.json',
      sbom: fixture('comparison-baseline.json'),
      findings: [{ componentId: 'c0', fixedVersion: '4.17.21' }],
    }),
  });
  const generated = await response.json();

  assert.equal(response.status, 200);
  assert.equal(generated.summary.updatedComponents, 1);
  assert.equal(generated.sbom.components[0].version, '4.17.21');
});
