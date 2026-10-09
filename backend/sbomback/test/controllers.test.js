const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const mock = require('./mockOsv');

let server;
test.before(async () => { server = await mock.start(); process.env.OSV_BASE_URL = `http://127.0.0.1:${server.address().port}`; });
test.after(() => server.close());

const call = (h, req) => new Promise((resolve, reject) => {
  const res = { code: 200, headers: {}, body: undefined };
  const finish = (b) => { if (b !== undefined) res.body = b; resolve(res); return res; };
  res.status = (c) => { res.code = c; return res; };
  res.type = () => res; res.setHeader = (k, v) => { res.headers[k] = v; };
  res.json = finish; res.send = finish; res.end = () => finish();
  Promise.resolve(h({ params: {}, query: {}, body: {}, user: { id: 'test-user' }, ...req }, res, reject)).catch(reject);
});

test('controller flow: create, overview, filter, detail, export', async () => {
  const { createOsvClient } = require('../src/services/osvClient');
  const aiCalls = [];
  const c = require('../src/controllers').makeControllers({
    osv: createOsvClient(),
    ai: {
      isConfigured: true,
      summarize: async (scan) => { aiCalls.push({ type: 'summary', scan }); return 'Prioritize the critical finding.'; },
      chat: async (scan, question, history) => {
        aiCalls.push({ type: 'chat', scan, question, history });
        return 'The scan has one critical finding.';
      },
    },
  });
  const sbom = JSON.parse(fs.readFileSync(path.join(__dirname, '../samples/sample-cyclonedx.json'), 'utf8'));
  const created = await call(c.createScan, { body: { fileName: 'app-sbom.json', sbom } });
  assert.equal(created.code, 201);
  const id = created.body.id;
  assert.equal((await call(c.listScans, {})).body.scans[0].fileName, 'app-sbom.json');
  assert.equal((await call(c.listScans, { user: { id: 'another-user' } })).body.scans.length, 0);
  await assert.rejects(
    call(c.getScan, { params: { id }, user: { id: 'another-user' } }),
    (err) => err.code === 'SCAN_NOT_FOUND'
  );
  assert.equal((await call(c.overview, { params: { id: 'latest' } })).body.summary.vulnerabilities, 3);
  const crit = await call(c.vulnerabilities, { params: { id }, query: { severity: 'critical' } });
  assert.equal(crit.body.total, 1);
  const byAlias = await call(c.vulnerabilities, { params: { id }, query: { q: 'cve-2099-0002' } });
  assert.equal(byAlias.body.total, 1);
  const detail = await call(c.vulnerability, { params: { id, findingId: crit.body.items[0].id } });
  assert.equal(detail.body.package, 'minimist');
  const csv = await call(c.exportScan, { params: { id }, query: { format: 'csv' } });
  assert.match(csv.body, /^priority,package/);
  const report = await call(c.report, { params: { id } });
  assert.equal(report.body.criticalFindings.length, 1);
  assert.equal((await call(c.health, {})).body.ai.configured, true);
  assert.equal((await call(c.aiSummary, { params: { id } })).body.answer, 'Prioritize the critical finding.');
  const chat = await call(c.aiChat, {
    params: { id },
    body: { question: 'What should I fix first?', history: [{ role: 'user', content: 'Explain risk.' }] },
  });
  assert.equal(chat.body.answer, 'The scan has one critical finding.');
  assert.equal(aiCalls.at(-1).question, 'What should I fix first?');
  assert.equal(aiCalls.at(-1).history.length, 1);
  await assert.rejects(
    call(c.aiChat, { params: { id }, body: { question: '   ' } }),
    (err) => err.code === 'INVALID_AI_QUESTION'
  );
});
