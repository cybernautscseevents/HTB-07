// Local stand-in for api.osv.dev used ONLY by tests (fixtures are synthetic, not real advisories).
const http = require('http');

const VULNS = {
  'GHSA-test-lodash': { id: 'GHSA-test-lodash', aliases: ['CVE-2099-0001'], summary: 'Test lodash issue', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N' }],
    affected: [{ package: { name: 'lodash', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }] },
  'GHSA-test-minimist': { id: 'GHSA-test-minimist', aliases: ['CVE-2099-0002'], severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affected: [{ package: { name: 'minimist', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.2.4' }, { introduced: '1.0.0' }, { fixed: '1.2.6' }] }] }] },
  'PYSEC-dup': { id: 'CVE-2099-0002', aliases: ['GHSA-test-minimist'], affected: [] },
  'GHSA-test-jest': { id: 'GHSA-test-jest', database_specific: { severity: 'MODERATE' },
    affected: [{ package: { name: 'jest', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '29.1.0' }] }] }] },
};
const BY_PKG = { lodash: ['GHSA-test-lodash'], minimist: ['GHSA-test-minimist', 'PYSEC-dup'], jest: ['GHSA-test-jest'] };

function start() {
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      res.setHeader('Content-Type', 'application/json');
      if (req.method === 'POST' && req.url === '/v1/querybatch') {
        const { queries } = JSON.parse(body);
        const results = queries.map((q) => {
          const name = q.package.purl ? q.package.purl.replace(/^pkg:npm\//, '').split('@')[0] : q.package.name;
          return { vulns: (BY_PKG[name] || []).map((id) => ({ id })) };
        });
        return res.end(JSON.stringify({ results }));
      }
      const m = req.url.match(/^\/v1\/vulns\/(.+)$/);
      const v = m && VULNS[decodeURIComponent(m[1])];
      if (v) return res.end(JSON.stringify(v));
      res.statusCode = 404; res.end('{}');
    });
  });
  return new Promise((resolve) => server.listen(0, () => resolve(server)));
}
module.exports = { start };
