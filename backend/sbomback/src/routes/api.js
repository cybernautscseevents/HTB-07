const express = require('express');
const { makeControllers } = require('../controllers');

function createApiRouter(deps) {
  const c = makeControllers(deps);
  const r = express.Router();
  r.post('/sbom/compare', c.compareSboms);
  r.post('/sbom/generate-updated', c.generateUpdatedSbom);
  r.post('/analyze', c.createScan); // alias of POST /scans
  r.route('/scans').get(c.listScans).post(c.createScan);
  r.route('/scans/:id').get(c.getScan).delete(c.deleteScan);
  r.post('/scans/:id/ai-summary', c.aiSummary);
  r.post('/scans/:id/ai-chat', c.aiChat);
  r.get('/scans/:id/overview', c.overview);
  r.get('/scans/:id/vulnerabilities', c.vulnerabilities);
  r.get('/scans/:id/vulnerabilities/:findingId', c.vulnerability);
  r.get('/scans/:id/components', c.components);
  r.get('/scans/:id/components/:componentId', c.component);
  r.get('/scans/:id/quality', c.quality);
  r.get('/scans/:id/report', c.report);
  r.get('/scans/:id/export', c.exportScan);
  return r;
}

module.exports = { createApiRouter };
