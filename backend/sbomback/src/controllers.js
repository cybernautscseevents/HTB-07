const store = require('./store');
const { ApiError } = require('./errors');
const { analyze } = require('./services/analyzer');
const { compareSboms, generateUpdatedSbom } = require('./services/sbomComparison');
const { toCsv, toJson, reportSummary } = require('./services/exporter');

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);
const summaryOf = (s) => ({ id: s.id, name: s.name, fileName: s.fileName, format: s.format, components: s.summary.totalComponents,
  vulnerabilities: s.summary.vulnerabilities, risk: s.risk.label, riskScore: s.risk.score, trust: s.trust.score, trustRating: s.trust.rating,
  createdAt: s.createdAt, status: s.status });

function getScan(req) {
  const scan = store.get(req.params.id, req.user?.id);
  if (!scan) throw new ApiError(404, 'SCAN_NOT_FOUND', 'Scan not found.', { action: 'Upload an SBOM to create a scan' });
  return scan;
}

function makeControllers({ osv, ai = { isConfigured: false } }) {
  return {
    health: wrap(async (req, res) => {
      const connected = await osv.ping();
      res.json({ status: 'ok', osv: { status: connected ? 'connected' : 'unreachable' },
        ai: { provider: 'groq', configured: ai.isConfigured }, scansInMemory: store.list().length });
    }),

    createScan: wrap(async (req, res) => {
      const body = req.body || {};
      // Accept either {fileName, name, sbom} or the raw SBOM document itself.
      const wrapped = body.sbom !== undefined;
      if (!wrapped && (typeof body !== 'object' || !Object.keys(body).length)) {
        throw new ApiError(400, 'MISSING_SBOM', 'No SBOM provided.', { reason: 'Send {"fileName", "sbom"} as JSON.', action: 'Upload another SBOM' });
      }
      const scan = await analyze({ input: wrapped ? body.sbom : body, fileName: wrapped ? body.fileName : req.query.fileName, name: wrapped ? body.name : req.query.name }, { osv });
      scan.ownerId = req.user.id;
      store.save(scan);
      res.status(201).json(scan);
    }),

    compareSboms: wrap(async (req, res) => {
      const body = req.body || {};
      const baseline = body.baseline;
      const updated = body.updated;
      const contentOf = (entry) => entry && typeof entry === 'object' && !Array.isArray(entry)
        && ('content' in entry || 'sbom' in entry)
        ? (entry.content ?? entry.sbom)
        : entry;
      const fileNameOf = (entry, fallback) => (
        entry && typeof entry === 'object' && !Array.isArray(entry) && typeof entry.fileName === 'string'
          ? entry.fileName
          : fallback
      );
      if (baseline === undefined || updated === undefined) {
        throw new ApiError(400, 'MISSING_COMPARISON_SBOMS', 'Provide both baseline and updated SBOMs.');
      }
      res.json(compareSboms(contentOf(baseline), contentOf(updated), {
        baselineFileName: fileNameOf(baseline, body.baselineFileName || null),
        updatedFileName: fileNameOf(updated, body.updatedFileName || null),
      }));
    }),

    generateUpdatedSbom: wrap(async (req, res) => {
      const body = req.body || {};
      const sbom = body.sbom ?? body.content;
      if (sbom === undefined) {
        throw new ApiError(400, 'MISSING_SBOM', 'Provide a baseline SBOM to generate an updated copy.');
      }
      res.json(await generateUpdatedSbom(
        sbom,
        { fileName: body.fileName || null, findings: body.findings },
        osv,
      ));
    }),

    listScans: (req, res) => res.json({ scans: store.list(req.user.id).map(summaryOf) }),
    getScan: (req, res) => res.json(getScan(req)),
    deleteScan: (req, res) => { store.remove(getScan(req).id, req.user.id); res.status(204).end(); },

    aiSummary: wrap(async (req, res) => {
      const scan = getScan(req);
      if (typeof ai.summarize !== 'function') {
        throw new ApiError(503, 'AI_NOT_CONFIGURED', 'Groq is not configured.', {
          reason: 'The backend has no Groq API key.',
          action: 'Set GROQ_API_KEY in the backend environment and restart the server.',
        });
      }
      res.json({ answer: await ai.summarize(scan) });
    }),

    aiChat: wrap(async (req, res) => {
      const scan = getScan(req);
      const question = typeof req.body?.question === 'string' ? req.body.question.trim() : '';
      if (!question || question.length > 1000) {
        throw new ApiError(400, 'INVALID_AI_QUESTION', 'Enter a question of 1 to 1000 characters.');
      }
      const history = req.body?.history ?? [];
      if (!Array.isArray(history) || history.length > 8 || history.some((message) =>
        !message || !['user', 'assistant'].includes(message.role)
        || typeof message.content !== 'string' || message.content.length > 2000)) {
        throw new ApiError(400, 'INVALID_AI_HISTORY', 'Chat history must contain user or assistant messages up to 2000 characters each.');
      }
      if (typeof ai.chat !== 'function') {
        throw new ApiError(503, 'AI_NOT_CONFIGURED', 'Groq is not configured.', {
          reason: 'The backend has no Groq API key.',
          action: 'Set GROQ_API_KEY in the backend environment and restart the server.',
        });
      }
      res.json({ answer: await ai.chat(scan, question, history.slice(-8)) });
    }),

    overview: (req, res) => {
      const s = getScan(req);
      res.json({ id: s.id, name: s.name, format: s.format, summary: s.summary, risk: s.risk, trust: { score: s.trust.score, rating: s.trust.rating, checks: s.trust.checks },
        topFindings: s.findings.slice(0, 10), distribution: s.distribution, quality: s.trust.breakdown, uncertain: s.uncertain, dataSource: s.dataSource });
    },

    vulnerabilities: (req, res) => {
      const s = getScan(req);
      const q = req.query;
      const text = String(q.q || '').toLowerCase();
      let list = s.findings.filter((f) => {
        if (text && ![f.package, f.vulnerabilityId, ...f.aliases].some((x) => String(x).toLowerCase().includes(text))) return false;
        if (q.severity && f.severity !== String(q.severity).toUpperCase()) return false;
        if (q.fixAvailable !== undefined && String(f.fixAvailable) !== q.fixAvailable) return false;
        if (q.dependencyType && f.dependency.type !== String(q.dependencyType).toUpperCase()) return false;
        if (q.environment && f.dependency.environment !== String(q.environment).toUpperCase()) return false;
        if (q.confidence && f.confidence !== String(q.confidence).toUpperCase()) return false;
        return true;
      });
      if (q.sort === 'risk') list = [...list].sort((a, b) => a.riskScore - b.riskScore);
      const pageSize = Math.min(Number(q.pageSize) || 25, 200);
      const page = Math.max(Number(q.page) || 1, 1);
      res.json({ total: list.length, page, pageSize, items: list.slice((page - 1) * pageSize, page * pageSize) });
    },

    vulnerability: (req, res) => {
      const f = getScan(req).findings.find((x) => x.id === req.params.findingId);
      if (!f) throw new ApiError(404, 'FINDING_NOT_FOUND', 'Vulnerability finding not found.');
      res.json(f);
    },

    components: (req, res) => {
      const s = getScan(req);
      const q = req.query;
      const text = String(q.q || '').toLowerCase();
      const items = s.components.filter((c) => (!text || String(c.name).toLowerCase().includes(text))
        && (!q.dependencyType || c.dependencyType === String(q.dependencyType).toUpperCase())
        && (!q.environment || c.environment === String(q.environment).toUpperCase())
        && (q.vulnerable === undefined || String(c.vulnerabilityCount > 0) === q.vulnerable));
      res.json({ total: items.length, items });
    },

    component: (req, res) => {
      const c = getScan(req).components.find((x) => x.id === req.params.componentId);
      if (!c) throw new ApiError(404, 'COMPONENT_NOT_FOUND', 'Component not found.');
      res.json(c);
    },

    quality: (req, res) => res.json(getScan(req).trust),
    report: (req, res) => res.json(reportSummary(getScan(req))),

    exportScan: (req, res) => {
      const s = getScan(req);
      const format = String(req.query.format || 'json').toLowerCase();
      if (!['json', 'csv'].includes(format)) throw new ApiError(400, 'UNSUPPORTED_EXPORT', 'Supported export formats are json and csv.');
      const base = `sbom-audit-${s.id.slice(0, 8)}`;
      res.setHeader('Content-Disposition', `attachment; filename="${base}.${format}"`);
      if (format === 'csv') res.type('text/csv').send(toCsv(s));
      else res.json(toJson(s));
    },
  };
}

module.exports = { makeControllers };
