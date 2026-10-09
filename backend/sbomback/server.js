require('dotenv').config();

const express = require('express');
const cors = require('cors');
const config = require('./src/config');
const { ApiError } = require('./src/errors');
const { createOsvClient } = require('./src/services/osvClient');
const { createGroqService } = require('./src/services/groq');
const { createApiRouter } = require('./src/routes/api');
const { createAuthRouter } = require('./src/routes/auth');
const { createAuthStore } = require('./src/services/authStore');
const { createSessionManager, requireAuthentication } = require('./src/middleware/authentication');
const store = require('./src/store');

const app = express();
app.use(cors({ origin: config.corsOrigins, credentials: true }));
app.use(express.json({ limit: config.bodyLimit }));
const authStore = createAuthStore(config.accountsFile);
const sessions = createSessionManager({ durationMs: config.sessionDurationMs, secure: config.secureCookies });
const osv = createOsvClient();
const ai = createGroqService({ model: config.groqModel });
app.use('/api/auth', createAuthRouter({ authStore, sessions, allowedOrigins: config.corsOrigins }));
app.get('/api/health', async (req, res, next) => {
  try {
    const connected = await osv.ping();
    res.json({
      status: 'ok',
      osv: { status: connected ? 'connected' : 'unreachable' },
      scansInMemory: store.list().length,
    });
  } catch (error) {
    next(error);
  }
});
app.use('/api', requireAuthentication(sessions, config.corsOrigins));
app.use('/api', createApiRouter({ osv, ai }));

app.use((req, res) => res.status(404).json(new ApiError(404, 'NOT_FOUND', `No route for ${req.method} ${req.path}`).toJSON()));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof ApiError) return res.status(err.status).json(err.toJSON());
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json(new ApiError(400, 'INVALID_JSON', 'Unable to analyze this SBOM.', { reason: 'The uploaded file is not valid JSON.', action: 'Upload another SBOM' }).toJSON());
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json(new ApiError(413, 'FILE_TOO_LARGE', 'The SBOM is too large.', { reason: `Limit is ${config.bodyLimit}.` }).toJSON());
  }
  console.error(err);
  res.status(500).json(new ApiError(500, 'INTERNAL_ERROR', 'Unexpected server error.').toJSON());
});

if (require.main === module) {
  app.listen(config.port, () => console.log(`SBOM Risk & Trust Auditor API listening on http://localhost:${config.port}`));
}
module.exports = app;
