const path = require('path');

module.exports = {
  port: Number(process.env.PORT) || 5000,
  secureCookies: process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production',
  sessionDurationMs: 12 * 60 * 60 * 1000,
  accountsFile: path.join(__dirname, '..', 'data', 'accounts.json'),
  osvBaseUrl: process.env.OSV_BASE_URL || 'https://api.osv.dev',
  osvTimeoutMs: Number(process.env.OSV_TIMEOUT_MS) || 15000,
  groqModel: process.env.GROQ_MODEL || 'qwen/qwen3.8-27b',
  corsOrigins: (process.env.CORS_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000')
    .split(',').map((s) => s.trim()).filter(Boolean),
  bodyLimit: process.env.BODY_LIMIT || '25mb',
  maxScans: Number(process.env.MAX_SCANS) || 50,
  // Scans are kept in memory. Set PERSIST_SCANS=true to also write them to a local JSON file.
  persistFile: process.env.PERSIST_SCANS === 'true' ? path.join(__dirname, '..', 'data', 'scans.json') : null,
};
