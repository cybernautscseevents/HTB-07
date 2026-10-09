const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { ApiError } = require('../src/errors');
const { createAuthStore } = require('../src/services/authStore');
const { createSessionManager, requireAuthentication } = require('../src/middleware/authentication');
const { createAuthRouter } = require('../src/routes/auth');

test('registration, private sessions, logout, and persistent password hashes', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-auth-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));

  const accountsFile = path.join(directory, 'accounts.json');
  const authStore = createAuthStore(accountsFile);
  const sessions = createSessionManager({ durationMs: 60_000 });
  const app = express();
  app.use(express.json());
  app.use('/api/auth', createAuthRouter({ authStore, sessions }));
  app.use('/api', requireAuthentication(sessions, []));
  app.get('/api/private', (req, res) => res.json({ user: req.user }));
  app.use((err, req, res, next) => {
    if (err instanceof ApiError) return res.status(err.status).json(err.toJSON());
    next(err);
  });

  const server = await new Promise((resolve) => {
    const listener = app.listen(0, '127.0.0.1', () => resolve(listener));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  const privateBeforeLogin = await fetch(`${baseUrl}/api/private`);
  assert.equal(privateBeforeLogin.status, 401);

  const shortRegistration = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'user@example.com', password: 'short7!' }),
  });
  assert.equal(shortRegistration.status, 400);

  const registration = await fetch(`${baseUrl}/api/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: ' User@Example.com ', password: 'easyPass8' }),
  });
  assert.equal(registration.status, 201);
  const sessionCookie = registration.headers.get('set-cookie');
  assert.match(sessionCookie, /HttpOnly/);
  assert.match(sessionCookie, /SameSite=Strict/);
  assert.match(sessionCookie, /Path=\/api/);
  const cookie = sessionCookie.split(';')[0];
  const accountFile = fs.readFileSync(accountsFile, 'utf8');
  assert.match(accountFile, /user@example.com/);
  assert.doesNotMatch(accountFile, /easyPass8/);

  const privateWithSession = await fetch(`${baseUrl}/api/private`, { headers: { Cookie: cookie } });
  assert.equal(privateWithSession.status, 200);
  assert.equal((await privateWithSession.json()).user.email, 'user@example.com');

  const validLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'user@example.com', password: 'easyPass8' }),
  });
  assert.equal(validLogin.status, 200);

  const invalidLogin = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'user@example.com', password: 'wrong password' }),
  });
  assert.equal(invalidLogin.status, 401);

  const logout = await fetch(`${baseUrl}/api/auth/logout`, {
    method: 'POST',
    headers: { Cookie: cookie },
  });
  assert.equal(logout.status, 204);
  const privateAfterLogout = await fetch(`${baseUrl}/api/private`, { headers: { Cookie: cookie } });
  assert.equal(privateAfterLogout.status, 401);
});
