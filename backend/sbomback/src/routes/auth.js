const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { ApiError } = require('../errors');

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_BYTES = 72;

function createAuthRouter({ authStore, sessions, allowedOrigins = [] }) {
  const router = express.Router();
  const origins = new Set(allowedOrigins);
  const limitAuthAttempts = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: { error: { code: 'AUTH_RATE_LIMITED', message: 'Too many authentication attempts. Try again later.' } },
  });
  const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  const publicUser = (user) => ({ id: user.id, email: user.email, createdAt: user.createdAt });
  router.use((req, res, next) => {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.headers.origin && !origins.has(req.headers.origin)) {
      return next(new ApiError(403, 'INVALID_ORIGIN', 'Request origin is not allowed.'));
    }
    next();
  });

  router.post('/register', limitAuthAttempts, wrap(async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!EMAIL_PATTERN.test(email) || email.length > 254) {
      throw new ApiError(400, 'INVALID_EMAIL', 'Enter a valid email address.');
    }
    if (password.length < PASSWORD_MIN_LENGTH || Buffer.byteLength(password, 'utf8') > PASSWORD_MAX_BYTES) {
      throw new ApiError(400, 'INVALID_PASSWORD', `Password must be at least ${PASSWORD_MIN_LENGTH} characters and no more than ${PASSWORD_MAX_BYTES} UTF-8 bytes.`);
    }

    const user = await authStore.register(email, password);
    sessions.setCookie(res, sessions.create(user));
    res.status(201).json({ user: publicUser(user) });
  }));

  router.post('/login', limitAuthAttempts, wrap(async (req, res) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const user = authStore.findByEmail(email);
    if (!user || !(await authStore.verifyPassword(user, password))) {
      throw new ApiError(401, 'INVALID_CREDENTIALS', 'Email or password is incorrect. If this is your first time here, create an account.');
    }
    sessions.setCookie(res, sessions.create(user));
    res.json({ user: publicUser(user) });
  }));

  router.get('/me', (req, res) => {
    const session = sessions.read(req);
    if (!session) {
      throw new ApiError(401, 'AUTHENTICATION_REQUIRED', 'Sign in to continue.');
    }
    res.json({ user: session.user });
  });

  router.post('/logout', (req, res) => {
    sessions.destroy(req);
    sessions.clearCookie(res);
    res.status(204).end();
  });

  return router;
}

module.exports = { createAuthRouter };
