const crypto = require('crypto');
const { ApiError } = require('../errors');

const COOKIE_NAME = 'sbom_session';
const COOKIE_PATH = '/api';
const DEFAULT_DURATION_MS = 12 * 60 * 60 * 1000;

function cookieValue(header = '', name = COOKIE_NAME) {
  const prefix = `${name}=`;
  const entry = header.split(';').map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return entry ? decodeURIComponent(entry.slice(prefix.length)) : '';
}

function createSessionManager({ durationMs = DEFAULT_DURATION_MS, secure = false } = {}) {
  const sessions = new Map();
  const cookieOptions = `HttpOnly; SameSite=Strict; Path=${COOKIE_PATH}; Max-Age=${Math.floor(durationMs / 1000)}${secure ? '; Secure' : ''}`;

  function get(token) {
    const session = sessions.get(token);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
      sessions.delete(token);
      return null;
    }
    return session;
  }

  return {
    cookieName: COOKIE_NAME,
    create(user) {
      const token = crypto.randomBytes(32).toString('base64url');
      sessions.set(token, { user: { id: user.id, email: user.email }, expiresAt: Date.now() + durationMs });
      return token;
    },
    read(req) {
      const token = cookieValue(req.headers.cookie);
      return token ? get(token) : null;
    },
    setCookie(res, token) {
      res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; ${cookieOptions}`);
    },
    clearCookie(res) {
      res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=${COOKIE_PATH}; Max-Age=0${secure ? '; Secure' : ''}`);
    },
    destroy(req) {
      const token = cookieValue(req.headers.cookie);
      if (token) sessions.delete(token);
    },
  };
}

function requireAuthentication(sessions, allowedOrigins) {
  const origins = new Set(allowedOrigins);
  return (req, res, next) => {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.headers.origin && !origins.has(req.headers.origin)) {
      return next(new ApiError(403, 'INVALID_ORIGIN', 'Request origin is not allowed.'));
    }
    const session = sessions.read(req);
    if (!session) {
      return next(new ApiError(401, 'AUTHENTICATION_REQUIRED', 'Sign in to continue.'));
    }
    req.user = session.user;
    next();
  };
}

module.exports = { createSessionManager, requireAuthentication };
