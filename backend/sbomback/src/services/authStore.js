const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { ApiError } = require('../errors');

function createAuthStore(filePath) {
  let users = [];
  if (filePath && fs.existsSync(filePath)) {
    users = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }

  function persist() {
    if (!filePath) return;
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const tempPath = `${filePath}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(tempPath, JSON.stringify(users), { mode: 0o600 });
    fs.renameSync(tempPath, filePath);
    if (process.platform !== 'win32') fs.chmodSync(filePath, 0o600);
  }

  return {
    count: () => users.length,
    findByEmail: (email) => users.find((user) => user.email === email) || null,
    findById: (id) => users.find((user) => user.id === id) || null,
    async register(email, password) {
      const normalizedEmail = email.trim().toLowerCase();
      if (users.some((user) => user.email === normalizedEmail)) {
        throw new ApiError(409, 'ACCOUNT_EXISTS', 'An account with this email already exists.');
      }
      const passwordHash = await bcrypt.hash(password, 12);
      if (users.some((user) => user.email === normalizedEmail)) {
        throw new ApiError(409, 'ACCOUNT_EXISTS', 'An account with this email already exists.');
      }
      const user = {
        id: crypto.randomUUID(),
        email: normalizedEmail,
        passwordHash,
        createdAt: new Date().toISOString(),
      };
      users.push(user);
      persist();
      return user;
    },
    verifyPassword: (user, password) => bcrypt.compare(password, user.passwordHash),
  };
}

module.exports = { createAuthStore };
