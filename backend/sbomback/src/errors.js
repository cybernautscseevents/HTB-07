class ApiError extends Error {
  constructor(status, code, message, { reason, action, details } = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.reason = reason;
    this.action = action;
    this.details = details;
  }
  toJSON() {
    return { error: { code: this.code, message: this.message, reason: this.reason, action: this.action, details: this.details } };
  }
}
module.exports = { ApiError };
