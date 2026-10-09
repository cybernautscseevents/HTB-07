const test = require('node:test');
const assert = require('node:assert/strict');
const { createGroqService } = require('../src/services/groq');

const scan = {
  name: 'example-app',
  format: 'CycloneDX',
  summary: { totalComponents: 2, vulnerabilities: 1 },
  risk: { score: 85, label: 'HIGH' },
  trust: { score: 90, rating: 'HIGH', checks: [], breakdown: [] },
  uncertain: { count: 0, unassessedComponents: [] },
  findings: [{
    vulnerabilityId: 'CVE-2099-0001',
    package: 'example-package',
    version: '1.0.0',
    severity: 'HIGH',
    riskScore: 85,
    dependency: { type: 'DIRECT', environment: 'PRODUCTION' },
    fixAvailable: true,
    fixedVersion: '1.0.1',
    confidence: 'HIGH',
    exploitability: { status: 'NOT_ASSESSED' },
  }],
};

test('Groq reports a missing API key clearly', async () => {
  const groq = createGroqService({ apiKey: '' });
  assert.equal(groq.isConfigured, false);
  await assert.rejects(
    groq.summarize(scan),
    (error) => error.status === 503 && error.code === 'AI_NOT_CONFIGURED'
  );
});

test('Groq summary uses configured model and verified scan context', async () => {
  let request;
  const groq = createGroqService({
    apiKey: 'test-key',
    model: 'test-model',
    client: {
      chat: { completions: {
        create: async (options) => {
          request = options;
          return { choices: [{ message: { content: 'Fix example-package first.' } }] };
        },
      } },
    },
  });

  assert.equal(await groq.summarize(scan), 'Fix example-package first.');
  assert.equal(request.model, 'test-model');
  assert.match(request.messages[1].content, /CVE-2099-0001/);
  assert.match(request.messages[1].content, /NOT_ASSESSED/);
  assert.match(request.messages[0].content, /Do not invent findings or metrics/);
});

test('Groq chat includes the question and recent conversation', async () => {
  let request;
  const groq = createGroqService({
    apiKey: 'test-key',
    client: {
      chat: { completions: {
        create: async (options) => {
          request = options;
          return { choices: [{ message: { content: 'Upgrade to 1.0.1.' } }] };
        },
      } },
    },
  });

  const answer = await groq.chat(scan, 'How do I fix it?', [
    { role: 'user', content: 'What is the issue?' },
    { role: 'assistant', content: 'A high severity issue was found.' },
  ]);
  assert.equal(answer, 'Upgrade to 1.0.1.');
  assert.equal(request.messages.at(-1).content, 'How do I fix it?');
  assert.match(request.messages.at(-3).content, /What is the issue\?/);
});

test('Groq invalid key gives an actionable diagnostic without exposing the key', async () => {
  const groq = createGroqService({
    apiKey: 'secret-test-key',
    client: {
      chat: { completions: {
        create: async () => {
          const error = new Error('Project denied for secret-test-key');
          error.status = 401;
          throw error;
        },
      } },
    },
  });

  await assert.rejects(groq.summarize(scan), (error) => {
    assert.equal(error.code, 'AI_PROVIDER_UNAVAILABLE');
    assert.equal(error.details.upstreamStatus, 401);
    assert.match(error.reason, /HTTP 401/);
    assert.match(error.action, /GROQ_API_KEY/);
    assert.doesNotMatch(JSON.stringify(error.toJSON()), /secret-test-key/);
    return true;
  });
});
