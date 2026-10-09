const config = require('../config');
const { ApiError } = require('../errors');

async function osvFetch(path, options = {}) {
  try {
    const res = await fetch(`${config.osvBaseUrl}${path}`, {
      ...options,
      headers: { 'Content-Type': 'application/json' },
      signal: AbortSignal.timeout(config.osvTimeoutMs),
    });
    if (!res.ok) throw new Error(`OSV responded with HTTP ${res.status}`);
    return await res.json();
  } catch (e) {
    throw new ApiError(502, 'OSV_UNAVAILABLE', 'Vulnerability intelligence is unavailable.', {
      reason: 'The OSV API could not be reached, so vulnerabilities could not be checked. No result is shown rather than a misleading "clean" one.',
      action: 'Try again shortly', details: e.message,
    });
  }
}

function toQuery(c) {
  if (c.purl && c.purlParts) return { package: { purl: c.purl } };
  if (c.ecosystem && c.name && c.version) return { package: { name: c.name, ecosystem: c.ecosystem }, version: c.version };
  return null;
}

const cache = new Map();

function createOsvClient() {
  return {
    canQuery: (c) => !!c.version && !!toQuery(c),

    // Returns Map<componentKey, string[]> of vulnerability ids.
    async queryComponents(components) {
      const queryable = components.filter((c) => this.canQuery(c));
      const result = new Map(queryable.map((c) => [c.key, []]));
      for (let i = 0; i < queryable.length; i += 500) {
        const chunk = queryable.slice(i, i + 500);
        const data = await osvFetch('/v1/querybatch', { method: 'POST', body: JSON.stringify({ queries: chunk.map(toQuery) }) });
        for (let j = 0; j < chunk.length; j++) {
          const r = (data.results || [])[j] || {};
          const ids = (r.vulns || []).map((v) => v.id);
          let token = r.next_page_token;
          for (let page = 0; token && page < 5; page++) { // bounded pagination
            const more = await osvFetch('/v1/query', { method: 'POST', body: JSON.stringify({ ...toQuery(chunk[j]), page_token: token }) });
            (more.vulns || []).forEach((v) => ids.push(v.id));
            token = more.next_page_token;
          }
          result.get(chunk[j].key).push(...ids);
        }
      }
      return result;
    },

    // Returns Map<id, vulnObject|null>; null = details could not be fetched.
    async getVulns(ids) {
      const unique = [...new Set(ids)];
      const out = new Map();
      let next = 0;
      const worker = async () => {
        while (next < unique.length) {
          const id = unique[next++];
          if (cache.has(id)) { out.set(id, cache.get(id)); continue; }
          try {
            const v = await osvFetch(`/v1/vulns/${encodeURIComponent(id)}`);
            cache.set(id, v);
            out.set(id, v);
          } catch { out.set(id, null); }
        }
      };
      await Promise.all(Array.from({ length: Math.min(10, unique.length) }, worker));
      return out;
    },

    async ping() {
      try { await osvFetch('/v1/vulns/GHSA-jfh8-c2jp-5v3q'); return true; } catch { return false; }
    },
  };
}

module.exports = { createOsvClient };
