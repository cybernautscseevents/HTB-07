// Derives DIRECT / TRANSITIVE classification and dependency paths from SBOM relationships.
// Without relationship data the answer is UNKNOWN - never guessed.
function buildContext(parsed) {
  const { components, edges, rootIds } = parsed;
  const byId = new Map(components.map((c) => [c.id, c]));
  const out = new Map();
  const incoming = new Set();
  edges.forEach(([from, to]) => {
    if (!out.has(from)) out.set(from, []);
    out.get(from).push(to);
    incoming.add(to);
  });

  const result = new Map(components.map((c) => [c.key, { dependencyType: 'UNKNOWN', path: null, inGraph: parsed.mentioned.has(c.id) }]));
  if (edges.length === 0) return result;

  const roots = rootIds.filter((r) => out.has(r));
  const starts = roots.length ? roots : [...new Set(edges.map(([f]) => f))].filter((f) => !incoming.has(f));
  const topLevelAreDirect = roots.length === 0; // no explicit app root: top-level nodes are the app's direct deps

  const seen = new Map(); // id -> {depth, path}
  const queue = [];
  starts.forEach((s) => {
    if (topLevelAreDirect) { seen.set(s, { depth: 1, path: [s] }); queue.push(s); }
    else (out.get(s) || []).forEach((n) => { if (!seen.has(n)) { seen.set(n, { depth: 1, path: [n] }); queue.push(n); } });
  });
  while (queue.length) {
    const id = queue.shift();
    const { depth, path } = seen.get(id);
    (out.get(id) || []).forEach((n) => {
      if (!seen.has(n)) { seen.set(n, { depth: depth + 1, path: [...path, n] }); queue.push(n); }
    });
  }
  seen.forEach((info, id) => {
    const c = byId.get(id);
    if (!c) return;
    result.set(c.key, {
      dependencyType: info.depth === 1 ? 'DIRECT' : 'TRANSITIVE', inGraph: true,
      path: info.path.map((p) => { const pc = byId.get(p); return pc ? `${pc.name}${pc.version ? '@' + pc.version : ''}` : p; }),
    });
  });
  return result;
}

module.exports = { buildContext };
