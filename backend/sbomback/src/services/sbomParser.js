const { ApiError } = require('../errors');
const { parsePurl } = require('./purl');

const clean = (v) => (typeof v === 'string' && v.trim() && v.trim().toUpperCase() !== 'NOASSERTION' ? v.trim() : null);

function readInput(input) {
  if (typeof input === 'string') {
    try { return JSON.parse(input); } catch (e) {
      throw new ApiError(400, 'INVALID_JSON', 'Unable to analyze this SBOM.', {
        reason: 'The uploaded file is not valid JSON.', action: 'Upload another SBOM',
        details: e.message,
      });
    }
  }
  return input;
}

function detectFormat(doc) {
  if (doc && typeof doc === 'object' && !Array.isArray(doc)) {
    if (doc.bomFormat === 'CycloneDX' || (doc.specVersion && (doc.components || doc.metadata) && !doc.spdxVersion)) return 'CycloneDX';
    if (typeof doc.spdxVersion === 'string' && doc.spdxVersion.startsWith('SPDX-')) return 'SPDX';
  }
  throw new ApiError(422, 'UNSUPPORTED_FORMAT', 'Unable to analyze this SBOM.', {
    reason: 'The uploaded file is not valid CycloneDX or SPDX JSON.', action: 'Upload another SBOM',
  });
}

function finalizeComponent(c) {
  const p = parsePurl(c.purl);
  const version = clean(c.version) || (p && p.version) || null;
  return {
    id: c.id, name: clean(c.name) || (p && p.name) || null, version,
    purl: c.purl || null,
    ecosystem: (p && p.ecosystem) || c.ecosystem || null,
    purlParts: p,
    type: c.type || null,
    environment: c.environment || 'UNKNOWN',
    licenses: c.licenses || [],
    supplier: c.supplier || null,
    hasHash: !!c.hasHash,
  };
}

// ---------- CycloneDX ----------
function parseCycloneDx(doc) {
  const checks = [
    ['bomFormat is "CycloneDX"', doc.bomFormat === 'CycloneDX'],
    ['specVersion present', typeof doc.specVersion === 'string'],
    ['version present', doc.version !== undefined],
    ['components is an array', Array.isArray(doc.components)],
  ];
  const flat = [];
  let anon = 0;
  const walk = (list) => (list || []).forEach((c) => {
    if (!c || typeof c !== 'object') return;
    const props = Object.fromEntries((c.properties || []).map((p) => [p.name, p.value]));
    let environment = 'UNKNOWN';
    if (c.scope === 'required') environment = 'PRODUCTION';
    else if (c.scope === 'excluded') environment = 'DEVELOPMENT';
    if (props['cdx:npm:package:development'] === 'true') environment = 'DEVELOPMENT';
    flat.push({
      id: c['bom-ref'] || `component-${anon++}`, name: c.name, version: c.version, purl: c.purl, type: c.type,
      environment,
      licenses: (c.licenses || []).map((l) => clean(l.expression) || clean(l.license && (l.license.id || l.license.name))).filter(Boolean),
      supplier: clean(c.supplier && c.supplier.name) || clean(c.publisher) || clean(c.author),
      hasHash: Array.isArray(c.hashes) && c.hashes.length > 0,
    });
    walk(c.components);
  });
  walk(doc.components);

  const edges = [];
  const mentioned = new Set();
  (doc.dependencies || []).forEach((d) => {
    if (!d || !d.ref) return;
    mentioned.add(d.ref);
    (d.dependsOn || []).forEach((to) => { edges.push([d.ref, to]); mentioned.add(to); });
  });
  const rootRef = doc.metadata && doc.metadata.component && doc.metadata.component['bom-ref'];
  return {
    format: 'CycloneDX', specVersion: doc.specVersion || null,
    timestamp: clean(doc.metadata && doc.metadata.timestamp),
    documentName: clean(doc.metadata && doc.metadata.component && doc.metadata.component.name),
    hasTools: !!(doc.metadata && doc.metadata.tools),
    checks, components: flat.map(finalizeComponent), edges, mentioned,
    rootIds: rootRef ? [rootRef] : [],
  };
}

// ---------- SPDX ----------
const REVERSED = { DEPENDENCY_OF: null, DEV_DEPENDENCY_OF: 'DEVELOPMENT', BUILD_DEPENDENCY_OF: 'DEVELOPMENT',
  TEST_DEPENDENCY_OF: 'DEVELOPMENT', RUNTIME_DEPENDENCY_OF: 'PRODUCTION', OPTIONAL_DEPENDENCY_OF: null };
const FORWARD = new Set(['DEPENDS_ON', 'CONTAINS']);

function parseSpdx(doc) {
  const checks = [
    ['spdxVersion present', typeof doc.spdxVersion === 'string'],
    ['SPDXID present', typeof doc.SPDXID === 'string'],
    ['name present', typeof doc.name === 'string'],
    ['dataLicense present', typeof doc.dataLicense === 'string'],
    ['documentNamespace present', typeof doc.documentNamespace === 'string'],
    ['creationInfo present', !!doc.creationInfo],
    ['packages is an array', Array.isArray(doc.packages)],
  ];
  const envById = {};
  const edges = [];
  const mentioned = new Set();
  const docId = doc.SPDXID || 'SPDXRef-DOCUMENT';
  const rootIds = new Set(doc.documentDescribes || []);

  (doc.relationships || []).forEach((r) => {
    const { spdxElementId: a, relatedSpdxElement: b, relationshipType: t } = r || {};
    if (!a || !b || !t) return;
    if (t === 'DESCRIBES' && a === docId) { rootIds.add(b); return; }
    if (t === 'DESCRIBED_BY' && b === docId) { rootIds.add(a); return; }
    if (FORWARD.has(t)) { edges.push([a, b]); mentioned.add(a); mentioned.add(b); }
    else if (t in REVERSED) {
      edges.push([b, a]); mentioned.add(a); mentioned.add(b);
      if (REVERSED[t]) envById[a] = REVERSED[t];
    }
  });

  const pkgs = (doc.packages || []).filter((p) => p && typeof p === 'object');
  const components = pkgs
    .filter((p) => !(rootIds.has(p.SPDXID) && edges.some(([from]) => from === p.SPDXID)))
    .map((p) => {
      const refs = p.externalRefs || [];
      const purlRef = refs.find((r) => r.referenceType === 'purl');
      return finalizeComponent({
        id: p.SPDXID, name: p.name, version: p.versionInfo, purl: purlRef && purlRef.referenceLocator,
        type: p.primaryPackagePurpose ? String(p.primaryPackagePurpose).toLowerCase() : 'library',
        environment: envById[p.SPDXID] || 'UNKNOWN',
        licenses: [clean(p.licenseConcluded), clean(p.licenseDeclared)].filter(Boolean).slice(0, 1),
        supplier: clean(p.supplier && String(p.supplier).replace(/^(Organization|Person):\s*/i, '')) || clean(p.originator),
        hasHash: Array.isArray(p.checksums) && p.checksums.length > 0,
      });
    });

  return {
    format: 'SPDX', specVersion: String(doc.spdxVersion).replace('SPDX-', ''),
    timestamp: clean(doc.creationInfo && doc.creationInfo.created), documentName: clean(doc.name),
    hasTools: !!(doc.creationInfo && (doc.creationInfo.creators || []).length),
    checks, components, edges, mentioned, rootIds: [...rootIds],
  };
}

function parseSbom(input) {
  const doc = readInput(input);
  const format = detectFormat(doc);
  const parsed = format === 'CycloneDX' ? parseCycloneDx(doc) : parseSpdx(doc);
  if (parsed.components.length === 0) {
    throw new ApiError(422, 'EMPTY_SBOM', 'Unable to analyze this SBOM.', {
      reason: 'The SBOM is valid but contains no components.', action: 'Upload another SBOM',
    });
  }
  if (parsed.components.every((c) => !c.name)) {
    throw new ApiError(422, 'MISSING_REQUIRED_INFORMATION', 'Unable to analyze this SBOM.', {
      reason: 'No component in the SBOM has a name or package URL (purl).', action: 'Upload another SBOM',
    });
  }
  parsed.components = parsed.components.filter((c) => c.name).map((c, i) => ({ ...c, key: `c${i}` }));
  return parsed;
}

module.exports = { parseSbom };
