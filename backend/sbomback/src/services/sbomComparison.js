const { ApiError } = require('../errors');
const { parseSbom } = require('./sbomParser');
const { analyze } = require('./analyzer');
const { compareVersions } = require('./version');

function readSbom(input, label) {
  let doc = input;
  if (typeof input === 'string') {
    try {
      doc = JSON.parse(input);
    } catch (error) {
      throw new ApiError(400, 'INVALID_SBOM_JSON', `${label} SBOM is not valid JSON.`, { details: error.message });
    }
  }

  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    throw new ApiError(400, 'INVALID_SBOM', `${label} SBOM must be a JSON object.`);
  }

  const isCycloneDx = doc.bomFormat === 'CycloneDX'
    && typeof doc.specVersion === 'string'
    && Array.isArray(doc.components);
  const isSpdx = typeof doc.spdxVersion === 'string'
    && /^SPDX-\d+\.\d+$/.test(doc.spdxVersion)
    && typeof doc.SPDXID === 'string'
    && typeof doc.name === 'string'
    && Array.isArray(doc.packages);
  if (!isCycloneDx && !isSpdx) {
    throw new ApiError(422, 'UNSUPPORTED_SBOM_FORMAT', `${label} file must be CycloneDX JSON or SPDX JSON.`);
  }

  const entries = isCycloneDx ? doc.components : doc.packages;
  if (entries.some((entry) => !entry || typeof entry !== 'object' || Array.isArray(entry))) {
    throw new ApiError(422, 'INVALID_SBOM_COMPONENT', `${label} SBOM contains an invalid component entry.`);
  }

  try {
    return parseSbom(doc);
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(422, 'INVALID_SBOM', `${label} SBOM structure is invalid.`, { details: error.message });
  }
}

function identityOf(component) {
  if (component.purlParts) {
    const { type, namespace, name } = component.purlParts;
    return `purl:${[type, namespace, name].filter(Boolean).join('/')}`.toLowerCase();
  }
  return `name:${String(component.ecosystem || '').toLowerCase()}:${String(component.name || '').toLowerCase()}`;
}

function publicComponent(component) {
  return {
    name: component.name,
    version: component.version,
    ecosystem: component.ecosystem,
    purl: component.purl,
  };
}

function compareSboms(baselineInput, updatedInput, { baselineFileName = null, updatedFileName = null } = {}) {
  const baseline = readSbom(baselineInput, 'Baseline');
  const updated = readSbom(updatedInput, 'Updated');
  const baselineGroups = new Map();
  const updatedGroups = new Map();

  for (const component of baseline.components) {
    const key = identityOf(component);
    if (!baselineGroups.has(key)) baselineGroups.set(key, []);
    baselineGroups.get(key).push(component);
  }
  for (const component of updated.components) {
    const key = identityOf(component);
    if (!updatedGroups.has(key)) updatedGroups.set(key, []);
    updatedGroups.get(key).push(component);
  }

  const addedComponents = [];
  const removedComponents = [];
  const versionChanges = [];
  let unchanged = 0;
  const identities = new Set([...baselineGroups.keys(), ...updatedGroups.keys()]);

  for (const identity of identities) {
    const before = [...(baselineGroups.get(identity) || [])];
    const after = [...(updatedGroups.get(identity) || [])];

    for (let i = before.length - 1; i >= 0; i--) {
      const exactIndex = after.findIndex((component) => component.version === before[i].version);
      if (exactIndex !== -1) {
        before.splice(i, 1);
        after.splice(exactIndex, 1);
        unchanged++;
      }
    }

    while (before.length && after.length) {
      const oldComponent = before.shift();
      const newComponent = after.shift();
      versionChanges.push({
        identity,
        name: newComponent.name || oldComponent.name,
        ecosystem: newComponent.ecosystem || oldComponent.ecosystem,
        purl: newComponent.purl || oldComponent.purl,
        fromVersion: oldComponent.version,
        toVersion: newComponent.version,
      });
    }

    removedComponents.push(...before.map((component) => ({ identity, ...publicComponent(component) })));
    addedComponents.push(...after.map((component) => ({ identity, ...publicComponent(component) })));
  }

  return {
    baseline: { fileName: baselineFileName, format: baseline.format, componentCount: baseline.components.length },
    updated: { fileName: updatedFileName, format: updated.format, componentCount: updated.components.length },
    summary: {
      added: addedComponents.length,
      removed: removedComponents.length,
      versionChanges: versionChanges.length,
      unchanged,
    },
    addedComponents,
    removedComponents,
    versionChanges,
    note: 'This compares package inventory and versions only; it does not detect vulnerabilities.',
  };
}

function replacePurlVersion(purl, version) {
  if (typeof purl !== 'string' || !purl.startsWith('pkg:')) return purl;
  const suffixIndex = purl.search(/[?#]/);
  const suffix = suffixIndex === -1 ? '' : purl.slice(suffixIndex);
  const core = suffixIndex === -1 ? purl : purl.slice(0, suffixIndex);
  const at = core.lastIndexOf('@');
  const slash = core.indexOf('/', 4);
  const encodedVersion = encodeURIComponent(version);
  if (at > slash) return `${core.slice(0, at)}@${encodedVersion}${suffix}`;
  return `${core}@${encodedVersion}${suffix}`;
}

async function generateUpdatedSbom(input, { fileName = null, findings = null } = {}, osv) {
  const document = typeof input === 'string' ? (() => {
    try {
      return JSON.parse(input);
    } catch (error) {
      throw new ApiError(400, 'INVALID_SBOM_JSON', 'Baseline SBOM is not valid JSON.', { details: error.message });
    }
  })() : input;
  const parsed = readSbom(document, 'Baseline');
  const scanFindings = Array.isArray(findings)
    ? findings
    : (await analyze({ input: document, fileName }, { osv })).findings;
  const componentsById = new Map(parsed.components.map((component) => [component.key, component]));
  const findingsByComponent = new Map();

  for (const finding of scanFindings) {
    if (!finding.fixedVersion || !finding.componentId) continue;
    if (!findingsByComponent.has(finding.componentId)) findingsByComponent.set(finding.componentId, []);
    findingsByComponent.get(finding.componentId).push(finding);
  }

  const updatesById = new Map();
  for (const [componentId, findings] of findingsByComponent) {
    const component = componentsById.get(componentId);
    if (!component?.version) continue;
    const candidates = [...new Set(findings.map((finding) => finding.fixedVersion))]
      .filter((version) => compareVersions(version, component.version) > 0)
      .sort(compareVersions);
    if (!candidates.length) continue;
    updatesById.set(component.id, {
      name: component.name,
      fromVersion: component.version,
      toVersion: candidates[candidates.length - 1],
      fixedFindings: findings.length,
    });
  }

  const updatedDocument = JSON.parse(JSON.stringify(document));
  const applyUpdate = (component, id) => {
    const update = updatesById.get(id);
    if (!update) return;
    component.version = update.toVersion;
    if (component.purl) component.purl = replacePurlVersion(component.purl, update.toVersion);
    if (Array.isArray(component.externalRefs)) {
      component.externalRefs.forEach((reference) => {
        if (reference.referenceType === 'purl' && typeof reference.referenceLocator === 'string') {
          reference.referenceLocator = replacePurlVersion(reference.referenceLocator, update.toVersion);
        }
      });
    }
  };

  if (parsed.format === 'CycloneDX') {
    let anonymousId = 0;
    const walk = (components) => (components || []).forEach((component) => {
      const id = component['bom-ref'] || `component-${anonymousId++}`;
      applyUpdate(component, id);
      walk(component.components);
    });
    walk(updatedDocument.components);
  } else {
    (updatedDocument.packages || []).forEach((component) => applyUpdate(component, component.SPDXID));
  }

  const changes = [...updatesById.values()];
  return {
    fileName: `updated-${fileName || 'sbom.json'}`,
    format: parsed.format,
    sbom: updatedDocument,
    changes,
    summary: { updatedComponents: changes.length },
    note: changes.length
      ? 'Suggested version updates are based on fixed versions listed by OSV. Review package compatibility and rebuild/test before adopting; this generated SBOM is not a guarantee of vulnerability-free software.'
      : 'No applicable higher fixed versions were available from OSV for the components in this SBOM. This comparison does not establish that the SBOM is vulnerability-free.',
  };
}

module.exports = { compareSboms, generateUpdatedSbom };
