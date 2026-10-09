const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

function displayContext(value) {
  if (!value) return 'Unknown';
  const normalized = String(value).toLowerCase();
  return normalized.charAt(0).toUpperCase() + normalized.slice(1);
}

function countValue(...values) {
  const value = values.find(
    (candidate) =>
      candidate !== undefined &&
      candidate !== null &&
      candidate !== '' &&
      Number.isFinite(Number(candidate))
  );

  return value === undefined ? undefined : Number(value);
}

export function normalizeScanData(scan = {}) {
  const summary = scan.summary || {};
  const rawVulnerabilities = Array.isArray(scan.vulnerabilities)
    ? scan.vulnerabilities
    : Array.isArray(scan.findings)
      ? scan.findings
      : [];
  const components = Array.isArray(scan.components)
    ? scan.components.map((component) => ({
        ...component,
        dependencyType: displayContext(component.dependencyType),
        environment: displayContext(component.environment),
        vulnerabilitiesCount:
          component.vulnerabilitiesCount ?? component.vulnerabilityCount ?? 0,
        riskScore: component.riskScore ?? component.risk ?? 0,
      }))
    : [];
  const distribution = Array.isArray(scan.distribution)
    ? scan.distribution
    : [];
  const existingCounts = scan.severityCounts || {};

  const vulnerabilities = rawVulnerabilities.map((finding) => ({
    ...finding,
    id: finding.id ?? finding.vulnerabilityId ?? finding.cve,
    cve: finding.cve ?? finding.vulnerabilityId,
    installedVersion: finding.installedVersion ?? finding.version,
    dependencyType: displayContext(
      finding.dependencyType ?? finding.dependency?.type
    ),
    environment: displayContext(
      finding.environment ?? finding.dependency?.environment
    ),
    confidence: displayContext(finding.confidence),
    remediationCommand:
      finding.remediationCommand ?? finding.remediation?.command,
    remediationAction:
      finding.remediationAction ?? finding.remediation?.action,
    confidenceRationale:
      finding.confidenceRationale ?? finding.confidenceReason,
    dependencyPath:
      finding.dependencyPath ?? finding.dependency?.path,
    affectedVersions:
      finding.affectedVersions ??
      (Array.isArray(finding.affectedRanges)
        ? finding.affectedRanges.join('; ')
        : undefined),
    exploitability:
      finding.exploitability?.status ?? finding.exploitability ?? 'NOT_ASSESSED',
    status: displayContext(finding.status),
  }));

  const severityCounts = Object.fromEntries(
    SEVERITIES.map((severity) => {
      const distributionCount = distribution.find(
        (item) => String(item.severity).toLowerCase() === severity
      )?.count;
      const findingCount = vulnerabilities.filter(
        (finding) => String(finding.severity).toLowerCase() === severity
      ).length;

      return [
        severity,
        countValue(
          existingCounts[severity],
          existingCounts[severity.toUpperCase()],
          summary[severity],
          distributionCount,
          findingCount
        ),
      ];
    })
  );

  const risk = scan.overallRisk || scan.risk || {};
  const trust = scan.sbomTrust || scan.trust || {};
  const uncertain = scan.uncertainFindings || scan.uncertain || {};
  const quality = scan.qualityBreakdown || scan.quality || trust.breakdown || [];
  const ntia = scan.ntiaMinimumElements || trust.ntia || [];

  return {
    ...scan,
    scanName: scan.scanName ?? scan.name,
    sbomFormat: scan.sbomFormat ?? scan.format,
    sbomFile: scan.sbomFile ?? scan.fileName,
    scanDate: scan.scanDate ?? scan.createdAt,
    vulnerabilities,
    components,
    vulnerabilitiesCount:
      countValue(
        scan.vulnerabilitiesCount,
        scan.vulnerabilities_count,
        typeof scan.vulnerabilities === 'number' ? scan.vulnerabilities : undefined,
        summary.vulnerabilities,
        vulnerabilities.length
      ) ?? 0,
    totalComponents:
      countValue(
        scan.totalComponents,
        scan.total_components,
        scan.componentsCount,
        scan.components_count,
        summary.totalComponents,
        summary.total_components,
        components.length
      ) ?? 0,
    severityCounts,
    overallRisk: {
      ...risk,
      score: countValue(risk.score) ?? 0,
      level: risk.level ?? risk.label ?? 'UNKNOWN',
      rationale: risk.rationale ?? risk.explanation ?? 'No risk assessment is available.',
      directProductionVulns:
        countValue(
          risk.directProductionVulns,
          vulnerabilities.filter(
            (finding) =>
              String(finding.dependencyType).toUpperCase() === 'DIRECT' &&
              String(finding.environment).toUpperCase() === 'PRODUCTION'
          ).length
        ) ?? 0,
      transitiveVulns:
        countValue(
          risk.transitiveVulns,
          vulnerabilities.filter(
            (finding) =>
              String(finding.dependencyType).toUpperCase() === 'TRANSITIVE'
          ).length
        ) ?? 0,
    },
    sbomTrust: {
      ...trust,
      score: countValue(trust.score) ?? 0,
      rating: trust.rating ?? 'UNKNOWN',
      highlights: trust.highlights || trust.checks || [],
      verifiedElements: trust.verifiedElements,
      summary: trust.summary || trust.principle || '',
    },
    qualityBreakdown: quality.map((item) => ({
      ...item,
      score: countValue(item.score, item.percent) ?? 0,
    })),
    ntiaMinimumElements: ntia.map((item) => ({
      ...item,
      element: item.element ?? item.label,
    })),
    uncertainFindings: Array.isArray(uncertain)
      ? uncertain
      : uncertain.findings || [],
  };
}
