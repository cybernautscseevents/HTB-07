/**
 * Centralized API Client for SBOM Risk & Trust Auditor
 * 
 * Target Backend: http://localhost:5000
 * Handles health checking, SBOM upload requests, and graceful fallback.
 */

const API_BASE_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname || "localhost"}:5000`;

function apiFetch(url, options = {}) {
  return fetch(url, { ...options, credentials: "include" });
}

async function readApiResponse(response) {
  const result = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(result?.error?.message || `Request failed (HTTP ${response.status}).`);
  }
  return result;
}

export async function getCurrentUser() {
  const response = await apiFetch(`${API_BASE_URL}/api/auth/me`);
  if (response.status === 401) return null;
  return (await readApiResponse(response)).user;
}

export async function authenticate(email, password, mode) {
  const endpoint = mode === "register" ? "register" : "login";
  const response = await apiFetch(`${API_BASE_URL}/api/auth/${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return (await readApiResponse(response)).user;
}

export async function logout() {
  const response = await apiFetch(`${API_BASE_URL}/api/auth/logout`, { method: "POST" });
  if (!response.ok && response.status !== 401) {
    await readApiResponse(response);
  }
}

/**
 * Checks the status of the Express backend on port 5000
 */
export async function checkBackendHealth() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

    const response = await apiFetch(`${API_BASE_URL}/api/health`, {
      method: "GET",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    if (response.ok) {
      const data = await response.json();
      return {
        isOnline: true,
        message: data.message || "Connected to backend",
        osvConnected: data.osv?.status === "connected",
        url: API_BASE_URL,
      };
    }
    return {
      isOnline: false,
      osvConnected: false,
      message: `Backend returned HTTP ${response.status}`,
      url: API_BASE_URL,
    };
  } catch (err) {
    return {
      isOnline: false,
      osvConnected: false,
      message: err.name === "AbortError" ? "Backend connection timed out" : "Backend unreachable (Port 5000 offline)",
      url: API_BASE_URL,
    };
  }
}

/**
 * Upload and analyze an SBOM file via backend API
 * If backend endpoint is unavailable or returns an error, returns clean error status
 */
export async function uploadSbom(file) {
  try {
    const text = await file.text();

    const response = await apiFetch(`${API_BASE_URL}/api/scans`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        fileName: file.name,
        sbom: text,
      }),
    });

    if (response.ok) {
      const result = await response.json();
      return {
        success: true,
        isLive: true,
        data: result,
      };
    }

    const errorText = await response.text();
    return {
      success: false,
      isLive: false,
      error: errorText || `Backend endpoint /api/scans responded with status ${response.status}`,
    };
  } catch (error) {
    return {
      success: false,
      isLive: false,
      error: error.message || "Backend API is not currently reachable. Please make sure the backend is running.",
    };
  }
}

export async function getScans() {
  const response = await apiFetch(`${API_BASE_URL}/api/scans`);
  if (!response.ok) {
    throw new Error(`Failed to load scans (HTTP ${response.status}).`);
  }

  const result = await response.json();
  if (!Array.isArray(result.scans)) {
    throw new Error("Backend returned an invalid scan history response.");
  }

  return result.scans;
}

export async function getScan(scanId) {
  const response = await apiFetch(
    `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}`
  );
  if (!response.ok) {
    throw new Error(`Failed to load scan (HTTP ${response.status}).`);
  }

  return response.json();
}

export async function compareSboms(baseline, updated) {
  const response = await apiFetch(`${API_BASE_URL}/api/sbom/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ baseline, updated }),
  });
  return readApiResponse(response);
}

export async function generateUpdatedSbom(fileName, sbom, findings) {
  const response = await apiFetch(`${API_BASE_URL}/api/sbom/generate-updated`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fileName, sbom, findings }),
  });
  return readApiResponse(response);
}

export async function exportScan(scanId, format) {
  if (!['csv', 'json'].includes(format)) {
    throw new Error(`Unsupported export format: ${format}`);
  }

  const response = await apiFetch(
    `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}/export?format=${format}`
  );
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || `Failed to export scan (HTTP ${response.status}).`);
  }

  const disposition = response.headers.get('Content-Disposition') || '';
  const fileName = disposition.match(/filename="?([^";]+)"?/i)?.[1];

  return {
    blob: await response.blob(),
    fileName: fileName || `sbom-audit-${scanId.slice(0, 8)}.${format}`,
  };
}

async function postAiRequest(scanId, endpoint, payload) {
  const response = await apiFetch(
    `${API_BASE_URL}/api/scans/${encodeURIComponent(scanId)}/${endpoint}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }
  );
  const result = await response.json().catch(() => null);
  if (!response.ok) {
    const details = [result?.error?.reason, result?.error?.action]
      .filter(Boolean)
      .join(' ');
    throw new Error(
      [result?.error?.message, details].filter(Boolean).join(' ') ||
          `AI request failed (HTTP ${response.status}).`
    );
  }
  if (typeof result?.answer !== "string") {
      throw new Error("Backend returned an invalid AI response.");
  }
  return result.answer;
}

export function generateAiSummary(scanId) {
    return postAiRequest(scanId, "ai-summary", {});
}

export function askAiAboutScan(scanId, question, history) {
    return postAiRequest(scanId, "ai-chat", { question, history });
}

/**
 * Validates basic CycloneDX / SPDX JSON schema on the client
 */
export function validateSbomJson(fileContent) {
  try {
    const parsed = JSON.parse(fileContent);
    
    // Check CycloneDX format
    if (parsed.bomFormat === "CycloneDX" || parsed.$schema?.includes("cyclonedx") || parsed.components) {
      return {
        isValid: true,
        format: "CycloneDX",
        version: parsed.specVersion || "1.5",
        componentCount: Array.isArray(parsed.components) ? parsed.components.length : 0,
        hasDependencies: Array.isArray(parsed.dependencies) && parsed.dependencies.length > 0,
        metadata: parsed.metadata || {},
      };
    }

    // Check SPDX format
    if (parsed.spdxVersion || parsed.SPDXID || parsed.packages) {
      return {
        isValid: true,
        format: "SPDX",
        version: parsed.spdxVersion || "2.3",
        componentCount: Array.isArray(parsed.packages) ? parsed.packages.length : 0,
        hasDependencies: Array.isArray(parsed.relationships) && parsed.relationships.length > 0,
        metadata: { name: parsed.name },
      };
    }

    return {
      isValid: false,
      error: "Document does not match recognized CycloneDX or SPDX JSON specifications.",
    };
  } catch (e) {
    return {
      isValid: false,
      error: `Invalid JSON syntax: ${e.message}`,
    };
  }
}
