/**
 * ChainShield – Shared API Client
 *
 * Single source of truth for all backend communication.
 * Import this module from both the dashboard and the extension.
 *
 * Dashboard:  reads VITE_API_BASE_URL from the Vite environment.
 * Extension:  passes the base URL explicitly via the `baseUrl` parameter
 *             or falls back to DEFAULT_BASE_URL.
 */

// ─── Default base URL ────────────────────────────────────────────────────────
// In ES modules / browser contexts, default to the local FastAPI server.
export const DEFAULT_BASE_URL = "http://127.0.0.1:8000";

// A scan can wait on several registry RPC calls (10 s timeout each) plus the
// model, so allow up to a minute before giving up. A timeout is an error, never a result.
export const DEFAULT_TIMEOUT_MS = 60000;

/** FastAPI validation errors (422) carry `detail` as a list of {loc, msg}. */
function formatDetail(detail) {
  if (Array.isArray(detail)) {
    return detail.map((item) => (item && item.msg) || JSON.stringify(item)).join("; ");
  }
  return typeof detail === "string" ? detail : JSON.stringify(detail);
}

// ─── Core fetch wrapper ───────────────────────────────────────────────────────
/**
 * Generic fetch helper. Throws a structured error object on any failure so
 * callers can distinguish network errors from HTTP errors from bad JSON.
 *
 * @param {string} path      - e.g. "/scan"
 * @param {object} options   - standard fetch options
 * @param {string} [baseUrl] - override for caller (dashboard or extension)
 * @returns {Promise<any>}   - parsed JSON body
 */
export async function apiFetch(path, options = {}, baseUrl = DEFAULT_BASE_URL, timeoutMs = DEFAULT_TIMEOUT_MS) {
  // Normalize base URL without trailing slash
  const cleanBase = (baseUrl || DEFAULT_BASE_URL).replace(/\/+$/, "");
  const cleanPath = path.startsWith("/") ? path : `/${path}`;
  const url = `${cleanBase}${cleanPath}`;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, {
      headers: { "Content-Type": "application/json" },
      ...options,
      signal: controller.signal,
    });
  } catch (networkError) {
    if (networkError?.name === "AbortError") {
      throw {
        type: "timeout",
        message: "The ChainShield backend did not respond in time. No result is available.",
      };
    }
    throw {
      type: "network",
      message: "Cannot reach the ChainShield backend. Is the server running?",
      detail: networkError?.message || String(networkError),
    };
  } finally {
    clearTimeout(timer);
  }

  if (!response.ok) {
    let detail = "";
    try {
      const body = await response.json();
      detail = formatDetail(body.detail || body.message || body);
    } catch {
      detail = await response.text().catch(() => "");
    }
    throw {
      type: "http",
      status: response.status,
      message: `Server returned ${response.status}: ${detail || response.statusText}`,
      detail,
    };
  }

  try {
    return await response.json();
  } catch {
    throw {
      type: "parse",
      message: "The server returned a response that could not be parsed.",
    };
  }
}

// ─── Public API methods ───────────────────────────────────────────────────────

/**
 * POST /scan
 * Scan a URL for phishing / smishing threats.
 *
 * @param {string} url      - The URL to scan (must be a valid URL string)
 * @param {string} [baseUrl] - API host URL
 * @returns {Promise<ScanResponse>}
 *
 * ScanResponse shape (from backend schema):
 * {
 *   url: string,
 *   status: string,          // "processed" | "error"
 *   message: string,
 *   protocol: string,
 *   domain: string,
 *   path: string,
 *   https: boolean,
 *   uses_ip: boolean,
 *   risk_level: string,      // "SAFE" | "MEDIUM" | "HIGH" | "UNKNOWN"
 *   findings: string[],
 *   blockchain_available: boolean,
 *   blockchain_found: boolean,
 * }
 */
export async function scanUrl(url, baseUrl = DEFAULT_BASE_URL) {
  return apiFetch(
    "/scan",
    { method: "POST", body: JSON.stringify({ url }) },
    baseUrl
  );
}

/**
 * GET /scan/history
 * Retrieve all previously scanned URLs from the database.
 *
 * History records include blockchain_available, blockchain_found and
 * blockchain_status. Use blockchain_status: only "match_threat" is a known threat.
 * Older rows report "not_recorded" or "match_unclassified" (entry existed, verdict
 * not recorded), which must not be shown as threats.
 *
 * History item shape:
 * {
 *   id: number,
 *   url: string,
 *   status: string,
 *   message: string,
 *   protocol: string,
 *   domain: string,
 *   path: string,
 *   https: boolean,
 *   uses_ip: boolean,
 *   risk_level: string,
 *   findings: string[],
 * }
 *
 * @param {string} [baseUrl] - API host URL
 * @returns {Promise<Array<HistoryItem>>}
 */
export async function getScanHistory(baseUrl = DEFAULT_BASE_URL) {
  return apiFetch("/scan/history", { method: "GET" }, baseUrl);
}

/**
 * POST /message/scan
 * Classify an SMS/message. The text is sent only when the user presses Scan.
 *
 * MessageScanResponse shape (backend app/schemas/message.py):
 * {
 *   status: "processed",
 *   verdict: "smishing_registry_match" | "likely_smishing" | "generic_spam" | "likely_legitimate" | "unavailable",
 *   risk_level: "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN",   // never "SAFE"
 *   decision_source: "blockchain" | "ml" | "unavailable",
 *   message: string,
 *   model: { status: "ok" | "error", label, probabilities, model_version, model_name, error },
 *   registry: { status: "match_threat" | "match_non_threat" | "no_match" | "unavailable", error },
 *   findings: string[], limitations: string[], message_length: number,
 *   scan_id: number | null, persisted: boolean,
 * }
 */
export async function scanMessage(text, baseUrl = DEFAULT_BASE_URL) {
  return apiFetch("/message/scan", { method: "POST", body: JSON.stringify({ text }) }, baseUrl);
}

/**
 * GET /message/history
 * Metadata only (verdict, model scores, registry status, length). No message text is stored.
 */
export async function getMessageHistory(baseUrl = DEFAULT_BASE_URL) {
  return apiFetch("/message/history", { method: "GET" }, baseUrl);
}
