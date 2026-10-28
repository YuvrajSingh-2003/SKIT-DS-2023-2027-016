/**
 * Dashboard API module.
 *
 * Uses the shared API client (frontend/shared/api.js) as the single source
 * of truth for backend communication, passing the environment-configured base URL.
 *
 * All dashboard components import from here so the environment configuration
 * remains cleanly separated and centralized.
 */

import {
  scanUrl as sharedScanUrl,
  getScanHistory as sharedGetScanHistory,
  scanMessage as sharedScanMessage,
  getMessageHistory as sharedGetMessageHistory,
} from "../../shared/api.js";

/**
 * Base URL resolution:
 * 1. import.meta.env.VITE_API_BASE_URL (configured in .env / .env.example)
 * 2. In Vite dev mode, if VITE_API_BASE_URL is empty, requests can also be routed
 *    through the Vite dev proxy to avoid CORS.
 * 3. Default fallback: http://127.0.0.1:8000
 */
const BASE_URL =
  (typeof import.meta !== "undefined" && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
  "http://127.0.0.1:8000";

/**
 * POST /scan
 * Calls the backend /scan endpoint with payload `{"url": "https://..."}`.
 *
 * @param {string} url - The URL to scan
 * @returns {Promise<ScanResponse>}
 */
export async function scanUrl(url) {
  return sharedScanUrl(url, BASE_URL);
}

/**
 * GET /scan/history
 * Calls the backend /scan/history endpoint to retrieve previously scanned URLs.
 * History items include blockchain_status (see frontend/shared/api.js for its values).
 *
 * @returns {Promise<Array<HistoryItem>>}
 */
export async function getScanHistory() {
  return sharedGetScanHistory(BASE_URL);
}

/** POST /message/scan — classify an SMS/message (sent only on explicit submit). */
export async function scanMessage(text) {
  return sharedScanMessage(text, BASE_URL);
}

/** GET /message/history — metadata-only message scan history. */
export async function getMessageHistory() {
  return sharedGetMessageHistory(BASE_URL);
}
