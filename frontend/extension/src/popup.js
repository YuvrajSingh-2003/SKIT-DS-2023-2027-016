/**
 * ChainShield Chrome Extension – popup.js
 *
 * Vanilla JS — no bundler, no framework. Runs in the popup context only.
 * Request, timeout and response interpretation live in src/logic.js
 * (globalThis.ChainShieldLogic), which is unit-tested with Node.
 *
 * - The user explicitly pastes a URL or a message and presses Scan. Nothing is
 *   read from pages, tabs or the clipboard, and nothing runs in the background.
 * - Failures, timeouts and malformed responses are shown as errors, never as safe.
 * - No blockchain calls and no secrets in the extension; the backend does that.
 */

"use strict";

// ─── Configuration ────────────────────────────────────────────────────────────

/**
 * Backend base URL. Must match host_permissions in manifest.json.
 * For another host, change both this constant and the manifest.
 */
const BACKEND_URL = "http://127.0.0.1:8000";

/** Dashboard link shown in the footer. Empty string hides it. */
const DASHBOARD_URL = "http://localhost:5173";

const Logic = globalThis.ChainShieldLogic;

// ─── DOM references ───────────────────────────────────────────────────────────
const form            = document.getElementById("scan-form");
const urlRow          = document.getElementById("url-row");
const urlInput        = document.getElementById("url-input");
const scanBtn         = document.getElementById("scan-btn");
const messageRow      = document.getElementById("message-row");
const messageInput    = document.getElementById("message-input");
const scanMessageBtn  = document.getElementById("scan-message-btn");
const modeUrlBtn      = document.getElementById("mode-url");
const modeMessageBtn  = document.getElementById("mode-message");
const idleHint        = document.getElementById("idle-hint");
const validationMsg   = document.getElementById("validation-msg");
const dashboardLink   = document.getElementById("dashboard-link");

const stateIdle       = document.getElementById("state-idle");
const stateLoading    = document.getElementById("state-loading");
const stateError      = document.getElementById("state-error");
const stateResult     = document.getElementById("state-result");

const errorMsg        = document.getElementById("error-msg");
const errorHint       = document.getElementById("error-hint");

const resultBadge     = document.getElementById("result-badge");
const resultDomain    = document.getElementById("result-domain");
const detailHttps     = document.getElementById("detail-https");
const detailIp        = document.getElementById("detail-ip");
const detailHttpsVal  = document.getElementById("detail-https-val");
const detailIpVal     = document.getElementById("detail-ip-val");
const modelMsg        = document.getElementById("model-msg");

const blockchainSec   = document.getElementById("blockchain-section");
const blockchainMsg   = document.getElementById("blockchain-msg");

const findingsSec     = document.getElementById("findings-section");
const findingsList    = document.getElementById("findings-list");
const noFindings      = document.getElementById("no-findings");

let mode = "url";

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Show exactly one state panel; hide the others. */
function showState(name) {
  const states = { idle: stateIdle, loading: stateLoading, error: stateError, result: stateResult };
  for (const [key, el] of Object.entries(states)) {
    if (!el) continue;
    const visible = key === name;
    el.hidden = !visible;
    el.style.display = visible ? "" : "none";
  }
}

function setBusy(busy) {
  scanBtn.disabled = busy;
  scanMessageBtn.disabled = busy;
  urlInput.disabled = busy;
  messageInput.disabled = busy;
  scanBtn.textContent = busy && mode === "url" ? "Scanning…" : "Scan";
  scanMessageBtn.textContent = busy && mode === "message" ? "Scanning…" : "Scan message";
}

function showValidation(text, input) {
  validationMsg.textContent = text;
  validationMsg.hidden = false;
  input.classList.add("input-error");
}

function clearValidation() {
  validationMsg.hidden = true;
  urlInput.classList.remove("input-error");
  messageInput.classList.remove("input-error");
}

function renderFindings(findings, emptyText) {
  findingsList.textContent = "";
  if (findings.length > 0) {
    for (const f of findings) {
      const li = document.createElement("li");
      li.textContent = f;              // plain text only
      findingsList.appendChild(li);
    }
    findingsSec.hidden = false;
    noFindings.hidden = true;
  } else {
    findingsSec.hidden = true;
    noFindings.textContent = emptyText;
    noFindings.hidden = false;
  }
}

function setMode(next) {
  mode = next;
  const isUrl = mode === "url";
  urlRow.hidden = !isUrl;
  messageRow.hidden = isUrl;
  modeUrlBtn.classList.toggle("mode-active", isUrl);
  modeMessageBtn.classList.toggle("mode-active", !isUrl);
  modeUrlBtn.setAttribute("aria-selected", String(isUrl));
  modeMessageBtn.setAttribute("aria-selected", String(!isUrl));
  idleHint.textContent = isUrl
    ? "Enter a URL above to check it for phishing indicators."
    : "Paste a text message above to check it for smishing.";
  clearValidation();
  showState("idle");
}

// ─── Render results ──────────────────────────────────────────────────────────

function renderUrlResult(data) {
  const view = Logic.describeUrlResult(data);

  resultBadge.className = `badge ${view.badgeClass}`;
  resultBadge.textContent = view.badgeLabel;
  resultDomain.textContent = typeof data.domain === "string" ? data.domain : "";

  detailHttps.hidden = false;
  detailIp.hidden = false;
  detailHttpsVal.textContent = data.https ? "Yes" : "No";
  detailHttpsVal.className = `pill ${data.https ? "pill-yes" : "pill-no"}`;
  detailIpVal.textContent = data.uses_ip ? "Yes" : "No";
  detailIpVal.className = `pill ${data.uses_ip ? "pill-no" : "pill-yes"}`;
  modelMsg.hidden = true;

  blockchainSec.hidden = false;
  blockchainSec.className = `blockchain-section ${
    data.blockchain_available !== true ? "blockchain-unavailable"
      : (data.blockchain_status ? data.blockchain_status === "match_threat" : data.blockchain_found)
        ? "blockchain-found" : "blockchain-clear"}`;
  blockchainMsg.textContent = view.registry;

  renderFindings(data.findings.filter((f) => typeof f === "string"), "No heuristic issues detected.");
  showState("result");
}

function renderMessageResult(data) {
  const view = Logic.describeMessageResult(data);

  resultBadge.className = `badge ${view.badgeClass}`;
  resultBadge.textContent = view.badgeLabel;
  resultDomain.textContent = view.explanation;

  detailHttps.hidden = true;
  detailIp.hidden = true;
  modelMsg.textContent = [view.probabilities, view.modelVersion && `Model: ${view.modelVersion}`]
    .filter(Boolean).join(" · ");
  modelMsg.hidden = !modelMsg.textContent;

  blockchainSec.hidden = false;
  blockchainSec.className = `blockchain-section ${
    data.registry.status === "match_threat" ? "blockchain-found"
      : data.registry.status === "no_match" ? "blockchain-clear" : "blockchain-unavailable"}`;
  blockchainMsg.textContent = view.registry;

  renderFindings(view.findings, "No message warning signs detected by the simple checks.");
  showState("result");
}

function renderError(err) {
  errorMsg.textContent = (err && err.message) || "An unexpected error occurred. No result is available.";
  if (err && (err.type === "network" || err.type === "timeout")) {
    errorHint.textContent = `Make sure the server is running at ${BACKEND_URL}`;
    errorHint.hidden = false;
  } else {
    errorHint.hidden = true;
  }
  showState("error");
}

// ─── Submit ───────────────────────────────────────────────────────────────────

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  clearValidation();

  let path;
  let body;
  if (mode === "url") {
    const url = urlInput.value.trim();
    if (!url) return showValidation("Please enter a URL.", urlInput);
    if (!Logic.isValidUrl(url)) return showValidation("Enter a URL starting with http:// or https://", urlInput);
    path = "/scan";
    body = { url };
  } else {
    const problem = Logic.validateMessage(messageInput.value);
    if (problem) return showValidation(problem, messageInput);
    path = "/message/scan";
    body = { text: messageInput.value };
  }

  setBusy(true);
  showState("loading");
  try {
    const data = await Logic.postJson(fetch, BACKEND_URL, path, body);
    if (path === "/scan") renderUrlResult(data);
    else renderMessageResult(data);
  } catch (err) {
    renderError(err);
  } finally {
    setBusy(false);
    // Loading never outlives the request: a result or error state is always shown.
    if (!stateLoading.hidden) showState("error");
  }
});

modeUrlBtn.addEventListener("click", () => setMode("url"));
modeMessageBtn.addEventListener("click", () => setMode("message"));

// ─── Initialise ───────────────────────────────────────────────────────────────

if (DASHBOARD_URL) {
  dashboardLink.href = DASHBOARD_URL;
  dashboardLink.hidden = false;
}

setBusy(false);
setMode("url");
