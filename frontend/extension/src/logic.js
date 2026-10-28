/**
 * ChainShield extension – pure request and result logic (no DOM).
 *
 * Loaded by popup.html before popup.js (exposes globalThis.ChainShieldLogic)
 * and by Node's built-in test runner (module.exports). No dependencies.
 *
 * Rules: network failure, timeout, HTTP errors and malformed responses are
 * errors, never a "safe" result. Model output is described as a prediction.
 */
(function (root) {
  "use strict";

  const MAX_MESSAGE_CHARS = 2000;
  const DEFAULT_TIMEOUT_MS = 15000;

  function isValidUrl(value) {
    try {
      const u = new URL(String(value).trim());
      return u.protocol === "http:" || u.protocol === "https:";
    } catch {
      return false;
    }
  }

  /** Returns an error string, or null when the message can be sent. */
  function validateMessage(value) {
    const text = typeof value === "string" ? value : "";
    if (!text.trim()) return "Please paste a message.";
    if (text.length > MAX_MESSAGE_CHARS) return `Messages are limited to ${MAX_MESSAGE_CHARS} characters.`;
    return null;
  }

  /**
   * POST JSON with a timeout. Throws {type, message} where type is
   * "timeout" | "network" | "http" | "parse".
   */
  async function postJson(fetchImpl, baseUrl, path, body, timeoutMs = DEFAULT_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetchImpl(`${String(baseUrl).replace(/\/+$/, "")}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (error) {
      if (error && error.name === "AbortError") {
        throw { type: "timeout", message: "The ChainShield backend did not respond in time. No result is available." };
      }
      throw { type: "network", message: "Cannot reach the ChainShield backend. No result is available." };
    } finally {
      clearTimeout(timer);
    }

    if (!response.ok) {
      let detail = "";
      try {
        const data = await response.json();
        detail = typeof data.detail === "string" ? data.detail : "";
      } catch { /* ignore */ }
      throw { type: "http", message: `Server error ${response.status}${detail ? `: ${detail}` : ""}. No result is available.` };
    }

    try {
      return await response.json();
    } catch {
      throw { type: "parse", message: "Unexpected response from the server. No result is available." };
    }
  }

  function malformed() {
    return { type: "parse", message: "Unexpected response from the server. No result is available." };
  }

  const URL_BADGES = {
    HIGH: { cls: "badge-high", label: "✕ High risk" },
    MEDIUM: { cls: "badge-medium", label: "! Suspicious" },
    SAFE: { cls: "badge-safe", label: "✓ No issues detected" },
    UNKNOWN: { cls: "badge-unknown", label: "? Inconclusive" },
  };

  /** Interpret a POST /scan response. Throws a parse error if fields are missing. */
  function describeUrlResult(data) {
    if (!data || typeof data.risk_level !== "string" || !Array.isArray(data.findings)) throw malformed();
    const level = data.risk_level.toUpperCase();
    const badge = URL_BADGES[level] || URL_BADGES.UNKNOWN;

    let state;
    let registry;
    // Only match_threat is a known threat. Older backends have no blockchain_status.
    const status = typeof data.blockchain_status === "string" ? data.blockchain_status : null;
    const registryThreat = status ? status === "match_threat" : data.blockchain_found === true;
    if (data.blockchain_available !== true) {
      registry = "Threat registry unavailable during this scan. This does not indicate safety.";
    } else if (registryThreat) {
      registry = "URL hash found in the threat registry.";
    } else if (status === "match_non_threat") {
      registry = "URL hash is registered without a threat verdict. This is not a safety guarantee.";
    } else {
      registry = "Registry checked: URL hash not found. Absence does not guarantee safety.";
    }
    if (registryThreat && level === "HIGH") state = "registry_match";
    else if (level === "HIGH" || level === "MEDIUM") state = "suspicious";
    else if (level === "SAFE") state = "no_issues";
    else state = "inconclusive";

    return { state, badgeClass: badge.cls, badgeLabel: badge.label, registry };
  }

  const MESSAGE_STATES = {
    smishing_registry_match: { cls: "badge-high", label: "✕ Known smishing (registry match)",
      text: "This exact message is registered as a known threat in the ChainShield registry." },
    likely_smishing: { cls: "badge-high", label: "! Likely smishing",
      text: "The model predicts this is a phishing (smishing) message. Predictions can be wrong." },
    generic_spam: { cls: "badge-medium", label: "Generic spam",
      text: "The model predicts unsolicited spam, not smishing. Predictions can be wrong." },
    likely_legitimate: { cls: "badge-safe", label: "Likely legitimate (model)",
      text: "The model predicts a legitimate message. This is not proof the message is safe." },
    unavailable: { cls: "badge-unknown", label: "? Detection unavailable",
      text: "The message model could not run. This is not a safety verdict." },
  };

  const REGISTRY_TEXT = {
    match_threat: "Message hash found in the threat registry.",
    match_non_threat: "Message hash is registered without a threat verdict.",
    no_match: "Registry checked: message hash not found. Absence does not guarantee safety.",
    unavailable: "Threat registry unavailable during this scan.",
  };

  /** Interpret a POST /message/scan response. Throws a parse error if fields are missing. */
  function describeMessageResult(data) {
    if (!data || !MESSAGE_STATES[data.verdict] || !data.model || !data.registry || !Array.isArray(data.findings)) {
      throw malformed();
    }
    const state = MESSAGE_STATES[data.verdict];
    let probabilities = "";
    if (data.model.status === "ok" && data.model.probabilities) {
      const p = data.model.probabilities;
      const pct = (v) => (typeof v === "number" ? `${Math.round(v * 100)}%` : "n/a");
      probabilities = `Model scores: smishing ${pct(p.smishing)}, generic spam ${pct(p.generic_spam)}, legitimate ${pct(p.legitimate)}`;
    }
    return {
      state: data.verdict,
      badgeClass: state.cls,
      badgeLabel: state.label,
      explanation: state.text,
      probabilities,
      registry: REGISTRY_TEXT[data.registry.status] || REGISTRY_TEXT.unavailable,
      findings: data.findings.filter((f) => typeof f === "string"),
      modelVersion: typeof data.model.model_version === "string" ? data.model.model_version : "",
    };
  }

  const api = {
    MAX_MESSAGE_CHARS, DEFAULT_TIMEOUT_MS, isValidUrl, validateMessage, postJson,
    describeUrlResult, describeMessageResult,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  root.ChainShieldLogic = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
