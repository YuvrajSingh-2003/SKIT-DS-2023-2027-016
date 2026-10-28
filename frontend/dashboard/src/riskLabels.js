/**
 * Risk-level wording shared by the dashboard's badges. Kept in step with the
 * extension (frontend/extension/src/logic.js, URL_BADGES); a Node test checks this.
 * LOW is used only by message scans: a low-risk model prediction, never "safe".
 */
export const RISK_LABELS = {
  SAFE:    { label: "No issues detected", cls: "badge-safe",    icon: "✓" },
  MEDIUM:  { label: "Suspicious",         cls: "badge-medium",  icon: "!" },
  HIGH:    { label: "High risk",          cls: "badge-high",    icon: "✕" },
  LOW:     { label: "Low risk",           cls: "badge-safe",    icon: "·" },
  UNKNOWN: { label: "Inconclusive",       cls: "badge-unknown", icon: "?" },
};

/** Unknown or missing levels are shown as inconclusive, never as safe. */
export function riskLabel(level) {
  return RISK_LABELS[String(level || "UNKNOWN").toUpperCase()] ?? RISK_LABELS.UNKNOWN;
}

/** Plain-language registry statuses (URL and message history). */
export const REGISTRY_LABELS = {
  match_threat: "Known threat",
  match_non_threat: "Registered, not a threat",
  no_match: "Not in registry",
  unavailable: "Registry unavailable",
  match_unclassified: "Registered, verdict not recorded",
  not_recorded: "Not recorded",
};

export function registryLabel(status) {
  return REGISTRY_LABELS[status] ?? "Registry unavailable";
}

/** Error text for a failed request; adds "No result is available." only once. */
export function failureText(error) {
  const text = (error && error.message) || "Unknown error";
  if (/No result is available\.?$/.test(text)) return text;
  return /[.?!]$/.test(text) ? `${text} No result is available.` : `${text}. No result is available.`;
}
