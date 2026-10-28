// Dependency-free tests for src/riskLabels.js and its consistency with the extension.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const source = readFileSync(new URL("../src/riskLabels.js", import.meta.url), "utf8");
const labels = await import(`data:text/javascript,${encodeURIComponent(source)}`);
const extension = createRequire(import.meta.url)("../../extension/src/logic.js");

test("URL risk wording matches the extension", () => {
  for (const level of ["SAFE", "MEDIUM", "HIGH", "UNKNOWN"]) {
    const ext = extension.describeUrlResult({ risk_level: level, findings: [], blockchain_available: false });
    const dash = labels.riskLabel(level);
    assert.equal(ext.badgeLabel, `${dash.icon} ${dash.label}`, level);
    assert.equal(ext.badgeClass, dash.cls, level);
  }
});

test("missing or unexpected levels are inconclusive, never safe", () => {
  for (const level of [undefined, null, "", "bogus", "safe-ish"]) {
    assert.equal(labels.riskLabel(level).label, "Inconclusive");
  }
  assert.equal(labels.riskLabel("safe").label, "No issues detected");
});

test("registry statuses get plain wording; unknown statuses are 'unavailable'", () => {
  assert.equal(labels.registryLabel("no_match"), "Not in registry");
  assert.equal(labels.registryLabel("match_threat"), "Known threat");
  assert.equal(labels.registryLabel("something-new"), "Registry unavailable");
});

test("failure text says 'No result is available.' exactly once", () => {
  const once = (s) => s.split("No result is available.").length - 1;
  assert.equal(once(labels.failureText({ message: "The ChainShield backend did not respond in time. No result is available." })), 1);
  assert.equal(labels.failureText({ message: "Server returned 500: boom" }), "Server returned 500: boom. No result is available.");
  assert.equal(labels.failureText(null), "Unknown error. No result is available.");
  assert.equal(labels.failureText({ message: "Cannot reach the ChainShield backend. Is the server running?" }),
    "Cannot reach the ChainShield backend. Is the server running? No result is available.");
  assert.equal(labels.failureText({ message: "Ends with a period." }), "Ends with a period. No result is available.");
});
