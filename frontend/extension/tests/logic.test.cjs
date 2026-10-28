// Run with: node --test frontend/extension/tests/
// Uses only Node's built-in test runner; no packages, no network.
const test = require("node:test");
const assert = require("node:assert/strict");
const L = require("../src/logic.js");

const okResponse = (data) => async () => ({ ok: true, status: 200, json: async () => data });

test("validates URLs and messages", () => {
  assert.equal(L.isValidUrl("https://example.com"), true);
  assert.equal(L.isValidUrl("ftp://example.com"), false);
  assert.equal(L.isValidUrl("not a url"), false);
  assert.match(L.validateMessage("   "), /paste/i);
  assert.match(L.validateMessage("x".repeat(L.MAX_MESSAGE_CHARS + 1)), /limited/);
  assert.equal(L.validateMessage("hello"), null);
});

test("builds the POST request with JSON body", async () => {
  let seen;
  const fake = async (url, init) => { seen = { url, init }; return okResponse({})(); };
  await L.postJson(fake, "http://127.0.0.1:8000/", "/message/scan", { text: "hi" });
  assert.equal(seen.url, "http://127.0.0.1:8000/message/scan");
  assert.equal(seen.init.method, "POST");
  assert.equal(seen.init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(seen.init.body), { text: "hi" });
});

test("timeout, network, HTTP and parse failures are errors, never results", async () => {
  const hang = (url, init) => new Promise((_, reject) =>
    init.signal.addEventListener("abort", () => reject(Object.assign(new Error("x"), { name: "AbortError" }))));
  await assert.rejects(L.postJson(hang, "http://h", "/scan", {}, 20), { type: "timeout" });
  await assert.rejects(L.postJson(async () => { throw new TypeError("down"); }, "http://h", "/scan", {}), { type: "network" });
  await assert.rejects(L.postJson(async () => ({ ok: false, status: 503, json: async () => ({ detail: "busy" }) }), "http://h", "/scan", {}),
    (e) => e.type === "http" && /503/.test(e.message));
  await assert.rejects(L.postJson(async () => ({ ok: true, json: async () => { throw new Error("bad"); } }), "http://h", "/scan", {}),
    { type: "parse" });
});

const message = (verdict, extra = {}) => ({
  verdict, findings: [], model: { status: "ok", probabilities: { smishing: 0.8, generic_spam: 0.1, legitimate: 0.1 }, model_version: "v1" },
  registry: { status: "no_match" }, ...extra,
});

test("each message verdict has a distinct state and wording", () => {
  const states = ["smishing_registry_match", "likely_smishing", "generic_spam", "likely_legitimate", "unavailable"]
    .map((v) => L.describeMessageResult(message(v)));
  assert.equal(new Set(states.map((s) => s.badgeLabel)).size, 5);
  assert.match(states[1].explanation, /can be wrong/);
  assert.match(states[2].explanation, /not smishing/);
  assert.match(states[3].explanation, /not proof/);
  assert.match(states[4].explanation, /not a safety verdict/);
  assert.match(states[1].probabilities, /smishing 80%/);
});

test("registry statuses are described without implying safety", () => {
  assert.match(L.describeMessageResult(message("likely_legitimate")).registry, /does not guarantee/);
  assert.match(L.describeMessageResult(message("likely_smishing", { registry: { status: "unavailable" } })).registry, /unavailable/);
});

test("malformed message and URL responses are rejected", () => {
  assert.throws(() => L.describeMessageResult({ verdict: "safe" }), { type: "parse" });
  assert.throws(() => L.describeMessageResult(null), { type: "parse" });
  assert.throws(() => L.describeUrlResult({ findings: [] }), { type: "parse" });
});

test("URL results distinguish registry match, suspicion, no issues and inconclusive", () => {
  const base = { findings: [], blockchain_available: true, blockchain_found: false };
  assert.equal(L.describeUrlResult({ ...base, risk_level: "HIGH", blockchain_found: true }).state, "registry_match");
  assert.equal(L.describeUrlResult({ ...base, risk_level: "MEDIUM" }).state, "suspicious");
  assert.equal(L.describeUrlResult({ ...base, risk_level: "SAFE" }).state, "no_issues");
  assert.equal(L.describeUrlResult({ ...base, risk_level: "UNKNOWN" }).state, "inconclusive");
  assert.match(L.describeUrlResult({ ...base, risk_level: "SAFE", blockchain_available: false }).registry, /does not indicate safety/);
  assert.doesNotMatch(L.describeUrlResult({ ...base, risk_level: "SAFE" }).badgeLabel, /^✓ Safe$/);
});

test("registered non-threat URL is not shown as a registry match", () => {
  const base = { findings: [], blockchain_available: true, blockchain_found: true };
  const nonThreat = L.describeUrlResult({ ...base, risk_level: "HIGH", blockchain_status: "match_non_threat" });
  assert.notEqual(nonThreat.state, "registry_match");
  assert.match(nonThreat.registry, /without a threat verdict/);
  assert.equal(L.describeUrlResult({ ...base, risk_level: "HIGH", blockchain_status: "match_threat" }).state, "registry_match");
  // Older backend without blockchain_status keeps the previous behavior.
  assert.equal(L.describeUrlResult({ ...base, risk_level: "HIGH" }).state, "registry_match");
});

test("422 validation details are shown as readable text", async () => {
  const response = { ok: false, status: 422, json: async () => ({ detail: [{ loc: ["body", "text"], msg: "Value error, text must not be blank" }] }) };
  await assert.rejects(L.postJson(async () => response, "http://h", "/message/scan", {}),
    (e) => e.type === "http" && /422: Value error, text must not be blank/.test(e.message) && !/object/.test(e.message));
});

test("timeout matches the dashboard and outlasts the backend's registry timeouts", () => {
  assert.equal(L.DEFAULT_TIMEOUT_MS, 60000);
});

test("likely smishing uses the MEDIUM colour, registry matches use HIGH", () => {
  const base = { model: { status: "ok" }, registry: { status: "no_match" }, findings: [] };
  assert.equal(L.describeMessageResult({ ...base, verdict: "likely_smishing" }).badgeClass, "badge-medium");
  assert.equal(L.describeMessageResult({ ...base, verdict: "smishing_registry_match", registry: { status: "match_threat" } }).badgeClass, "badge-high");
});
