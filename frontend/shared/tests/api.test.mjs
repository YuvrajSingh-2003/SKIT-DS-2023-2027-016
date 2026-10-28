// Tests for frontend/shared/api.js (node --test; fetch is mocked, no network).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = readFileSync(new URL("../api.js", import.meta.url), "utf8");
const api = await import(`data:text/javascript,${encodeURIComponent(source)}`);

function withFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return fn().finally(() => { globalThis.fetch = original; });
}

test("422 validation details are readable, not [object Object]", () =>
  withFetch(async () => new Response(JSON.stringify({ detail: [{ loc: ["body", "url"], msg: "Input should be a valid URL" }] }),
    { status: 422 }), async () => {
    await assert.rejects(api.scanUrl("nope"), (err) => {
      assert.equal(err.type, "http");
      assert.equal(err.status, 422);
      assert.match(err.message, /Input should be a valid URL/);
      assert.doesNotMatch(err.message, /object Object/);
      return true;
    });
  }));

test("string detail is kept as is", () =>
  withFetch(async () => new Response(JSON.stringify({ detail: "An error occurred" }), { status: 500 }), async () => {
    await assert.rejects(api.getScanHistory(), (err) => err.message === "Server returned 500: An error occurred");
  }));

test("a hung backend times out as an error, never a result", () =>
  withFetch((url, opts) => new Promise((_, reject) => {
    opts.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
  }), async () => {
    await assert.rejects(api.apiFetch("/scan", { method: "POST" }, undefined, 20), (err) => err.type === "timeout");
  }));

test("network failure is reported as network error", () =>
  withFetch(async () => { throw new TypeError("Failed to fetch"); }, async () => {
    await assert.rejects(api.getMessageHistory(), (err) => err.type === "network");
  }));

test("successful JSON is returned unchanged", () =>
  withFetch(async () => new Response(JSON.stringify({ risk_level: "UNKNOWN" }), { status: 200 }), async () => {
    assert.deepEqual(await api.scanMessage("hi"), { risk_level: "UNKNOWN" });
  }));
