// The dev/preview proxy must forward API paths only, never the dashboard's own routes.
import { test } from "node:test";
import assert from "node:assert/strict";
import config from "../vite.config.js";

const keys = Object.keys(config.server.proxy);
const proxied = (path) => keys.some((k) => (k.startsWith("^") ? new RegExp(k).test(path) : path.startsWith(k)));

test("API paths are proxied", () => {
  for (const path of ["/scan", "/scan/history", "/message/scan", "/message/history"]) assert.ok(proxied(path), path);
});

test("dashboard routes are not proxied", () => {
  for (const path of ["/scanner", "/messages", "/history", "/overview", "/"]) assert.ok(!proxied(path), path);
});
