import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { createServer, CSP } from "../src/server.js";

async function withServer<T>(fn: (base: string) => Promise<T>, ai = {}): Promise<T> {
  const s = createServer({ ai });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  try { return await fn(`http://127.0.0.1:${(s.address() as AddressInfo).port}`); } finally { await new Promise((r) => s.close(r)); }
}
const eml = (n: string) => readFileSync(new URL(`../../samples/${n}`, import.meta.url));

test("analyze endpoint returns report, ai and final verdict", () => withServer(async (b) => {
  const res = await fetch(b + "/api/analyze", { method: "POST", body: eml("paypal-phish.eml") });
  assert.equal(res.status, 200);
  const j: any = await res.json();
  assert.equal(j.final.verdict, "phishing");
  assert.equal(j.ai.source, "offline");
  assert.ok(j.report.findings.length > 5);
}));

test("ai=0 skips the second opinion", () => withServer(async (b) => {
  const j: any = await (await fetch(b + "/api/analyze?ai=0", { method: "POST", body: eml("newsletter-ok.eml") })).json();
  assert.equal(j.ai, null);
  assert.equal(j.final.verdict, "clean");
}));

test("empty and oversized bodies are rejected", () => withServer(async (b) => {
  assert.equal((await fetch(b + "/api/analyze", { method: "POST", body: "" })).status, 400);
  const big = Buffer.alloc(10 * 1024 * 1024 + 10, 97);
  try {
    const r = await fetch(b + "/api/analyze", { method: "POST", body: big });
    assert.equal(r.status, 413);
  } catch (e) {
    assert.ok(e instanceof TypeError); // connection destroyed while uploading is also a valid refusal
  }
}));

test("every response carries the strict CSP and nosniff", () => withServer(async (b) => {
  for (const p of ["/", "/app.js", "/style.css", "/api/samples", "/nope"]) {
    const r = await fetch(b + p);
    assert.equal(r.headers.get("content-security-policy"), CSP, p);
    assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  }
  assert.ok(!CSP.includes("unsafe-inline"));
}));

test("static files: no traversal, only known types", () => withServer(async (b) => {
  assert.equal((await fetch(b + "/..%2Fpackage.json")).status, 404);
  assert.equal((await fetch(b + "/%2e%2e/package.json")).status, 404);
  assert.equal((await fetch(b + "/index.html")).status, 200);
  assert.equal((await fetch(b + "/package.json")).status, 404);
}));

test("samples list and download, unknown sample is 404, bad method is 405", () => withServer(async (b) => {
  const l: any = await (await fetch(b + "/api/samples")).json();
  assert.ok(l.samples.includes("paypal-phish.eml"));
  assert.equal(l.aiConfigured, false);
  assert.equal((await fetch(b + "/api/samples/paypal-phish.eml")).status, 200);
  assert.equal((await fetch(b + "/api/samples/secret.eml")).status, 404);
  assert.equal((await fetch(b + "/api/analyze", { method: "DELETE" })).status, 405);
}));

test("index page has no inline script or style and the JS never uses innerHTML", () => {
  const html = readFileSync(new URL("../../public/index.html", import.meta.url), "utf8");
  assert.ok(!/<script(?![^>]*\bsrc=)/i.test(html));
  assert.ok(!/<style|style=/i.test(html));
  assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/.test(readFileSync(new URL("../../public/app.js", import.meta.url), "utf8")));
});
