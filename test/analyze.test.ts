import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyzeEml, verdictOf, severityOf } from "../src/analyze.js";
import { parseAuthResults, parseMailbox, aligned, domainOf } from "../src/auth.js";
import { parseEml } from "../src/eml.js";
import { analyzeUrl, extractLinks } from "../src/urls.js";
import { analyzeAttachment, extensions } from "../src/attachments.js";
import { registeredDomain, levenshtein, brandImitation, homographRisk, deLeet, subdomainLabels } from "../src/domain.js";

const sample = (n: string) => readFileSync(new URL(`../../samples/${n}`, import.meta.url));
const ids = (r: ReturnType<typeof analyzeEml>) => r.findings.map((f) => f.id);

test("domain helpers", () => {
  assert.equal(registeredDomain("a.b.example.com"), "example.com");
  assert.equal(registeredDomain("shop.example.co.uk"), "example.co.uk");
  assert.equal(registeredDomain("example.com."), "example.com");
  assert.deepEqual(subdomainLabels("a.b.example.com"), ["a", "b"]);
  assert.equal(levenshtein("kitten", "sitting"), 3);
  assert.equal(levenshtein("same", "same"), 0);
  assert.equal(deLeet("paypa1"), "paypal");
  assert.equal(deLeet("rnicrosoft"), "microsoft");
});

test("brand imitation: lookalike, embedded, legit, and no false positives", () => {
  assert.equal(brandImitation("paypa1.com")?.kind, "lookalike");
  assert.equal(brandImitation("rnicrosoft.com")?.brand, "microsoft");
  assert.equal(brandImitation("paypal.com.secure-login.evil.top")?.kind, "embedded");
  assert.equal(brandImitation("login-microsoft-support.net")?.brand, "microsoft");
  assert.equal(brandImitation("paypal.com"), null);
  assert.equal(brandImitation("www.google.com"), null);
  assert.equal(brandImitation("accounts.google.com"), null);
  assert.equal(brandImitation("outlook.com"), null);
  assert.equal(brandImitation("example.org"), null);
  assert.equal(brandImitation("apple-pie-recipes.example"), null);
  assert.equal(brandImitation("amazon-secure-login.example")?.brand, "amazon");
});

test("homograph detection", () => {
  assert.deepEqual(homographRisk("xn--pypal-4ve.com"), { punycode: true, mixedScript: false });
  assert.equal(homographRisk("pаypal.com").mixedScript, true); // Cyrillic a
  assert.deepEqual(homographRisk("example.com"), { punycode: false, mixedScript: false });
});

test("mailbox and auth parsing", () => {
  assert.deepEqual(parseMailbox('"Ana B" <Ana@Example.COM>'), { name: "Ana B", address: "ana@example.com", domain: "example.com" });
  assert.equal(parseMailbox("bare@example.com")?.domain, "example.com");
  assert.equal(parseMailbox("not an address"), null);
  assert.equal(parseMailbox(undefined), null);
  assert.equal(domainOf("<x@Y.com>"), "y.com");
  assert.equal(aligned("mail.example.com", "example.com"), true);
  assert.equal(aligned("example.com", "evil.com"), false);
  const h = parseEml("Authentication-Results: mx.test; spf=pass smtp.mailfrom=a@b.com; dkim=fail header.d=x.com; dkim=pass header.d=b.com; dmarc=pass (p=reject) header.from=b.com\n\n").headers;
  const a = parseAuthResults(h);
  assert.equal(a.spf, "pass");
  assert.equal(a.spfDomain, "b.com");
  assert.equal(a.dkim, "pass");
  assert.equal(a.dkimDomain, "b.com");
  assert.equal(a.dmarc, "pass");
  const rs = parseAuthResults(parseEml("Received-SPF: Fail (domain does not designate)\n\n").headers);
  assert.equal(rs.spf, "fail");
  assert.equal(parseAuthResults(parseEml("Subject: x\n\n").headers).dmarc, "missing");
});

test("url extraction and analysis", () => {
  const html = `<a href="http://evil.top/x">https://www.paypal.com/login</a> <a href='mailto:a@b.c'>mail</a> <a href=http://u:p@host.test/>x</a>`;
  const links = extractLinks("see https://plain.example/path.", html);
  assert.ok(links.some((l) => l.href === "http://evil.top/x" && l.text.includes("paypal.com")));
  assert.ok(links.some((l) => l.href === "https://plain.example/path"));
  assert.ok(!links.some((l) => l.href.startsWith("mailto")));
  const u = analyzeUrl({ href: "http://evil.top/x", text: "https://www.paypal.com/login" })!;
  assert.ok(u.flags.some((f) => f.id === "url.mismatch"));
  assert.ok(u.flags.some((f) => f.id === "url.tld"));
  assert.ok(u.flags.some((f) => f.id === "url.http"));
  assert.ok(analyzeUrl({ href: "https://192.168.1.5/login", text: "" })!.flags.some((f) => f.id === "url.ip"));
  assert.ok(analyzeUrl({ href: "https://paypal.com@evil.test/", text: "" })!.flags.some((f) => f.id === "url.userinfo"));
  assert.ok(analyzeUrl({ href: "https://bit.ly/abc", text: "" })!.flags.some((f) => f.id === "url.shortener"));
  assert.ok(analyzeUrl({ href: "https://xn--pypal-4ve.com/", text: "" })!.flags.some((f) => f.id === "url.punycode"));
  assert.ok(analyzeUrl({ href: "https://a.b.c.d.evil.test/", text: "" })!.flags.some((f) => f.id === "url.subdomains"));
  assert.equal(analyzeUrl({ href: "https://github.com/settings", text: "https://github.com/settings" })!.flags.length, 0);
  assert.equal(analyzeUrl({ href: "not a url", text: "" }), null);
  assert.equal(analyzeUrl({ href: "ftp://x.test/", text: "" }), null);
});

test("link extraction is bounded", () => {
  const html = Array.from({ length: 1000 }, (_, i) => `<a href="https://h${i}.test/">x</a>`).join("");
  assert.ok(extractLinks("", html).length <= 200);
});

test("attachment analysis", () => {
  const mk = (filename: string, bytes: number[] = [1, 2]) => ({ filename, contentType: "x", size: 10, sha256: "", inline: false, head: Buffer.from(bytes) });
  const f = (n: string, b?: number[]) => analyzeAttachment(mk(n, b)).map((x) => x.id);
  assert.ok(f("invoice.pdf.exe").includes("att.double"));
  assert.ok(f("invoice.pdf.exe").includes("att.exec"));
  assert.ok(f("report.docm").includes("att.macro"));
  assert.ok(f("a.zip").includes("att.archive"));
  assert.ok(f("page.html").includes("att.html"));
  assert.ok(f("holiday.jpg", [0x4d, 0x5a]).includes("att.magic"));
  assert.ok(f("doc.pdf", [0x50, 0x4b]).includes("att.magic"));
  assert.ok(f("fdp.‮exe").includes("att.rtlo"));
  assert.deepEqual(f("photo.png"), []);
  assert.deepEqual(extensions("a.b.C"), ["b", "c"]);
});

test("scoring helpers", () => {
  assert.equal(verdictOf(0), "clean");
  assert.equal(verdictOf(24), "clean");
  assert.equal(verdictOf(25), "suspicious");
  assert.equal(verdictOf(55), "phishing");
  assert.equal(severityOf(40), "critical");
  assert.equal(severityOf(0), "info");
});

test("sample: PayPal phish is detected with the right reasons", () => {
  const r = analyzeEml(sample("paypal-phish.eml"));
  assert.equal(r.verdict, "phishing");
  for (const id of ["auth.spf-fail", "auth.dmarc-fail", "url.mismatch", "url.brand-embedded", "sender.brand-name", "sender.reply-to", "content.urgency", "content.pixel"]) assert.ok(ids(r).includes(id), id);
  assert.equal(r.subject, "[URGENT] Your account will be suspended");
});

test("sample: invoice with .pdf.exe attachment", () => {
  const r = analyzeEml(sample("factura-adjunto.eml"));
  assert.equal(r.verdict, "phishing");
  assert.ok(ids(r).includes("att.double") && ids(r).includes("att.exec"));
  assert.equal(r.attachments[0]!.filename, "Factura_2026.pdf.exe");
});

test("sample: CEO fraud passes authentication but is still flagged", () => {
  const r = analyzeEml(sample("ceo-giftcards.eml"));
  assert.equal(r.auth.dmarc, "pass");
  assert.equal(r.verdict, "suspicious");
  assert.ok(ids(r).includes("sender.freemail-exec"));
});

test("sample: legitimate GitHub notification scores zero", () => {
  const r = analyzeEml(sample("newsletter-ok.eml"));
  assert.equal(r.score, 0);
  assert.equal(r.verdict, "clean");
});

test("sample: prompt injection aimed at AI scanners is itself a finding", () => {
  const r = analyzeEml(sample("llm-injection.eml"));
  assert.ok(ids(r).includes("content.llm-injection"));
  assert.notEqual(r.verdict, "clean");
});

test("SPF/DKIM passing for another domain is flagged", () => {
  const r = analyzeEml("Authentication-Results: mx; spf=pass smtp.mailfrom=bounce@sender.test; dkim=pass header.d=sender.test; dmarc=none\nFrom: Bank <a@bank.test>\nMessage-ID: <1@x>\nDate: Tue, 10 Nov 2026 08:00:00 +0100\nReceived: from x by y\n\nhi");
  assert.ok(ids(r).includes("auth.spf-align"));
  assert.ok(ids(r).includes("auth.dkim-align"));
});

test("display name containing a different address", () => {
  const r = analyzeEml('From: "support@bank.test" <x@evil.test>\n\nhi');
  assert.ok(ids(r).includes("sender.name-address"));
});

test("sender domain one character from a brand", () => {
  const r = analyzeEml("From: x@gooogle.com\n\nhi");
  assert.ok(ids(r).includes("sender.lookalike"));
});

test("score is capped at 100 and findings are sorted by points", () => {
  const r = analyzeEml(sample("paypal-phish.eml"));
  assert.ok(r.score <= 100);
  for (let i = 1; i < r.findings.length; i++) assert.ok(r.findings[i - 1]!.points >= r.findings[i]!.points);
});

test("garbage input produces a report instead of a crash", () => {
  const r = analyzeEml("\u0000\u0001garbage");
  assert.ok(r.warnings.length > 0);
  assert.ok(ids(r).includes("sender.no-from"));
});

test("HTML form in the body is a credential harvester signal", () => {
  const r = analyzeEml("From: a@b.test\nContent-Type: text/html\n\n<form action='http://x.test'><input name=p type=password></form>");
  assert.ok(ids(r).includes("content.form"));
});

test("Spanish and Portuguese lures are recognized", () => {
  assert.ok(ids(analyzeEml("From: a@b.test\nSubject: Aviso\n\nSu cuenta sera suspendida. Verifica tu cuenta ahora.")).includes("content.credentials"));
  assert.ok(ids(analyzeEml("From: a@b.test\nSubject: Aviso\n\nSua conta sera bloqueada imediatamente.")).includes("content.urgency"));
});
