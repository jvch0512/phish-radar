import test from "node:test";
import assert from "node:assert/strict";
import { decodeWords, decodeBody, parseParams, parseEml, htmlToText, decodeEntities, header, MAX_MESSAGE_BYTES } from "../src/eml.js";

test("RFC 2047 encoded words: base64, quoted-printable, joined words, other charsets", () => {
  assert.equal(decodeWords("=?UTF-8?B?SGVsbG8gV29ybGQ=?="), "Hello World");
  assert.equal(decodeWords("=?utf-8?Q?Caf=C3=A9_Cr=C3=A8me?="), "Café Crème");
  assert.equal(decodeWords("=?UTF-8?B?SGVsbG8g?= =?UTF-8?B?V29ybGQ=?="), "Hello World");
  assert.equal(decodeWords("=?iso-8859-1?Q?Se=F1or?= Gomez"), "Señor Gomez");
  assert.equal(decodeWords("=?bogus-charset?Q?abc?="), "abc");
  assert.equal(decodeWords("plain text"), "plain text");
});

test("quoted-printable and base64 bodies", () => {
  assert.equal(decodeBody("caf=C3=A9 =\r\nline", "quoted-printable").toString("utf8"), "café line");
  assert.equal(decodeBody("SGk=", "base64").toString(), "Hi");
  assert.equal(decodeBody("SG\r\nk=", "base64").toString(), "Hi");
  assert.equal(decodeBody("=ZZ=4", "quoted-printable").toString("latin1"), "=ZZ=4");
});

test("content type parameters, quoted values with semicolons", () => {
  const p = parseParams('multipart/mixed; boundary="a;b"; charset=UTF-8');
  assert.equal(p.type, "multipart/mixed");
  assert.equal(p.params["boundary"], "a;b");
  assert.equal(p.params["charset"], "UTF-8");
  assert.deepEqual(parseParams("").params, {});
});

test("simple message with folded headers", () => {
  const m = parseEml("Subject: hello\r\n world\r\nFrom: a@b.test\r\n\r\nbody text\r\n");
  assert.equal(header(m.headers, "subject"), "hello world");
  assert.equal(m.text.trim(), "body text");
  assert.equal(m.attachments.length, 0);
});

test("multipart/alternative with html and text, nested mixed with attachment", () => {
  const eml = [
    "From: a@b.test",
    'Content-Type: multipart/mixed; boundary="OUTER"',
    "",
    "preamble ignored",
    "--OUTER",
    'Content-Type: multipart/alternative; boundary="INNER"',
    "",
    "--INNER",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: quoted-printable",
    "",
    "Hola caf=C3=A9",
    "--INNER",
    "Content-Type: text/html; charset=utf-8",
    "",
    "<p>Hola <b>caf&eacute;</b></p>",
    "--INNER--",
    "--OUTER",
    'Content-Type: application/octet-stream; name="Invoice.pdf.exe"',
    "Content-Transfer-Encoding: base64",
    "Content-Disposition: attachment",
    "",
    "TVqQAAMAAAAEAAAA",
    "--OUTER--",
    "epilogue",
    "",
  ].join("\r\n");
  const m = parseEml(eml);
  assert.equal(m.text.trim(), "Hola café");
  assert.match(m.html, /<b>caf/);
  assert.equal(m.attachments.length, 1);
  const a = m.attachments[0]!;
  assert.equal(a.filename, "Invoice.pdf.exe");
  assert.equal(a.head.subarray(0, 2).toString("latin1"), "MZ");
  assert.equal(a.sha256.length, 64);
});

test("html-only message gets a text rendering", () => {
  const m = parseEml("Content-Type: text/html\r\n\r\n<style>x{}</style><p>Hello&nbsp;<a href='#'>there</a></p><script>evil()</script>");
  assert.equal(m.text, "Hello there");
});

test("RFC 2047 filenames are decoded and unnamed binary parts are attachments", () => {
  const eml = 'Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename="=?UTF-8?B?ZmFjdHVyYS56aXA=?="\r\n\r\nAAAA\r\n--B\r\nContent-Type: image/png\r\n\r\nBBBB\r\n--B--\r\n';
  const m = parseEml(eml);
  assert.deepEqual(m.attachments.map((a) => a.filename), ["factura.zip", "(unnamed)"]);
});

test("malformed input never throws and reports warnings", () => {
  for (const bad of ["", "not an email at all", "\r\n\r\n", "Content-Type: multipart/mixed\r\n\r\nx", "Content-Type: multipart/mixed; boundary=\r\n\r\n--\r\n", "\x00\x01\x02", "A: b\r\nbroken line without colon\r\n\r\nbody"]) {
    const m = parseEml(bad);
    assert.ok(Array.isArray(m.warnings));
  }
  assert.ok(parseEml("random words").warnings.some((w) => /no valid headers/.test(w)));
});

test("limits: part count, nesting depth, message size", () => {
  const many = ["Content-Type: multipart/mixed; boundary=B", ""];
  for (let i = 0; i < 400; i++) many.push("--B", "Content-Type: text/plain", "", "x" + i);
  many.push("--B--", "");
  const m = parseEml(many.join("\n"));
  assert.ok(m.warnings.some((w) => /part limit/.test(w)));

  let nested = "Content-Type: text/plain\r\n\r\ndeep";
  for (let i = 0; i < 20; i++) nested = `Content-Type: multipart/mixed; boundary=L${i}\r\n\r\n--L${i}\r\n${nested}\r\n--L${i}--\r\n`;
  assert.ok(parseEml(nested).warnings.some((w) => /nesting/.test(w)));

  assert.throws(() => parseEml("a".repeat(MAX_MESSAGE_BYTES + 1)), /larger than/);
});

test("html helpers", () => {
  assert.equal(decodeEntities("&lt;a&gt; &amp; &#65;&#x42; &quot;x&quot; &bogus; &#0;"), '<a> & AB "x" &bogus; ');
  assert.equal(htmlToText("<p>a</p><p>b<br>c</p>"), "a\nb\nc");
});

test("mbox From line is ignored", () => {
  const m = parseEml("From sender@example.test Mon Jan  1 00:00:00 2026\nSubject: x\n\nhi");
  assert.equal(header(m.headers, "subject"), "x");
});
