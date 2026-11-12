// RFC 5322 / MIME parser for .eml files. Everything here handles untrusted input, so every loop
// is bounded and malformed input produces warnings, never exceptions.

import { createHash } from "node:crypto";

export const MAX_MESSAGE_BYTES = 10 * 1024 * 1024;
const MAX_HEADER_BYTES = 100 * 1024;
const MAX_PARTS = 200;
const MAX_DEPTH = 8;

export interface Header {
  name: string;
  value: string; // unfolded and RFC 2047 decoded
  raw: string; // unfolded, not decoded
}

export interface Attachment {
  filename: string;
  contentType: string;
  size: number;
  sha256: string;
  inline: boolean;
  head: Buffer; // first bytes, for magic number checks
}

export interface ParsedEmail {
  headers: Header[];
  text: string;
  html: string;
  attachments: Attachment[];
  warnings: string[];
}

export function decodeCharset(buf: Buffer, charset: string | undefined): string {
  const cs = (charset ?? "utf-8").toLowerCase().replace(/^"|"$/g, "");
  try {
    if (cs === "us-ascii" || cs === "ascii") return buf.toString("latin1");
    return new TextDecoder(cs === "utf8" ? "utf-8" : cs).decode(buf);
  } catch {
    return buf.toString("latin1");
  }
}

function qDecode(s: string): Buffer {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "_") out.push(0x20);
    else if (c === "=" && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 1, i + 3))) {
      out.push(parseInt(s.slice(i + 1, i + 3), 16));
      i += 2;
    } else out.push(s.charCodeAt(i) & 0xff);
  }
  return Buffer.from(out);
}

/** Decodes RFC 2047 encoded words (=?charset?B|Q?text?=). Adjacent encoded words are joined. */
export function decodeWords(value: string): string {
  const joined = value.replace(/(\?=)\s+(=\?)/g, "$1$2");
  return joined.replace(/=\?([^?\s]+)\?([bBqQ])\?([^?\s]*)\?=/g, (_m, cs: string, enc: string, text: string) => {
    const bytes = enc.toLowerCase() === "b" ? Buffer.from(text, "base64") : qDecode(text);
    return decodeCharset(bytes, cs);
  });
}

function splitHead(raw: string): [string, string] {
  const m = /\r?\n\r?\n/.exec(raw);
  if (!m) return [raw, ""];
  return [raw.slice(0, m.index), raw.slice(m.index + m[0].length)];
}

function parseHeaders(block: string, warnings: string[]): Header[] {
  if (block.length > MAX_HEADER_BYTES) {
    warnings.push("header block truncated at 100 KB");
    block = block.slice(0, MAX_HEADER_BYTES);
  }
  const unfolded: string[] = [];
  for (const line of block.split(/\r?\n/)) {
    if (/^[ \t]/.test(line) && unfolded.length) unfolded[unfolded.length - 1] += " " + line.trim();
    else unfolded.push(line);
  }
  const out: Header[] = [];
  for (const line of unfolded) {
    const i = line.indexOf(":");
    if (i <= 0 || /[\s]/.test(line.slice(0, i))) {
      if (line.trim()) warnings.push("ignored malformed header line");
      continue;
    }
    const raw = line.slice(i + 1).trim();
    out.push({ name: line.slice(0, i), value: decodeWords(raw), raw });
  }
  return out;
}

export function header(headers: Header[], name: string): string | undefined {
  const n = name.toLowerCase();
  return headers.find((h) => h.name.toLowerCase() === n)?.value;
}

export function headersAll(headers: Header[], name: string): Header[] {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n);
}

/** Splits "text/html; charset=utf-8; name=x" into the type and its parameters. */
export function parseParams(value: string): { type: string; params: Record<string, string> } {
  const parts: string[] = [];
  let cur = "";
  let q = false;
  for (const ch of value) {
    if (ch === '"') q = !q;
    if (ch === ";" && !q) { parts.push(cur); cur = ""; } else cur += ch;
  }
  parts.push(cur);
  const params: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const i = p.indexOf("=");
    if (i < 0) continue;
    params[p.slice(0, i).trim().toLowerCase()] = p.slice(i + 1).trim().replace(/^"|"$/g, "");
  }
  return { type: (parts[0] ?? "").trim().toLowerCase(), params };
}

export function decodeBody(body: string, encoding: string): Buffer {
  const enc = encoding.trim().toLowerCase();
  if (enc === "base64") return Buffer.from(body.replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
  if (enc === "quoted-printable") {
    const s = body.replace(/=\r?\n/g, "");
    const out: number[] = [];
    for (let i = 0; i < s.length; i++) {
      if (s[i] === "=" && /^[0-9a-fA-F]{2}$/.test(s.slice(i + 1, i + 3))) {
        out.push(parseInt(s.slice(i + 1, i + 3), 16));
        i += 2;
      } else out.push(s.charCodeAt(i) & 0xff);
    }
    return Buffer.from(out);
  }
  return Buffer.from(body, "latin1");
}

interface Ctx {
  text: string[];
  html: string[];
  attachments: Attachment[];
  warnings: string[];
  parts: number;
}

function walk(raw: string, depth: number, ctx: Ctx): void {
  if (ctx.parts++ >= MAX_PARTS) {
    if (ctx.parts === MAX_PARTS + 1) ctx.warnings.push("part limit reached, remaining MIME parts ignored");
    return;
  }
  const [head, body] = splitHead(raw);
  const hs = parseHeaders(head, ctx.warnings);
  const ct = parseParams(header(hs, "content-type") ?? "text/plain");
  const dispo = parseParams(header(hs, "content-disposition") ?? "");
  const encoding = header(hs, "content-transfer-encoding") ?? "7bit";

  if (ct.type.startsWith("multipart/") && ct.params["boundary"]) {
    if (depth >= MAX_DEPTH) {
      ctx.warnings.push("MIME nesting limit reached");
      return;
    }
    const b = ct.params["boundary"];
    const chunks = body.split("--" + b);
    for (let i = 1; i < chunks.length; i++) {
      let c = chunks[i]!;
      if (c.startsWith("--")) break; // closing delimiter
      c = c.replace(/^[ \t]*\r?\n/, "");
      walk(c, depth + 1, ctx);
    }
    return;
  }

  const filename = decodeWords(dispo.params["filename"] ?? ct.params["name"] ?? "");
  const isAttachment = dispo.type === "attachment" || filename !== "" || (!ct.type.startsWith("text/") && !ct.type.startsWith("multipart/") && ct.type !== "message/rfc822" && ct.type !== "");
  const bytes = decodeBody(body, encoding);
  if (isAttachment) {
    ctx.attachments.push({
      filename: filename || "(unnamed)",
      contentType: ct.type,
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      inline: dispo.type === "inline",
      head: bytes.subarray(0, 8),
    });
    return;
  }
  const decoded = decodeCharset(bytes, ct.params["charset"]);
  if (ct.type === "text/html") ctx.html.push(decoded);
  else if (ct.type === "text/plain" || ct.type === "") ctx.text.push(decoded);
}

export function htmlToText(html: string): string {
  return decodeEntities(
    html
      .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
      .replace(/<br\s*\/?>|<\/(p|div|tr|li|h\d)>/gi, "\n")
      .replace(/<[^>]*>/g, " "),
  )
    .replace(/[ \t]*\n[ \t]*/g, "\n")
    .replace(/[ \t]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos|nbsp);/gi, (_m, e: string) => {
    const l = e.toLowerCase();
    if (l === "amp") return "&";
    if (l === "lt") return "<";
    if (l === "gt") return ">";
    if (l === "quot") return '"';
    if (l === "apos") return "'";
    if (l === "nbsp") return " ";
    const code = l.startsWith("#x") ? parseInt(l.slice(2), 16) : parseInt(l.slice(1), 10);
    return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
  });
}

export function parseEml(input: Buffer | string): ParsedEmail {
  const warnings: string[] = [];
  let raw = typeof input === "string" ? input : input.toString("latin1");
  if (raw.length > MAX_MESSAGE_BYTES) throw new Error(`message larger than ${MAX_MESSAGE_BYTES} bytes`);
  raw = raw.replace(/^(?:From [^\r\n]*\r?\n)/, ""); // mbox "From " line
  const [head] = splitHead(raw);
  const headers = parseHeaders(head, warnings);
  if (headers.length === 0) warnings.push("no valid headers found, this may not be an email");
  const ctx: Ctx = { text: [], html: [], attachments: [], warnings, parts: 0 };
  walk(raw, 0, ctx);
  const html = ctx.html.join("\n");
  const text = ctx.text.join("\n") || htmlToText(html);
  return { headers, text, html, attachments: ctx.attachments, warnings };
}
