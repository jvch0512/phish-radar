import { Header, headersAll, header } from "./eml.js";
import { registeredDomain } from "./domain.js";

export type AuthResult = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | "policy" | "missing";

export interface AuthSummary {
  spf: AuthResult;
  dkim: AuthResult;
  dmarc: AuthResult;
  spfDomain?: string; // smtp.mailfrom domain
  dkimDomain?: string; // header.d
  dmarcPolicy?: string;
  authservId?: string;
}

const KNOWN = new Set<AuthResult>(["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"]);

function asResult(s: string | undefined): AuthResult {
  const v = (s ?? "").toLowerCase() as AuthResult;
  return KNOWN.has(v) ? v : "missing";
}

/** Parses Authentication-Results (RFC 8601). Uses only the topmost header, which our own MTA added. */
export function parseAuthResults(headers: Header[]): AuthSummary {
  const out: AuthSummary = { spf: "missing", dkim: "missing", dmarc: "missing" };
  const ar = headersAll(headers, "authentication-results")[0]?.value;
  if (ar) {
    out.authservId = ar.split(";")[0]?.trim().split(/\s+/)[0];
    for (const seg of ar.split(";").slice(1)) {
      const s = seg.trim();
      const m = /^(spf|dkim|dmarc)\s*=\s*([a-z]+)/i.exec(s);
      if (!m) continue;
      const method = m[1]!.toLowerCase() as "spf" | "dkim" | "dmarc";
      const res = asResult(m[2]);
      // for multiple DKIM signatures keep the best result
      if (method === "dkim" && out.dkim === "pass") continue;
      out[method] = res;
      if (method === "spf") out.spfDomain = domainOf(/smtp\.mailfrom=([^\s;]+)/i.exec(s)?.[1]);
      if (method === "dkim") out.dkimDomain = /header\.[di]=@?([^\s;]+)/i.exec(s)?.[1]?.toLowerCase();
      if (method === "dmarc") out.dmarcPolicy = /p=([a-z]+)/i.exec(s)?.[1]?.toLowerCase();
    }
  }
  if (out.spf === "missing") {
    const rs = header(headers, "received-spf");
    const m = /^\s*([a-z]+)/i.exec(rs ?? "");
    if (m) out.spf = asResult(m[1]);
  }
  return out;
}

export function domainOf(addr: string | undefined): string | undefined {
  if (!addr) return undefined;
  const at = addr.lastIndexOf("@");
  const d = (at >= 0 ? addr.slice(at + 1) : addr).replace(/[>\s"']/g, "").toLowerCase();
  return d || undefined;
}

export interface Mailbox {
  name: string;
  address: string;
  domain: string;
}

export function parseMailbox(v: string | undefined): Mailbox | null {
  if (!v) return null;
  const angle = /^(.*?)<([^<>]+)>/.exec(v);
  const address = (angle ? angle[2]! : v).trim().replace(/^mailto:/i, "");
  if (!/^[^@\s]+@[^@\s]+$/.test(address)) return null;
  const name = angle ? angle[1]!.trim().replace(/^"|"$/g, "") : "";
  return { name, address: address.toLowerCase(), domain: address.slice(address.lastIndexOf("@") + 1).toLowerCase() };
}

export const aligned = (a: string | undefined, b: string | undefined): boolean => !!a && !!b && registeredDomain(a) === registeredDomain(b);
