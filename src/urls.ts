import { decodeEntities } from "./eml.js";
import { RISKY_TLDS, SHORTENERS, brandImitation, homographRisk, registeredDomain, subdomainLabels } from "./domain.js";

export interface LinkRef {
  href: string;
  text: string; // anchor text, empty for plain text URLs
}

const MAX_LINKS = 200;

export function extractLinks(text: string, html: string): LinkRef[] {
  const out: LinkRef[] = [];
  const seen = new Set<string>();
  const add = (href: string, t: string) => {
    const key = href + "\u0000" + t;
    if (!seen.has(key) && out.length < MAX_LINKS) {
      seen.add(key);
      out.push({ href, text: t });
    }
  };
  const re = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const href = decodeEntities((m[1] ?? m[2] ?? m[3] ?? "").trim());
    const label = decodeEntities(m[4]!.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
    if (/^(https?:)?\/\//i.test(href)) add(href, label);
  }
  const plain = /\bhttps?:\/\/[^\s<>"'()]+/gi;
  for (const src of [text, html.replace(/<[^>]*>/g, " ")]) {
    while ((m = plain.exec(src)) !== null) add(m[0].replace(/[.,;:!?]+$/, ""), "");
  }
  return out;
}

export interface UrlFlag {
  id: string;
  points: number;
  title: string;
  detail: string;
}

export interface UrlInfo {
  href: string;
  host: string;
  text: string;
  flags: UrlFlag[];
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function analyzeUrl(link: LinkRef): UrlInfo | null {
  let u: URL;
  try {
    u = new URL(link.href);
  } catch {
    return null;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  const host = u.hostname.toLowerCase();
  const flags: UrlFlag[] = [];
  const flag = (id: string, points: number, title: string, detail: string) => flags.push({ id, points, title, detail });

  if (IPV4.test(host) || host.startsWith("[") || /^0x[0-9a-f]+$/i.test(host) || /^\d{8,10}$/.test(host)) {
    flag("url.ip", 20, "URL points to an IP address", `Legitimate senders use domain names, this one uses ${host}.`);
  }
  if (u.username || u.password) {
    flag("url.userinfo", 25, "Credentials trick in URL", "Everything before the @ is a decoy, the real host is " + host + ".");
  }
  const hr = homographRisk(host);
  if (hr.mixedScript) flag("url.homograph", 30, "Mixed-script domain (homograph)", `Domain ${host} mixes ASCII and non-ASCII letters, which is used to imitate real brands.`);
  else if (hr.punycode) flag("url.punycode", 15, "Punycode (IDN) domain", `${host} is an internationalized domain and may render as look-alike characters.`);
  if (SHORTENERS.has(registeredDomain(host))) flag("url.shortener", 10, "URL shortener", "The final destination is hidden behind a redirect.");
  const tld = host.split(".").pop() ?? "";
  if (RISKY_TLDS.has(tld)) flag("url.tld", 8, `Frequently abused TLD .${tld}`, "This TLD has a high share of malicious registrations.");
  if (subdomainLabels(host).length >= 4) flag("url.subdomains", 8, "Excessive subdomain depth", `${host} has ${subdomainLabels(host).length} subdomain levels, often used to push the real domain out of view.`);
  const brand = brandImitation(host);
  if (brand) {
    flag(
      brand.kind === "lookalike" ? "url.brand-lookalike" : "url.brand-embedded",
      brand.kind === "lookalike" ? 30 : 25,
      `Imitates ${brand.brand}`,
      `${host} is not a ${brand.brand} domain (real: ${brand.legit}).`,
    );
  }
  if (u.protocol === "http:") flag("url.http", 4, "Unencrypted HTTP link", "The link does not use TLS.");
  if (link.href.length > 300) flag("url.long", 4, "Very long URL", "Long URLs are used to hide the real host or carry tracking tokens.");

  // anchor text claims one domain, href goes to another
  const shown = /\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i.exec(link.text.replace(/^https?:\/\//i, ""));
  if (shown) {
    const claimed = shown[1]!.toLowerCase();
    if (registeredDomain(claimed) !== registeredDomain(host)) {
      flag("url.mismatch", 30, "Link text does not match destination", `Shows "${claimed}" but goes to ${host}.`);
    }
  }
  return { href: link.href.length > 200 ? link.href.slice(0, 200) + "..." : link.href, host, text: link.text.slice(0, 120), flags };
}
