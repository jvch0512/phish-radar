// Domain helpers: registered domain, Levenshtein, homograph detection, brand list.

const MULTI = new Set(["co.uk", "org.uk", "ac.uk", "gov.uk", "com.br", "com.ar", "com.mx", "com.es", "com.au", "co.jp", "co.in", "com.cn", "com.tr", "co.za", "com.pt", "net.br", "org.br"]);

export function registeredDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");
  const last2 = labels.slice(-2).join(".");
  return MULTI.has(last2) ? labels.slice(-3).join(".") : last2;
}

export function subdomainLabels(host: string): string[] {
  const reg = registeredDomain(host);
  const h = host.toLowerCase();
  return h.length > reg.length ? h.slice(0, h.length - reg.length - 1).split(".") : [];
}

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0]!;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j]!;
      prev[j] = Math.min(prev[j]! + 1, prev[j - 1]! + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length]!;
}

/** Brand label (left of the TLD) mapped to its legitimate registered domains. */
export const BRANDS: Record<string, string[]> = {
  paypal: ["paypal.com"],
  microsoft: ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"],
  google: ["google.com", "gmail.com", "googlemail.com"],
  apple: ["apple.com", "icloud.com"],
  amazon: ["amazon.com", "amazon.es", "amazon.co.uk", "amazonaws.com"],
  netflix: ["netflix.com"],
  facebook: ["facebook.com", "fb.com"],
  instagram: ["instagram.com"],
  linkedin: ["linkedin.com"],
  dropbox: ["dropbox.com"],
  docusign: ["docusign.com", "docusign.net"],
  santander: ["santander.com", "santander.es", "santander.com.br"],
  bbva: ["bbva.com", "bbva.es"],
  caixabank: ["caixabank.es", "caixabank.com"],
  correos: ["correos.es"],
  dhl: ["dhl.com", "dhl.de"],
  fedex: ["fedex.com"],
  github: ["github.com"],
  binance: ["binance.com"],
  coinbase: ["coinbase.com"],
};

const LEET: Record<string, string> = { "0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a", "$": "s" };

export function deLeet(s: string): string {
  return s.replace(/rn/g, "m").replace(/vv/g, "w").replace(/[013457$]/g, (c) => LEET[c] ?? c);
}

const BAIT = /(login|log-in|signin|sign-in|secure|security|support|verify|verification|account|update|billing|helpdesk|help|service|pay|wallet|confirm|alert|recover|unlock|online)/;

export interface BrandHit {
  brand: string;
  kind: "lookalike" | "embedded";
  legit: string;
}

/** Detects a domain that imitates a known brand without being one of its real domains. */
export function brandImitation(host: string): BrandHit | null {
  const reg = registeredDomain(host);
  const label = reg.split(".")[0] ?? "";
  for (const [brand, legit] of Object.entries(BRANDS)) {
    if (legit.includes(reg)) return null;
  }
  for (const [brand, legit] of Object.entries(BRANDS)) {
    const l = deLeet(label);
    if (label !== brand && (levenshtein(l, brand) <= (brand.length >= 7 ? 2 : 1) && Math.abs(l.length - brand.length) <= 2 && l.length >= 4)) {
      return { brand, kind: "lookalike", legit: legit[0]! };
    }
    if (label.includes(brand) && label !== brand && BAIT.test(label)) {
      return { brand, kind: "embedded", legit: legit[0]! };
    }
    if (subdomainLabels(host).some((s) => s === brand || s.includes(brand))) {
      return { brand, kind: "embedded", legit: legit[0]! };
    }
  }
  return null;
}

/** Non-ASCII letters mixed with ASCII in one label, or any label that decodes from punycode. */
export function homographRisk(hostname: string): { punycode: boolean; mixedScript: boolean } {
  const labels = hostname.split(".");
  const punycode = labels.some((l) => l.toLowerCase().startsWith("xn--"));
  const mixedScript = labels.some((l) => /[^\x00-\x7f]/.test(l) && /[a-z]/i.test(l));
  return { punycode, mixedScript };
}

export const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "lnkd.in"]);
export const RISKY_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "rest", "icu", "cam", "bond"]);
