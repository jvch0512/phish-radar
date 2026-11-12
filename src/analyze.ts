import { parseEml, header, headersAll, Header, ParsedEmail } from "./eml.js";
import { AuthSummary, aligned, domainOf, parseAuthResults, parseMailbox } from "./auth.js";
import { analyzeUrl, extractLinks, UrlInfo } from "./urls.js";
import { analyzeAttachment } from "./attachments.js";
import { BRANDS, levenshtein, registeredDomain } from "./domain.js";
import { detectInjection } from "./ai.js";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Verdict = "clean" | "suspicious" | "phishing";

export interface Finding {
  id: string;
  category: "authentication" | "sender" | "url" | "attachment" | "content" | "structure";
  severity: Severity;
  points: number;
  title: string;
  detail: string;
}

export interface Report {
  score: number;
  verdict: Verdict;
  from: string;
  subject: string;
  date: string;
  auth: AuthSummary;
  hops: number;
  findings: Finding[];
  urls: UrlInfo[];
  attachments: { filename: string; contentType: string; size: number; sha256: string }[];
  warnings: string[];
  excerpt: string;
}

export const SUSPICIOUS_AT = 25;
export const PHISHING_AT = 55;

export function severityOf(points: number): Severity {
  return points >= 30 ? "critical" : points >= 20 ? "high" : points >= 10 ? "medium" : points > 0 ? "low" : "info";
}

export function verdictOf(score: number): Verdict {
  return score >= PHISHING_AT ? "phishing" : score >= SUSPICIOUS_AT ? "suspicious" : "clean";
}

interface Rule {
  id: string;
  points: number;
  title: string;
  re: RegExp;
}

// English, Spanish and Portuguese, the languages this portfolio's author works in.
const CONTENT_RULES: Rule[] = [
  { id: "content.urgency", points: 10, title: "Urgency or threat language", re: /\b(urgent|immediately|within 24 hours|account (?:will be )?(?:suspended|locked|closed)|final (?:notice|warning)|act now|last chance|urgente|inmediatamente|en las pr[oó]ximas 24 horas|cuenta (?:ser[aá] )?(?:suspendida|bloqueada|cancelada)|[uú]ltimo aviso|imediatamente|sua conta ser[aá] (?:suspensa|bloqueada)|[uú]ltimo aviso)\b/i },
  { id: "content.credentials", points: 14, title: "Asks for credentials or verification", re: /\b(verify your (?:account|identity|password)|confirm your (?:password|identity|account)|update your (?:payment|billing|account)|log ?in to (?:verify|confirm|restore)|enter your (?:password|pin|card)|verifica tu (?:cuenta|identidad)|confirma tu (?:contrase[ñn]a|identidad)|actualiza tus datos|verifique sua conta|confirme sua senha)\b/i },
  { id: "content.money", points: 10, title: "Payment, gift card or wire request", re: /\b(wire transfer|gift cards?|bitcoin|cryptocurrency wallet|unpaid invoice|overdue payment|transferencia bancaria|tarjetas? regalo|factura pendiente|pagamento pendente|boleto vencido)\b/i },
  { id: "content.prize", points: 10, title: "Prize or windfall bait", re: /\b(you(?:'ve| have) won|claim your (?:prize|reward|refund)|lottery|inheritance|has ganado|reclama tu premio|voc[eê] ganhou)\b/i },
  { id: "content.secrecy", points: 8, title: "Pressure to keep it secret or bypass process", re: /\b(do not (?:tell|share|discuss)|keep this (?:confidential|between us)|don't call|no se lo digas|mant[eé]n esto en secreto|n[aã]o conte a ningu[eé]m)\b/i },
  { id: "content.generic", points: 4, title: "Generic greeting", re: /\b(dear (?:customer|user|client|member)|estimado (?:cliente|usuario)|caro (?:cliente|usu[aá]rio))\b/i },
];

const FREEMAIL = new Set(["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "yahoo.es", "proton.me", "protonmail.com", "icloud.com", "gmx.com", "aol.com", "live.com", "mail.com"]);

function addressInHeader(hs: Header[], name: string) {
  return parseMailbox(header(hs, name));
}

export function analyzeParsed(email: ParsedEmail): Report {
  const hs = email.headers;
  const findings: Finding[] = [];
  const add = (category: Finding["category"], id: string, points: number, title: string, detail: string) =>
    findings.push({ id, category, points, severity: severityOf(points), title, detail });

  const from = addressInHeader(hs, "from");
  const replyTo = addressInHeader(hs, "reply-to");
  const returnPath = addressInHeader(hs, "return-path");
  const subject = header(hs, "subject") ?? "";
  const auth = parseAuthResults(hs);

  // 1. authentication
  if (auth.spf === "missing" && auth.dkim === "missing" && auth.dmarc === "missing") {
    add("authentication", "auth.none", 6, "No authentication results", "No Authentication-Results or Received-SPF header, so the receiving server did not record SPF, DKIM or DMARC checks.");
  } else {
    if (auth.spf === "fail") add("authentication", "auth.spf-fail", 18, "SPF failed", `The sending IP is not authorized for ${auth.spfDomain ?? "the envelope domain"}.`);
    else if (auth.spf === "softfail") add("authentication", "auth.spf-softfail", 10, "SPF softfail", "The domain owner flagged this sender as probably unauthorized.");
    else if (auth.spf === "none" || auth.spf === "permerror") add("authentication", "auth.spf-none", 5, `SPF ${auth.spf}`, "The sending domain publishes no usable SPF policy.");
    if (auth.dkim === "fail") add("authentication", "auth.dkim-fail", 18, "DKIM signature invalid", "The message was altered after signing or the signature is forged.");
    else if (auth.dkim === "none" || auth.dkim === "missing") add("authentication", "auth.dkim-none", 5, "No DKIM signature", "The message is not cryptographically signed by the sender domain.");
    if (auth.dmarc === "fail") add("authentication", "auth.dmarc-fail", 25, "DMARC failed", `Neither SPF nor DKIM aligned with the visible From domain${auth.dmarcPolicy ? " (policy p=" + auth.dmarcPolicy + ")" : ""}.`);
    else if (auth.dmarc === "none" || auth.dmarc === "missing") add("authentication", "auth.dmarc-none", 5, "No DMARC result", "The From domain has no enforced DMARC policy for this message.");
  }
  if (from) {
    if (auth.spf === "pass" && auth.spfDomain && !aligned(auth.spfDomain, from.domain)) {
      add("authentication", "auth.spf-align", 12, "SPF passes for a different domain", `SPF validated ${auth.spfDomain}, but the visible sender is ${from.domain}. Attackers pass SPF with their own domain.`);
    }
    if (auth.dkim === "pass" && auth.dkimDomain && !aligned(auth.dkimDomain, from.domain)) {
      add("authentication", "auth.dkim-align", 12, "DKIM signed by a different domain", `Signature d=${auth.dkimDomain} does not align with ${from.domain}.`);
    }
  }

  // 2. sender
  if (!from) add("sender", "sender.no-from", 15, "Missing or invalid From address", "The From header is absent or unparseable.");
  if (from) {
    const nameMail = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/.exec(from.name);
    if (nameMail && domainOf(nameMail[0]) !== from.domain) {
      add("sender", "sender.name-address", 25, "Display name contains a different email address", `Shows "${nameMail[0]}" but the real sender is ${from.address}.`);
    }
    const lname = from.name.toLowerCase().replace(/[^a-z0-9]/g, "");
    for (const [brand, legit] of Object.entries(BRANDS)) {
      if (lname.includes(brand) && !legit.some((d) => registeredDomain(from.domain) === d)) {
        add("sender", "sender.brand-name", 22, `Display name claims ${brand}`, `"${from.name}" is sent from ${from.domain}, which is not a ${brand} domain.`);
        break;
      }
    }
    if (FREEMAIL.has(from.domain) && /\b(ceo|cfo|coo|cto|director|presidente|president|chairman|gerente|diretor)\b/i.test(from.name)) {
      add("sender", "sender.freemail-exec", 22, "Executive title sent from a free mailbox", `"${from.name}" writes from ${from.domain}, a classic CEO fraud pattern.`);
    }
    if (replyTo && !aligned(replyTo.domain, from.domain)) {
      add("sender", "sender.reply-to", 15, "Reply-To differs from From", `Replies go to ${replyTo.address}, not to ${from.domain}.`);
    }
    if (returnPath && !aligned(returnPath.domain, from.domain)) {
      add("sender", "sender.return-path", 6, "Return-Path domain differs from From", `Envelope sender ${returnPath.address} is on another domain.`);
    }
    const label = registeredDomain(from.domain).split(".")[0] ?? "";
    for (const [brand, legit] of Object.entries(BRANDS)) {
      if (!legit.includes(registeredDomain(from.domain)) && label !== brand && levenshtein(label, brand) === 1 && label.length >= 5) {
        add("sender", "sender.lookalike", 25, `Sender domain imitates ${brand}`, `${from.domain} is one character away from ${brand}.`);
        break;
      }
    }
  }
  const msgId = header(hs, "message-id");
  if (!msgId) add("structure", "struct.no-msgid", 4, "No Message-ID", "Legitimate mail servers always add a Message-ID.");
  else if (from && msgId.includes("@") && !aligned(domainOf(msgId), from.domain) && /^<[a-f0-9-]{20,}@/.test(msgId) === false) {
    // many providers use their own domain here, so this stays informational
  }
  const hops = headersAll(hs, "received").length;
  if (hops === 0) add("structure", "struct.no-received", 6, "No Received headers", "No relay trace is present, which suggests the message was fabricated or stripped.");
  const date = header(hs, "date");
  if (!date || Number.isNaN(Date.parse(date))) add("structure", "struct.date", 4, "Missing or invalid Date", date ? `Unparseable date: ${date}` : "No Date header.");
  if (header(hs, "x-mailer")?.match(/phpmailer|swiftmailer|mass ?mail|bulk/i)) add("structure", "struct.mailer", 4, "Bulk or scripted mailer", `X-Mailer: ${header(hs, "x-mailer")}`);

  // 3. urls
  const links = extractLinks(email.text, email.html);
  const urls: UrlInfo[] = [];
  for (const l of links) {
    const info = analyzeUrl(l);
    if (info) urls.push(info);
  }
  const perFlag = new Map<string, { points: number; title: string; hosts: Set<string>; detail: string }>();
  for (const u of urls) {
    for (const f of u.flags) {
      const e = perFlag.get(f.id) ?? { points: f.points, title: f.title, hosts: new Set<string>(), detail: f.detail };
      e.hosts.add(u.host);
      perFlag.set(f.id, e);
    }
  }
  for (const [id, e] of perFlag) {
    const extra = e.hosts.size > 1 ? ` (${e.hosts.size} links)` : "";
    add("url", id, e.points, e.title + extra, e.detail);
  }

  // 4. attachments
  const attReports = email.attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, size: a.size, sha256: a.sha256 }));
  for (const a of email.attachments) {
    for (const f of analyzeAttachment(a)) add("attachment", f.id, f.points, f.title, f.detail);
  }

  // 5. content
  const body = subject + "\n" + email.text;
  for (const r of CONTENT_RULES) {
    const m = r.re.exec(body);
    if (m) add("content", r.id, r.points, r.title, `Matched: "${m[0].slice(0, 60)}"`);
  }
  const inj = detectInjection(body);
  if (inj) add("content", "content.llm-injection", 15, "Prompt injection aimed at AI scanners", `The message tries to instruct an AI reviewer: "${inj}".`);
  if (email.html && !email.text.trim()) add("content", "content.empty-text", 3, "HTML only, no readable text", "Image-only messages evade text filters.");
  if (/<form\b/i.test(email.html)) add("content", "content.form", 25, "HTML form inside the email", "Forms in email bodies are used to harvest credentials directly.");
  if (/<(?:img)[^>]+(?:width|height)\s*=\s*["']?1["']?[^>]*>/i.test(email.html)) add("content", "content.pixel", 3, "Tracking pixel", "A 1x1 image reports when the message was opened.");

  // score: diminishing returns so many small signals cannot outweigh one decisive one
  const sorted = [...findings].sort((a, b) => b.points - a.points);
  let score = 0;
  sorted.forEach((f, i) => {
    score += f.points * Math.pow(0.85, i);
  });
  // strong, independent evidence classes reinforce each other
  const cats = new Set(findings.filter((f) => f.points >= 10).map((f) => f.category));
  if (cats.size >= 3) score += 10;
  if (findings.some((f) => f.id === "auth.dmarc-fail") && findings.some((f) => f.category === "url" && f.points >= 20)) score += 10;
  score = Math.min(100, Math.round(score));

  const text = email.text.replace(/\s+/g, " ").trim();
  return {
    score,
    verdict: verdictOf(score),
    from: from ? (from.name ? `${from.name} <${from.address}>` : from.address) : header(hs, "from") ?? "",
    subject,
    date: date ?? "",
    auth,
    hops,
    findings: sorted,
    urls,
    attachments: attReports,
    warnings: email.warnings,
    excerpt: text.slice(0, 1500),
  };
}

export function analyzeEml(input: Buffer | string): Report {
  return analyzeParsed(parseEml(input));
}
