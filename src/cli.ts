#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { analyzeEml } from "./analyze.js";
import { askClaude, combine } from "./ai.js";

const args = process.argv.slice(2);
const json = args.includes("--json");
const noAi = args.includes("--no-ai");
const files = args.filter((a) => !a.startsWith("--"));
if (files.length === 0) {
  console.error("usage: phish-radar [--json] [--no-ai] <file.eml> [...]\nexit code: 0 clean, 1 suspicious, 2 phishing, 3 error");
  process.exit(3);
}

const colors: Record<string, string> = { clean: "\x1b[32m", suspicious: "\x1b[33m", phishing: "\x1b[31m" };
let worst = 0;
for (const f of files) {
  try {
    const report = analyzeEml(readFileSync(f));
    const apiKey = process.env["ANTHROPIC_API_KEY"];
    const ai = noAi ? null : await askClaude(report, apiKey ? { apiKey } : {});
    const final = ai ? combine(report, ai) : { verdict: report.verdict, raisedByAi: false };
    worst = Math.max(worst, final.verdict === "phishing" ? 2 : final.verdict === "suspicious" ? 1 : 0);
    if (json) {
      console.log(JSON.stringify({ file: f, report, ai, final }));
      continue;
    }
    const c = colors[final.verdict] ?? "";
    console.log(`\n${f}\n  From:    ${report.from}\n  Subject: ${report.subject}`);
    console.log(`  Auth:    SPF=${report.auth.spf} DKIM=${report.auth.dkim} DMARC=${report.auth.dmarc}`);
    console.log(`  Verdict: ${c}${final.verdict.toUpperCase()}\x1b[0m  score ${report.score}/100${final.raisedByAi ? "  (raised by AI)" : ""}`);
    for (const x of report.findings.slice(0, 8)) console.log(`    [${x.severity.padEnd(8)}] +${String(x.points).padStart(2)} ${x.title}`);
    if (ai) console.log(`  AI (${ai.source}): ${ai.tactic}${ai.note ? "  - " + ai.note : ""}`);
  } catch (e) {
    console.error(`${f}: ${e instanceof Error ? e.message : "error"}`);
    worst = 3;
  }
}
process.exit(worst);
