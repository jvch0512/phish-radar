import http from "node:http";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { analyzeEml } from "./analyze.js";
import { askClaude, combine, AiOptions } from "./ai.js";
import { MAX_MESSAGE_BYTES } from "./eml.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const TYPES: Record<string, string> = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };

function headers(extra: Record<string, string> = {}): Record<string, string> {
  return { "content-security-policy": CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer", "cache-control": "no-store", ...extra };
}

function json(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, headers({ "content-type": "application/json; charset=utf-8" }));
  res.end(JSON.stringify(body));
}

function readBody(req: http.IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let n = 0;
    req.on("data", (c: Buffer) => {
      n += c.length;
      if (n > limit) {
        reject(new Error("too large"));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export interface ServerOptions {
  ai: AiOptions;
  publicDir?: string;
  samplesDir?: string;
}

export function createServer(opts: ServerOptions): http.Server {
  const publicDir = opts.publicDir ?? path.join(ROOT, "public");
  const samplesDir = opts.samplesDir ?? path.join(ROOT, "samples");
  const samples = (): string[] => {
    try {
      return readdirSync(samplesDir).filter((f) => f.endsWith(".eml")).sort();
    } catch {
      return [];
    }
  };

  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "GET" && url.pathname === "/api/samples") return json(res, 200, { samples: samples(), aiConfigured: !!opts.ai.apiKey });
      const sm = /^\/api\/samples\/([\w.-]+\.eml)$/.exec(url.pathname);
      if (req.method === "GET" && sm) {
        if (!samples().includes(sm[1]!)) return json(res, 404, { error: "unknown sample" });
        res.writeHead(200, headers({ "content-type": "message/rfc822" }));
        return void res.end(readFileSync(path.join(samplesDir, sm[1]!)));
      }
      if (req.method === "POST" && url.pathname === "/api/analyze") {
        let body: Buffer;
        try {
          body = await readBody(req, MAX_MESSAGE_BYTES);
        } catch {
          return json(res, 413, { error: "message too large" });
        }
        if (body.length === 0) return json(res, 400, { error: "empty body" });
        const report = analyzeEml(body);
        const useAi = url.searchParams.get("ai") !== "0";
        const ai = useAi ? await askClaude(report, opts.ai) : null;
        const final = ai ? combine(report, ai) : { verdict: report.verdict, raisedByAi: false };
        return json(res, 200, { report, ai, final });
      }
      if (req.method === "GET") {
        const name = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
        if (!/^[\w.-]+$/.test(name) || !TYPES[path.extname(name)]) return json(res, 404, { error: "not found" });
        try {
          const data = readFileSync(path.join(publicDir, name));
          res.writeHead(200, headers({ "content-type": TYPES[path.extname(name)]! }));
          return void res.end(data);
        } catch {
          return json(res, 404, { error: "not found" });
        }
      }
      json(res, 405, { error: "method not allowed" });
    } catch {
      json(res, 500, { error: "internal error" });
    }
  });
}
