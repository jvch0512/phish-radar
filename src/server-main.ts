import { createServer } from "./server.js";

const host = "127.0.0.1"; // loopback only: the app parses hostile files, never expose it
const port = Number(process.env["PORT"] ?? 8300);
const apiKey = process.env["ANTHROPIC_API_KEY"];
const server = createServer({ ai: apiKey ? { apiKey } : {} });
server.listen(port, host, () => {
  console.log(`Phish Radar on http://${host}:${port}  (Claude review: ${apiKey ? "on" : "off, offline heuristic"})`);
});
