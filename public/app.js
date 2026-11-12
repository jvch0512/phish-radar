// All rendering uses textContent and createElement. Only textContent and createElement are used, because the data comes from hostile emails.
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
const NS = "http://www.w3.org/2000/svg";

function gauge(score, verdict) {
  const svg = $("gauge"); clear(svg);
  const col = { clean: "#35d07f", suspicious: "#f5b942", phishing: "#ff5d6c" }[verdict];
  const mk = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); return e; };
  const r = 50, c = 2 * Math.PI * r;
  svg.append(mk("circle", { cx: 60, cy: 60, r, fill: "none", stroke: "#22305a", "stroke-width": 10 }));
  svg.append(mk("circle", { cx: 60, cy: 60, r, fill: "none", stroke: col, "stroke-width": 10, "stroke-linecap": "round", "stroke-dasharray": `${(c * score) / 100} ${c}`, transform: "rotate(-90 60 60)" }));
  const t = mk("text", { x: 60, y: 66, "text-anchor": "middle", "font-size": 30, "font-weight": 800, fill: col }); t.textContent = String(score);
  const s = mk("text", { x: 60, y: 84, "text-anchor": "middle", "font-size": 9, fill: "#8b97c4" }); s.textContent = "RISK / 100";
  svg.append(t, s);
}

function render(data) {
  const { report: r, ai, final } = data;
  $("result").hidden = false; $("error").hidden = true;
  gauge(r.score, final.verdict);
  const v = $("verdict"); v.textContent = final.verdict.toUpperCase(); v.className = "verdict " + final.verdict;
  if (final.raisedByAi) v.append(el("span", "raised", "  raised by AI"));
  $("from").textContent = "From: " + r.from;
  $("subject").textContent = r.subject || "(no subject)";
  const a = $("auth"); clear(a);
  for (const k of ["spf", "dkim", "dmarc"]) a.append(el("span", "pill " + r.auth[k], k.toUpperCase() + " " + r.auth[k]));
  $("fcount").textContent = `(${r.findings.length})`;
  const fl = $("findings"); clear(fl);
  if (!r.findings.length) fl.append(el("li", "", "No indicators found."));
  for (const f of r.findings) {
    const li = el("li", f.severity);
    li.append(el("span", "pts", "+" + f.points), el("div", "t", f.title), el("div", "d", f.detail));
    fl.append(li);
  }
  const ac = $("ai"); clear(ac); ac.className = "ai";
  if (ai) {
    ac.append(el("div", "tactic", `${ai.source === "claude" ? "Claude" : "Offline heuristic"}: ${ai.verdict}, ${ai.tactic || "no tactic"}`));
    ac.append(el("div", "line", `confidence ${Math.round(ai.confidence * 100)}%`));
    if (ai.reasons.length) { const ul = el("ul"); for (const x of ai.reasons) ul.append(el("li", "", x)); ac.append(ul); }
    if (ai.note) ac.append(el("div", "line", ai.note));
  } else ac.append(el("div", "line", "Disabled for this run."));
  const u = $("urls"); clear(u);
  if (!r.urls.length) u.append(el("div", "line", "No links."));
  for (const x of r.urls) {
    const row = el("div", "urlrow"); row.append(el("div", "h", x.host));
    if (x.text) row.append(el("div", "line", `shown as: ${x.text}`));
    for (const f of x.flags) row.append(el("span", "tag", f.title));
    u.append(row);
  }
  const t = $("atts"); clear(t);
  if (!r.attachments.length) t.append(el("div", "line", "None."));
  for (const x of r.attachments) {
    const row = el("div", "urlrow"); row.append(el("div", "h", x.filename), el("div", "line", `${x.contentType} · ${x.size} bytes · sha256 ${x.sha256.slice(0, 16)}...`));
    t.append(row);
  }
}

async function analyze(buf) {
  try {
    const res = await fetch("/api/analyze" + ($("useai").checked ? "" : "?ai=0"), { method: "POST", body: buf });
    if (!res.ok) throw new Error((await res.json()).error || "HTTP " + res.status);
    render(await res.json());
  } catch (e) { const err = $("error"); err.hidden = false; err.textContent = "Analysis failed: " + e.message; }
}

const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", async (e) => { e.preventDefault(); drop.classList.remove("over"); const f = e.dataTransfer.files[0]; if (f) analyze(await f.arrayBuffer()); });
$("file").addEventListener("change", async (e) => { const f = e.target.files[0]; if (f) analyze(await f.arrayBuffer()); });

fetch("/api/samples").then((r) => r.json()).then((d) => {
  const ai = $("ai-status"); ai.textContent = d.aiConfigured ? "AI: Claude" : "AI: offline heuristic"; if (d.aiConfigured) ai.classList.add("on");
  for (const name of d.samples) {
    const b = el("button", "s", name.replace(/\.eml$/, "")); b.type = "button";
    b.addEventListener("click", async () => analyze(await (await fetch("/api/samples/" + name)).arrayBuffer()));
    $("samples").append(b);
  }
});
