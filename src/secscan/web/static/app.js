"use strict";
// secscan dashboard. All scan data comes from scanned hosts and is untrusted:
// it is only ever inserted as text (never innerHTML).

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const app = document.getElementById("app");
let pollTimer = null;
let checksCache = null;
let findingFilter = "all";

// ---------- helpers ----------
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  append(el, children);
  return el;
}
function s(tag, attrs, ...children) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : String(c));
  }
}

async function api(path, options = {}) {
  const res = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") msg = body.detail;
      else if (Array.isArray(body.detail) && body.detail[0]) msg = body.detail[0].msg;
    } catch (_) { /* not JSON */ }
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

async function loadChecks() {
  if (!checksCache) checksCache = await api("/api/checks");
  return checksCache;
}
function checkTitle(name) {
  const c = (checksCache || []).find((x) => x.name === name);
  return c ? c.title : name;
}

function fmtDate(iso) {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
function fmtDuration(a, b) {
  if (!a || !b) return null;
  const secs = (new Date(b) - new Date(a)) / 1000;
  return secs < 60 ? `${secs.toFixed(1)}s` : `${Math.floor(secs / 60)}m ${Math.round(secs % 60)}s`;
}
function isActive(scan) { return scan.status === "queued" || scan.status === "running"; }
function plural(n, word) { return `${n} ${word}${n === 1 ? "" : "s"}`; }

function toast(message) {
  const t = h("div", { class: "toast", role: "status" }, message);
  document.body.append(t);
  setTimeout(() => t.remove(), 3500);
}

function sevBadge(sev) { return h("span", { class: `sev sev-${sev}` }, sev); }
function gradeBadge(grade, small) {
  if (!grade) return h("span", { class: "muted" }, "—");
  return h("span", { class: `grade g-${grade}${small ? " sm" : ""}`, title: `Grade ${grade}` }, grade);
}
function countChips(counts) {
  if (!counts) return h("span", { class: "muted" }, "—");
  const chips = SEVERITIES.filter((sv) => counts[sv]).map((sv) =>
    h("span", { class: `sev sev-${sv}`, title: `${counts[sv]} ${sv}` }, `${counts[sv]} ${sv}`));
  return chips.length ? h("span", { class: "counts" }, chips) : h("span", { class: "sev sev-info" }, "clean");
}
function statusLabel(status) { return h("span", { class: `status ${status}` }, status); }

// ---------- routing ----------
function route() {
  clearTimeout(pollTimer);
  const m = location.hash.match(/^#\/scans\/(\d+)/);
  if (m) renderScan(Number(m[1]));
  else renderDashboard();
}
window.addEventListener("hashchange", route);
document.addEventListener("DOMContentLoaded", route);

// ---------- dashboard ----------
async function renderDashboard() {
  const data = h("div", { id: "dash-data" });
  app.replaceChildren(h("p", { class: "muted" }, "Loading…"));
  try {
    const checks = await loadChecks();
    app.replaceChildren(newScanCard(checks), data);
    await refreshDashboard();
  } catch (e) {
    app.replaceChildren(h("div", { class: "card error-text" }, `Could not load the dashboard: ${e.message}`));
  }
}

async function refreshDashboard() {
  const data = document.getElementById("dash-data");
  if (!data) return;
  const scans = await api("/api/scans");
  data.replaceChildren();
  append(data, [statsRow(scans), targetsSection(scans), historySection(scans)]);
  if (scans.some(isActive)) {
    pollTimer = setTimeout(() => refreshDashboard().catch(() => {}), 2000);
  }
}

function newScanCard(checks) {
  const input = h("input", {
    type: "text", name: "target", required: true, autocomplete: "off", spellcheck: "false",
    placeholder: "example.com, 192.168.1.10 or https://site.example", "aria-label": "Target",
  });
  const consent = h("input", { type: "checkbox", id: "consent" });
  const error = h("p", { class: "form-error", role: "alert" });
  const button = h("button", { class: "btn primary", type: "submit" }, "Start scan");
  const ports = h("input", {
    type: "text", name: "ports", autocomplete: "off", spellcheck: "false", class: "ports-input",
    placeholder: "common (default) · e.g. 1-1024 or 22,80,8000-8100", "aria-label": "Ports to scan",
  });
  const toggles = checks.map((c) =>
    h("label", { class: "chip-toggle" },
      h("input", { type: "checkbox", name: "check", value: c.name, checked: true }),
      h("span", {}, c.title)));

  const form = h("form", { class: "scan-form", novalidate: true },
    h("div", { class: "row" }, input, button),
    h("div", { class: "chips" }, h("span", { class: "muted" }, "Checks:"), toggles),
    h("label", { class: "ports-row" }, h("span", { class: "muted" }, "Ports:"), ports),
    h("label", { class: "consent", for: "consent" }, consent,
      h("span", {}, "I own this target or have written permission from its owner to scan it.")),
    error);

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    error.textContent = "";
    const target = input.value.trim();
    const selected = [...form.querySelectorAll("input[name=check]:checked")].map((x) => x.value);
    if (!target) { error.textContent = "Enter a hostname, IP address or URL."; input.focus(); return; }
    if (!selected.length) { error.textContent = "Select at least one check."; return; }
    if (!consent.checked) { error.textContent = "Confirm that you are authorized to scan this target."; return; }
    button.disabled = true;
    try {
      const { id } = await api("/api/scans", {
        method: "POST",
        body: JSON.stringify({ target, checks: selected, ports: ports.value.trim() || null, authorized: true }),
      });
      location.hash = `#/scans/${id}`;
    } catch (e) {
      error.textContent = e.message;
    } finally {
      button.disabled = false;
    }
  });

  return h("section", { class: "card" }, h("h1", {}, "New scan"),
    h("p", { class: "muted" }, "Checks exposed services, the TLS certificate and HTTP security headers."),
    form);
}

function latestPerTarget(scans) {
  const byTarget = new Map();
  for (const scan of scans) { // newest first
    if (!byTarget.has(scan.target)) byTarget.set(scan.target, []);
    byTarget.get(scan.target).push(scan);
  }
  return [...byTarget.entries()].map(([target, list]) => ({
    target, scans: list, latest: list.find((x) => x.status === "done") || null, newest: list[0],
  }));
}

function statsRow(scans) {
  const targets = latestPerTarget(scans);
  const scored = targets.filter((t) => t.latest);
  const avg = scored.length ? Math.round(scored.reduce((a, t) => a + t.latest.score, 0) / scored.length) : null;
  const serious = scored.reduce((a, t) => a + (t.latest.counts.critical || 0) + (t.latest.counts.high || 0), 0);
  const stat = (label, value, hint) => h("div", { class: "card stat" },
    h("div", { class: "label" }, label), h("div", { class: "value" }, value),
    hint ? h("div", { class: "muted" }, hint) : null);
  return h("section", { class: "grid grid-4" },
    stat("Targets", targets.length),
    stat("Scans run", scans.length),
    stat("Average score", avg === null ? "—" : avg, "latest scan per target"),
    stat("High & critical", serious, "open in latest scans"));
}

function sparkline(values) {
  const w = 96, hgt = 30, pad = 3;
  const svg = s("svg", { class: "spark", viewBox: `0 0 ${w} ${hgt}`, "aria-hidden": "true" });
  if (values.length < 2) return svg;
  const step = (w - pad * 2) / (values.length - 1);
  const pts = values.map((v, i) => [pad + i * step, pad + (hgt - pad * 2) * (1 - v / 100)]);
  svg.append(s("polyline", { points: pts.map((p) => p.join(",")).join(" ") }));
  const last = pts[pts.length - 1];
  svg.append(s("circle", { cx: last[0], cy: last[1], r: 2.6 }));
  return svg;
}

function targetsSection(scans) {
  const targets = latestPerTarget(scans);
  if (!targets.length) return null;
  const cards = targets.map((t) => {
    const shown = t.latest || t.newest;
    const history = t.scans.filter((x) => x.status === "done").slice(0, 10).reverse().map((x) => x.score);
    return h("a", { class: "card target-card", href: `#/scans/${shown.id}` },
      h("div", { class: "head" },
        gradeBadge(t.latest && t.latest.grade),
        h("div", {},
          h("div", { class: "name", title: t.target }, t.target),
          h("div", { class: "sub" },
            t.latest ? `Score ${t.latest.score} · ${fmtDate(t.latest.finished_at)}` : statusText(t.newest)))),
      h("div", { class: "foot-row" }, t.latest ? countChips(t.latest.counts) : statusLabel(t.newest.status),
        sparkline(history)));
  });
  return [h("h2", {}, "Targets"), h("section", { class: "grid grid-targets" }, cards)];
}
function statusText(scan) { return scan.status === "failed" ? "Last scan failed" : "Scan in progress"; }

function historySection(scans) {
  const title = h("h2", {}, "Scan history");
  if (!scans.length) {
    return [title, h("div", { class: "card empty" }, h("strong", {}, "No scans yet"),
      "Start your first scan above, for example against a machine in your own lab.")];
  }
  const rows = scans.map((scan) => {
    const go = () => { location.hash = `#/scans/${scan.id}`; };
    return h("tr", { class: "clickable", onclick: go },
      h("td", { class: "num muted" }, `#${scan.id}`),
      h("td", {}, h("a", { href: `#/scans/${scan.id}`, onclick: (e) => e.stopPropagation() }, scan.input)),
      h("td", {}, statusLabel(scan.status)),
      h("td", { class: "num" }, scan.score === null ? "—" : h("span", { class: "counts" }, gradeBadge(scan.grade, true), ` ${scan.score}`)),
      h("td", {}, scan.status === "done" ? countChips(scan.counts) : (scan.error ? h("span", { class: "error-text" }, scan.error) : "—")),
      h("td", { class: "muted" }, fmtDate(scan.created_at)));
  });
  return [title, h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["#", "Target", "Status", "Score", "Findings", "Started"].map((x) => h("th", { scope: "col" }, x)))),
    h("tbody", {}, rows)))];
}

// ---------- scan detail ----------
async function renderScan(id) {
  let scan;
  try {
    await loadChecks();
    scan = await api(`/api/scans/${id}`);
  } catch (e) {
    app.replaceChildren(h("a", { class: "back", href: "#/" }, "← All scans"),
      h("div", { class: "card error-text" }, e.message));
    return;
  }
  if (location.hash !== `#/scans/${id}`) return; // user navigated away meanwhile
  const openIds = new Set([...app.querySelectorAll("details.finding[open]")].map((d) => d.dataset.id));
  app.replaceChildren(scanView(scan));
  app.querySelectorAll("details.finding").forEach((d) => { if (openIds.has(d.dataset.id)) d.open = true; });
  if (isActive(scan)) pollTimer = setTimeout(() => renderScan(id), 1000);
}

function scanView(scan) {
  const duration = fmtDuration(scan.started_at, scan.finished_at);
  const portsOpt = (scan.options || {}).ports;
  const meta = [scan.address, fmtDate(scan.created_at), duration && `took ${duration}`, portsOpt && `ports ${portsOpt}`]
    .filter(Boolean).join(" · ");
  const head = h("div", { class: "scan-head" },
    h("div", {}, h("h1", {}, scan.input), h("div", { class: "meta" }, statusLabel(scan.status), " ", meta)),
    scanActions(scan));

  const parts = [h("a", { class: "back", href: "#/" }, "← All scans"), head];
  if (isActive(scan)) parts.push(progressCard(scan));
  else if (scan.status === "failed") parts.push(h("div", { class: "card error-text" }, scan.error || "Scan failed."));
  else parts.push(resultView(scan));
  return h("div", {}, parts);
}

function scanActions(scan) {
  if (isActive(scan)) return null;
  const rescan = h("button", { class: "btn", type: "button" }, "Rescan");
  rescan.addEventListener("click", async () => {
    rescan.disabled = true;
    try {
      const { id } = await api("/api/scans", {
        method: "POST",
        body: JSON.stringify({
          target: scan.input, checks: scan.checks, ports: (scan.options || {}).ports || null, authorized: true,
        }),
      });
      location.hash = `#/scans/${id}`;
    } catch (e) { toast(e.message); rescan.disabled = false; }
  });
  const del = h("button", { class: "btn danger", type: "button" }, "Delete");
  del.addEventListener("click", async () => {
    if (!confirm(`Delete scan #${scan.id} of ${scan.input}?`)) return;
    try { await api(`/api/scans/${scan.id}`, { method: "DELETE" }); location.hash = "#/"; }
    catch (e) { toast(e.message); }
  });
  const exports = scan.status === "done" ? [
    h("a", { class: "btn", href: `/api/scans/${scan.id}/report.html`, target: "_blank", rel: "noopener" }, "HTML report"),
    h("a", { class: "btn", href: `/api/scans/${scan.id}/report.json`, download: `secscan-${scan.id}.json` }, "JSON"),
  ] : [];
  return h("div", { class: "actions" }, exports, rescan, del);
}

function progressCard(scan) {
  const total = scan.checks.length;
  const done = scan.completed.length;
  const bar = h("div");
  bar.style.width = `${Math.max(4, (done / total) * 100)}%`;
  const steps = scan.checks.map((name) => {
    const state = scan.completed.includes(name) ? "done" : scan.current_check === name ? "current" : "pending";
    return h("li", { class: state }, h("span", { class: "dot" }, state === "done" ? "✓" : ""), checkTitle(name));
  });
  return h("section", { class: "card" },
    h("h3", {}, scan.status === "queued" ? "Waiting to start…" : `Scanning… ${done} of ${total} checks done`),
    h("div", { class: "progress", role: "progressbar", "aria-valuemin": 0, "aria-valuemax": total, "aria-valuenow": done }, bar),
    h("ul", { class: "steps" }, steps));
}

function scoreRing(score, grade) {
  const r = 46, c = 2 * Math.PI * r;
  return s("svg", { class: "ring", viewBox: "0 0 112 112", role: "img", "aria-label": `Score ${score} of 100, grade ${grade}` },
    s("circle", { class: "track", cx: 56, cy: 56, r, fill: "none", "stroke-width": 10 }),
    s("circle", {
      class: `stroke-${grade}`, cx: 56, cy: 56, r, fill: "none", "stroke-width": 10, "stroke-linecap": "round",
      "stroke-dasharray": c.toFixed(2), "stroke-dashoffset": (c * (1 - score / 100)).toFixed(2),
      transform: "rotate(-90 56 56)",
    }),
    s("text", { x: 56, y: 60, "text-anchor": "middle", "font-size": 30 }, String(score)),
    s("text", { class: "small", x: 56, y: 78, "text-anchor": "middle" }, "/ 100"));
}

function resultView(scan) {
  const result = scan.result;
  const cmp = scan.comparison;
  const newIds = new Set(cmp ? cmp.new_ids : []);

  const gradeWords = { A: "Excellent", B: "Good", C: "Fair", D: "Poor", F: "Critical" };
  const scoreCard = h("div", { class: "card score-card" }, scoreRing(scan.score, scan.grade),
    h("div", { class: "grade-text" }, "Security grade", h("strong", {}, `${scan.grade} · ${gradeWords[scan.grade]}`),
      plural(result.findings.length, "finding")));

  const tiles = h("div", { class: "sev-tiles" }, SEVERITIES.map((sv) =>
    h("div", { class: `sev-tile sev-${sv}` }, h("span", { class: "n" }, scan.counts[sv] || 0), h("span", { class: "l" }, sv))));

  let compareLine;
  if (cmp) {
    const delta = scan.score - cmp.previous_score;
    compareLine = h("p", { class: "compare" }, "Compared with ",
      h("a", { href: `#/scans/${cmp.previous_id}` }, `scan #${cmp.previous_id}`), ` (${fmtDate(cmp.previous_finished_at)}): score ${cmp.previous_score} → `,
      h("strong", {}, scan.score), " ",
      delta ? h("span", { class: delta > 0 ? "delta-up" : "delta-down" }, `(${delta > 0 ? "+" : ""}${delta})`) : "(no change)",
      ` · ${cmp.new_ids.length} new, ${cmp.fixed.length} fixed.`);
  } else {
    compareLine = h("p", { class: "compare" }, "First completed scan of this target. Rescan later to see what changed.");
  }

  const summary = h("section", { class: "summary" }, scoreCard, h("div", { class: "card" }, tiles, compareLine));

  return h("div", {}, summary,
    findingsSection(result.findings, newIds),
    cmp && cmp.fixed.length ? fixedSection(cmp.fixed) : null,
    h("h2", {}, "Check details"),
    h("div", { class: "stack" }, result.checks.map(checkCard)));
}

function findingsSection(findings, newIds) {
  const list = h("div", { class: "findings" });
  const counts = Object.fromEntries(SEVERITIES.map((sv) => [sv, findings.filter((f) => f.severity === sv).length]));
  if (findingFilter !== "all" && !counts[findingFilter]) findingFilter = "all";

  const filterBtn = (key, label) => {
    const b = h("button", { class: "filter", type: "button", "aria-pressed": String(findingFilter === key) }, label);
    b.addEventListener("click", () => {
      findingFilter = key;
      filters.querySelectorAll(".filter").forEach((x) => x.setAttribute("aria-pressed", String(x === b)));
      fill();
    });
    return b;
  };
  const filters = h("div", { class: "filters", role: "group", "aria-label": "Filter by severity" },
    filterBtn("all", `All ${findings.length}`),
    SEVERITIES.filter((sv) => counts[sv]).map((sv) => filterBtn(sv, `${sv[0].toUpperCase()}${sv.slice(1)} ${counts[sv]}`)));

  const fill = () => {
    const shown = findings.filter((f) => findingFilter === "all" || f.severity === findingFilter);
    list.replaceChildren(...shown.map((f) => findingCard(f, newIds.has(f.id))));
  };
  fill();

  if (!findings.length) {
    return [h("h2", {}, "Findings"), h("div", { class: "card empty" }, h("strong", {}, "No findings"), "None of the checks reported an issue.")];
  }
  return [h("h2", {}, "Findings"), filters, list];
}

function findingCard(f, isNew) {
  return h("details", { class: "finding", "data-id": f.id },
    h("summary", {}, sevBadge(f.severity), h("span", { class: "title" }, f.title), isNew ? h("span", { class: "tag new" }, "NEW") : null),
    h("div", { class: "body" }, h("dl", {},
      f.description ? [h("dt", {}, "Why it matters"), h("dd", {}, f.description)] : null,
      f.evidence ? [h("dt", {}, "Evidence"), h("dd", {}, h("code", { class: "evidence" }, f.evidence))] : null,
      f.recommendation ? [h("dt", {}, "How to fix"), h("dd", {}, f.recommendation)] : null,
      h("dt", {}, "ID"), h("dd", {}, h("code", {}, f.id)))));
}

function fixedSection(fixed) {
  return [h("h2", {}, "Fixed since the previous scan"),
    h("div", { class: "findings fixed-list" }, fixed.map((f) =>
      h("div", { class: "finding" }, h("summary", {}, h("span", { class: "tag fixed" }, "FIXED"), sevBadge(f.severity), h("span", { class: "title" }, f.title)))))];
}

function checkCard(c) {
  const body = [];
  if (c.error) body.push(h("p", { class: "error-text" }, `Check could not complete: ${c.error}`));
  for (const note of c.notes || []) body.push(h("p", { class: "muted" }, note));
  const d = c.data || {};
  if (!c.error && c.check === "ports" && d.open) {
    body.push(h("p", { class: "muted" }, `${d.open.length} open of ${d.scanned} ports checked.`));
    if (d.open.length) {
      body.push(h("table", {}, h("thead", {}, h("tr", {}, ["Port", "Service", "Banner"].map((x) => h("th", {}, x)))),
        h("tbody", {}, d.open.map((p) => h("tr", {}, h("td", { class: "num" }, p.port), h("td", {}, p.service),
          h("td", {}, p.banner ? h("code", {}, p.banner) : "—"))))));
    }
  } else if (!c.error && c.check === "tls" && Array.isArray(d.endpoints)) {
    for (const ep of d.endpoints.filter((e) => e.reachable)) body.push(tlsEndpoint(ep));
  } else if (!c.error && c.check === "headers" && d.url) {
    const present = Object.entries(d.present || {});
    const rows = [["URL", `${d.final_url} (HTTP ${d.status_code})`]];
    if ((d.redirects || []).length) rows.push(["Redirects", [...d.redirects, d.final_url].join(" → ")]);
    if (d.http_redirect) rows.push(["HTTP → HTTPS", d.http_redirect]);
    rows.push(["Present", present.length ? present.map(([k, v]) => h("div", {}, h("strong", {}, k), ": ", h("code", {}, v))) : "none"]);
    rows.push(["Missing", (d.missing || []).join(", ") || "none"]);
    if ((d.cookies || []).length) {
      rows.push(["Cookies", d.cookies.map((ck) => h("div", {}, h("code", {}, ck.name), " ",
        flag("Secure", ck.secure), flag("HttpOnly", ck.httponly), flag(`SameSite ${ck.samesite || "unset"}`, !!ck.samesite)))]);
    }
    body.push(kv(rows));
  }
  const n = c.findings.length;
  return h("section", { class: "card check-card" },
    h("h3", {}, c.title, n ? h("span", { class: "sev sev-info" }, plural(n, "finding")) : (c.error ? null : h("span", { class: "sev sev-ok" }, "ok"))),
    body);
}

function kv(pairs) {
  return h("dl", { class: "kv" }, pairs.map(([k, v]) => [h("dt", {}, k), h("dd", {}, v === null || v === undefined || v === "" ? "—" : v)]));
}

function flag(label, ok) {
  return h("span", { class: `flag ${ok ? "on" : "off"}` }, `${ok ? "✓" : "✗"} ${label}`);
}

const PROTO_GOOD = { "TLSv1.2": true, "TLSv1.3": true };
function tlsEndpoint(ep) {
  const protos = Object.entries(ep.protocols || {}).map(([name, status]) => {
    let cls = "neutral";
    if (status === "supported") cls = PROTO_GOOD[name] ? "good" : "bad";
    else if (status === "rejected") cls = PROTO_GOOD[name] ? "neutral" : "good";
    return h("span", { class: `proto ${cls}`, title: status }, `${name} ${status === "supported" ? "✓" : status === "rejected" ? "✗" : "?"}`);
  });
  const rows = [
    ["Negotiated", [ep.protocol || "unknown", ep.cipher ? [" · ", h("code", {}, ep.cipher)] : null]],
    ["Protocols", h("span", { class: "protos" }, protos)],
    ["Weak ciphers", ep.weak_cipher === "supported" ? h("span", { class: "error-text" }, `accepted (${ep.weak_cipher_name})`) : ep.weak_cipher],
    ["Trust", ep.verification === "trusted" ? h("span", { class: "flag on" }, "✓ trusted") : h("span", { class: "error-text" }, ep.verification)],
  ];
  const c = ep.certificate;
  if (c) {
    rows.push(["Subject", c.subject], ["Names", (c.sans || []).join(", ") || "none"],
      ["Issuer", `${c.issuer || "unknown"}${c.self_signed ? " (self-signed)" : ""}`],
      ["Valid", `${c.not_before} → ${c.not_after}`],
      ["Key", `${c.key_type}${c.key_bits ? ` ${c.key_bits} bits` : ""} · signature ${c.signature || "unknown"}`]);
  }
  return h("div", { class: "endpoint" }, h("h4", {}, `Port ${ep.port}`), kv(rows));
}
