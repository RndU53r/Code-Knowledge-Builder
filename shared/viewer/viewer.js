"use strict";
(function () {
  // ckb knowledge graph viewer. No network access except, in live mode, same-origin /api calls to the
  // local read-only ckb server. All target-derived strings are inserted with textContent only.
  const DATA = JSON.parse(document.getElementById("ckb-data").textContent);
  const LIVE = DATA.live || null;
  let G, byId, outAdj, inAdj, generated;
  const COLORS = {repo:"#8892a6",dir:"#6b7385",file:"#7f8ea8",module:"#7f8ea8",class:"#b48ead",interface:"#b48ead",function:"#6ea8fe",
    method:"#6ea8fe",endpoint:"#5ad19a",consumer:"#5ad19a",cron_job:"#5ad19a",cli_command:"#5ad19a",topic:"#f7b955",queue:"#f7b955",table:"#e5a05b",cache:"#e5a05b",bucket:"#e5a05b",
    env_var:"#9aa3b2",package:"#6b7385",cloud_resource:"#56c2e6",service:"#56c2e6",external:"#c0c6d2",sink:"#ff8f6b",taint_source:"#5ad19a",
    threat:"#ff6b6b",sc_finding:"#ff6b6b",cspm_finding:"#ff6b6b",trust_boundary:"#c792ea",drift:"#ffcb6b",doc_section:"#c0c6d2",asset:"#c792ea"};
  const EDGE_COLORS = {calls:"#6ea8fe",http_calls:"#5ad19a",publishes:"#f7b955",consumes:"#f7b955",reads:"#e5a05b",writes:"#e5a05b",
    routes_to:"#5ad19a",reaches_sink:"#ff8f6b",threatens:"#ff6b6b",finding_at:"#ff6b6b",affects:"#ff6b6b",drifts_from:"#ffcb6b",
    spawns:"#c792ea",imports:"#4b5468",contains:"#3a4152",reads_env:"#4b5468"};
  const SEC = new Set(["threat","sc_finding","cspm_finding","drift","trust_boundary"]);
  const OVERVIEW = new Set(["endpoint","consumer","cron_job","cli_command","topic","queue","table","bucket","external","service","cloud_resource","threat","cspm_finding","drift","trust_boundary"]);
  const $ = (id) => document.getElementById(id);
  const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = String(text); if (cls) e.className = cls; return e; };

  function load(graph) {
    G = graph; byId = new Map(); outAdj = new Map(); inAdj = new Map(); generated = graph.generated;
    for (const n of G.nodes) byId.set(n.id, n);
    for (const e of G.edges) { if (!outAdj.has(e.src)) outAdj.set(e.src, []); outAdj.get(e.src).push(e);
      if (!inAdj.has(e.dst)) inAdj.set(e.dst, []); inAdj.get(e.dst).push(e); }
    const s = G.stats || {};
    $("meta").textContent = `${s.nodes || G.nodes.length} nodes · ${s.edges || G.edges.length} edges · ${Object.keys(G.repos || {}).join(", ")} · ${G.generated || ""}`;
    buildKinds(); buildRoles(); buildTours();
  }

  // ---------------------------------------------------------------- state
  const pos = new Map(); const vel = new Map();
  let visible = new Set(); let selected = null; let hover = null; let highlight = new Set(); let hlEdges = new Set();
  let hiddenKinds = new Set(["contains", "package", "dir", "env_var"]);
  let pathStart = null; let tour = null; let tourStep = 0; let alpha = 1;
  const cv = $("cv"), ctx = cv.getContext("2d"); let W = 0, H = 0, scale = 1, ox = 0, oy = 0;
  load(DATA.graph);

  function degree(id) { return (outAdj.get(id) || []).length + (inAdj.get(id) || []).length; }
  function place(id, near) {
    if (pos.has(id)) return;
    const p = near && pos.get(near);
    pos.set(id, p ? {x: p.x + (Math.random() - .5) * 80, y: p.y + (Math.random() - .5) * 80} : {x: (Math.random() - .5) * 600, y: (Math.random() - .5) * 400});
    vel.set(id, {x: 0, y: 0});
  }
  function show(ids, near) { for (const id of ids) if (byId.has(id) && !hiddenKinds.has(byId.get(id).kind)) { visible.add(id); place(id, near); } alpha = 1; }
  function overview() {
    visible = new Set();
    const ids = [];
    for (const n of G.nodes) if (OVERVIEW.has(n.kind) && !(n.kind === "cspm_finding" && !$("ov-sec").checked)) ids.push(n.id);
    for (const e of G.edges) if (e.kind === "routes_to") ids.push(e.dst);
    for (const e of G.edges) if (e.dst_citation) { ids.push(e.src); ids.push(e.dst); }
    show(ids.slice(0, 1500));
  }
  function showAll() { visible = new Set(); show(G.nodes.map(n => n.id).slice(0, (DATA.cap || 5000))); }
  function expand(id) { const ids = [id]; for (const e of (outAdj.get(id) || [])) ids.push(e.dst); for (const e of (inAdj.get(id) || [])) ids.push(e.src); show(ids, id); }

  // ---------------------------------------------------------------- filters UI
  function buildKinds() {
    const box = $("kinds"); box.replaceChildren();
    const counts = {}; for (const n of G.nodes) counts[n.kind] = (counts[n.kind] || 0) + 1;
    for (const k of Object.keys(counts).sort()) {
      const lab = el("label", null, "k"); const cb = el("input"); cb.type = "checkbox"; cb.checked = !hiddenKinds.has(k);
      cb.addEventListener("change", () => { if (cb.checked) hiddenKinds.delete(k); else { hiddenKinds.add(k); for (const id of [...visible]) if (byId.get(id).kind === k) visible.delete(id); } alpha = 1; });
      const dot = el("span", null, "dot"); dot.style.background = COLORS[k] || "#888";
      lab.append(cb, dot, el("span", `${k} (${counts[k]})`)); box.append(lab);
    }
  }
  function buildRoles() {
    const counts = {}; for (const n of G.nodes) if (n.kind === "file" && n.attrs && n.attrs.role) counts[n.attrs.role] = (counts[n.attrs.role] || 0) + 1;
    const sel = $("role"); sel.replaceChildren(el("option", "All roles")); sel.firstChild.value = "";
    for (const r of Object.keys(counts).sort()) { const o = el("option", `${r} (${counts[r]})`); o.value = r; sel.append(o); }
    $("rolebox").hidden = !Object.keys(counts).length;
    sel.onchange = () => { if (!sel.value) { overview(); return; }
      visible = new Set(); show(G.nodes.filter(n => n.kind === "file" && n.attrs && n.attrs.role === sel.value).map(n => n.id).slice(0, 1500)); };
  }
  function buildTours() {
    const sel = $("tours"); sel.replaceChildren(el("option", "— choose a tour —"));
    sel.firstChild.value = "";
    for (const t of (G.tours || [])) { const o = el("option", t.title || t.name); o.value = t.name; sel.append(o); }
  }
  const FULL = DATA.graph;
  if (DATA.callgraph) {
    $("levelbox").hidden = false;
    for (const [lv, label] of [["repo", "Repo → repo"], ["file", "File → file"], ["function", "Function → function"], ["class", "Class → class"], ["library", "Library calls"]]) {
      if (DATA.callgraph[lv] && DATA.callgraph[lv].nodes.length) { const o = el("option", label); o.value = lv; $("level").append(o); }
    }
    $("level").addEventListener("change", () => {
      const lv = $("level").value; clearHL(); selected = null; $("detail").replaceChildren(el("div", "Select a node.", "mut"));
      if (lv === "full") { load(FULL); overview(); }
      else { const c = DATA.callgraph[lv]; load({...FULL, nodes: c.nodes, edges: c.edges, tours: FULL.tours, stats: {nodes: c.nodes.length, edges: c.edges.length}}); showAll(); }
      alpha = 1; hud(lv === "full" ? "" : `${lv} call graph: ${c_count(lv)}`);
    });
  }
  function c_count(lv) { const c = DATA.callgraph[lv]; return `${c.nodes.length} nodes, ${c.edges.length} edges (weights = number of underlying calls)`; }
  $("btn-overview").addEventListener("click", overview);
  $("btn-all").addEventListener("click", showAll);
  $("lowconf").addEventListener("change", () => { alpha = 1; });
  $("ov-sec").addEventListener("change", () => { alpha = 1; });
  $("ov-taint").addEventListener("change", () => { if ($("ov-taint").checked) taintOverlay(); else clearHL(); });

  // ---------------------------------------------------------------- search
  $("q").addEventListener("input", () => {
    const q = $("q").value.trim().toLowerCase(); const box = $("results"); box.replaceChildren();
    if (q.length < 2) return;
    let n = 0;
    for (const node of G.nodes) {
      if ((node.name || "").toLowerCase().includes(q) || (node.qualname || "").toLowerCase().includes(q) || (node.path || "").toLowerCase().includes(q)) {
        const d = el("div"); const dot = el("span", "● "); dot.style.color = COLORS[node.kind] || "#888";
        d.append(dot, el("span", `${node.name} `), el("span", node.kind, "mut small"));
        d.addEventListener("click", () => { show([node.id]); expand(node.id); select(node.id, true); });
        box.append(d); if (++n >= 30) break;
      }
    }
  });

  // ---------------------------------------------------------------- analysis (offline ports of graph_query ops)
  const DEP = new Set(["calls","imports","routes_to","http_calls","grpc_calls","spawns","inherits","implements","overrides","uses_type","references"]);
  function contained(id) { const out = [id], st = [id]; while (st.length) { const c = st.pop(); for (const e of (outAdj.get(c) || [])) if (e.kind === "contains" && !out.includes(e.dst)) { out.push(e.dst); st.push(e.dst); } } return out; }
  function* dependents(id) {
    for (const e of (inAdj.get(id) || [])) if (DEP.has(e.kind)) yield [e.src, e];
    for (const e of (outAdj.get(id) || [])) if (e.kind === "publishes" || e.kind === "writes")
      for (const e2 of (inAdj.get(e.dst) || [])) if ((e2.kind === "consumes" || e2.kind === "reads") && e2.src !== id) yield [e2.src, e2];
  }
  function impact(id) {
    const seeds = contained(id); const dist = new Map(seeds.map(s => [s, 0])); const q = [...seeds]; const edges = new Set();
    while (q.length) { const c = q.shift(); if (dist.get(c) >= 6) continue;
      for (const [nx, e] of dependents(c)) if (!dist.has(nx)) { dist.set(nx, dist.get(c) + 1); edges.add(e); q.push(nx);
        for (const e2 of (inAdj.get(nx) || [])) if (e2.kind === "routes_to" && !dist.has(e2.src)) { dist.set(e2.src, dist.get(nx) + 1); edges.add(e2); q.push(e2.src); } } }
    return {nodes: [...dist.keys()], edges};
  }
  function forward(c) { const out = (outAdj.get(c) || []).map(e => [e.dst, e]); const k = byId.get(c);
    if (k && ["topic","table","queue","bucket","cache"].includes(k.kind)) for (const e of (inAdj.get(c) || [])) if (e.kind === "consumes" || e.kind === "reads") out.push([e.src, e]); return out; }
  function findPath(a, b) {
    const targets = new Set(contained(b)); const prev = new Map([[a, null]]); const q = [a];
    while (q.length) { const c = q.shift(); if (targets.has(c) && c !== a) { const ns = [], es = []; let x = c; while (prev.get(x)) { const [p, e] = prev.get(x); es.push(e); ns.push(x); x = p; } ns.push(a); return {nodes: ns, edges: new Set(es)}; }
      for (const [nx, e] of forward(c)) if (!prev.has(nx) && e.kind !== "contains") { prev.set(nx, [c, e]); q.push(nx); } }
    return null;
  }
  function taintOverlay() {
    clearHL(); const sinks = new Set(G.nodes.filter(n => n.kind === "sink" && !(n.attrs || {}).safe).map(n => n.id));
    const T = new Set(["routes_to","calls","http_calls","grpc_calls","spawns","reaches_sink","flows_to","publishes","consumes"]);
    for (const src of G.nodes.filter(n => ["endpoint","consumer","cron_job","cli_command","taint_source"].includes(n.kind))) {
      const prev = new Map([[src.id, null]]); const q = [src.id];
      while (q.length) { const c = q.shift(); if (sinks.has(c)) { let x = c; highlight.add(x); while (prev.get(x)) { const [p, e] = prev.get(x); hlEdges.add(e); highlight.add(p); x = p; } continue; }
        for (const [nx, e] of forward(c)) if (T.has(e.kind) && !prev.has(nx)) { prev.set(nx, [c, e]); q.push(nx); } }
    }
    show([...highlight]); hud(`taint overlay: ${highlight.size} nodes on source → unsafe-sink candidate paths (confirm each hop in code)`);
  }
  function clearHL() { highlight = new Set(); hlEdges = new Set(); hud(""); }

  // ---------------------------------------------------------------- detail panel
  function cite(c) { return el("code", c || "[no citation]"); }
  function select(id, center) {
    selected = id; const n = byId.get(id); const box = $("detail"); box.replaceChildren(); if (!n) return;
    if (pathStart && pathStart !== id) { const p = findPath(pathStart, id); clearHL(); if (p) { p.nodes.forEach(x => highlight.add(x)); hlEdges = p.edges; show(p.nodes); hud(`path: ${p.nodes.length - 1} hops`); } else hud("no forward path found"); pathStart = null; }
    if (center && pos.has(id)) { const p = pos.get(id); ox = W / 2 - p.x * scale; oy = H / 2 - p.y * scale; }
    const head = el("div"); const pill = el("span", n.kind, "pill"); pill.style.borderColor = COLORS[n.kind] || "#888";
    head.append(pill, el("strong", n.name)); box.append(head);
    const kv = el("div", null, "kv");
    const add = (k, v) => { kv.append(el("span", k, "mut"), v instanceof Node ? v : el("span", v)); };
    add("citation", cite(n.citation)); add("repo", n.repo || ""); if (n.qualname) add("qualname", n.qualname);
    add("extractor", (n.provenance || {}).extractor || ""); add("confidence", n.confidence || ""); add("label", n.label || "");
    if (n.signature) add("signature", el("code", n.signature));
    for (const [k, v] of Object.entries(n.attrs || {})) if (typeof v !== "object") add(k, String(v)); else if (Array.isArray(v) && v.length) add(k, v.slice(0, 6).join(", "));
    box.append(kv);
    if (n.summary) { box.append(el("h2", "Summary" + (n.summary_status === "OUTDATED" ? " [OUTDATED]" : ""))); box.append(el("div", n.summary)); }
    const tools = el("div", null, "row");
    const b1 = el("button", "Expand"); b1.type = "button"; b1.onclick = () => expand(id);
    const b2 = el("button", "Impact"); b2.type = "button"; b2.onclick = () => { clearHL(); const r = impact(id); r.nodes.forEach(x => highlight.add(x)); hlEdges = r.edges; show(r.nodes, id); hud(`impact: ${r.nodes.length - contained(id).length} dependents`); };
    const b3 = el("button", "Path from here"); b3.type = "button"; b3.onclick = () => { pathStart = id; hud("select a destination node…"); };
    tools.append(b1, b2, b3); box.append(tools);
    const sec = [];
    for (const x of contained(id)) for (const e of [...(inAdj.get(x) || []), ...(outAdj.get(x) || [])]) { const o = e.src === x ? e.dst : e.src; if (SEC.has((byId.get(o) || {}).kind)) sec.push([e, o]); }
    if (sec.length) { box.append(el("h2", "Security")); for (const [e, o] of sec.slice(0, 40)) box.append(edgeRow(e, o)); }
    const outs = outAdj.get(id) || [], ins = inAdj.get(id) || [];
    box.append(el("h2", `Outgoing (${outs.length})`)); for (const e of outs.slice(0, 80)) box.append(edgeRow(e, e.dst));
    box.append(el("h2", `Incoming (${ins.length})`)); for (const e of ins.slice(0, 80)) box.append(edgeRow(e, e.src));
  }
  function edgeRow(e, other) {
    const o = byId.get(other) || {name: other, kind: "?"}; const d = el("div", null, "edge");
    const sev = (o.attrs || {}).severity; const k = el("span", e.kind + " ", "mut"); const nm = el("span", o.name + " ", sev ? "sev-" + sev : "");
    d.append(k, nm, el("span", `[${e.confidence}${e.label !== "observed" ? ", " + e.label : ""}]`, "mut small"), el("br"), cite(e.citation));
    d.addEventListener("click", () => { show([other], selected); select(other, true); }); return d;
  }

  // ---------------------------------------------------------------- tours
  $("tours").addEventListener("change", () => { const name = $("tours").value; tour = (G.tours || []).find(t => t.name === name) || null; tourStep = 0; renderTour(); });
  function renderTour() {
    const box = $("tourbox"); box.replaceChildren(); if (!tour) { box.hidden = true; return; } box.hidden = false;
    const st = (tour.steps || [])[tourStep]; if (!st) return;
    box.append(el("strong", `${tourStep + 1}/${tour.steps.length} · ${tour.title || tour.name}`), el("div", st.note || ""), cite(st.citation));
    const row = el("div", null, "row"); const p = el("button", "‹ Prev"), n = el("button", "Next ›"); p.type = n.type = "button";
    p.onclick = () => { tourStep = Math.max(0, tourStep - 1); renderTour(); }; n.onclick = () => { tourStep = Math.min(tour.steps.length - 1, tourStep + 1); renderTour(); };
    row.append(p, n); box.append(row);
    if (byId.has(st.node_id)) { show([st.node_id]); expand(st.node_id); select(st.node_id, true); clearHL(); highlight.add(st.node_id); }
  }

  // ---------------------------------------------------------------- layout + render
  function edgeVisible(e) { return visible.has(e.src) && visible.has(e.dst) && !hiddenKinds.has(e.kind) && ($("lowconf").checked || e.confidence !== "low")
    && ($("ov-sec").checked || !SEC.has((byId.get(e.src) || {}).kind)); }
  function step() {
    if (alpha < 0.02) return; const ids = [...visible]; const n = ids.length; const k = n > 900 ? 0.4 : 1;
    for (let i = 0; i < n; i++) { const a = pos.get(ids[i]), va = vel.get(ids[i]);
      for (let j = i + 1; j < n; j += (n > 900 ? 3 : 1)) { const b = pos.get(ids[j]), vb = vel.get(ids[j]); let dx = a.x - b.x, dy = a.y - b.y; let d2 = dx * dx + dy * dy + 0.01;
        if (d2 > 90000) continue; const f = 900 * k / d2; dx *= f; dy *= f; va.x += dx; va.y += dy; vb.x -= dx; vb.y -= dy; } }
    for (const e of G.edges) { if (!edgeVisible(e)) continue; const a = pos.get(e.src), b = pos.get(e.dst); const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.sqrt(dx * dx + dy * dy) + 0.01; const f = (d - 70) * 0.01; const fx = dx / d * f, fy = dy / d * f;
      vel.get(e.src).x += fx; vel.get(e.src).y += fy; vel.get(e.dst).x -= fx; vel.get(e.dst).y -= fy; }
    for (const id of ids) { const p = pos.get(id), v = vel.get(id); v.x = (v.x - p.x * 0.001) * 0.6; v.y = (v.y - p.y * 0.001) * 0.6; p.x += v.x * alpha; p.y += v.y * alpha; }
    alpha *= 0.985;
  }
  function draw() {
    const dpr = window.devicePixelRatio || 1; const r = cv.getBoundingClientRect();
    if (r.width * dpr !== cv.width || r.height * dpr !== cv.height) { cv.width = r.width * dpr; cv.height = r.height * dpr; W = r.width; H = r.height; if (!ox && !oy) { ox = W / 2; oy = H / 2; } }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H); ctx.translate(ox, oy); ctx.scale(scale, scale);
    const hl = highlight.size > 0;
    for (const e of G.edges) { if (!edgeVisible(e)) continue; const a = pos.get(e.src), b = pos.get(e.dst);
      const on = hlEdges.has(e) || (selected && (e.src === selected || e.dst === selected));
      ctx.globalAlpha = hl && !on ? 0.12 : (on ? 1 : 0.55); ctx.strokeStyle = EDGE_COLORS[e.kind] || "#5a6273"; ctx.lineWidth = (on ? 2.2 : 1) / scale;
      ctx.setLineDash(e.label === "observed" ? [] : [4 / scale, 3 / scale]); ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
      const mx = b.x - (b.x - a.x) * 0.15, my = b.y - (b.y - a.y) * 0.15; ctx.beginPath(); ctx.arc(mx, my, 1.8 / scale, 0, 6.3); ctx.fillStyle = ctx.strokeStyle; ctx.fill(); }
    ctx.setLineDash([]);
    for (const id of visible) { const n = byId.get(id), p = pos.get(id); const rad = Math.min(14, 4 + Math.sqrt(degree(id)));
      ctx.globalAlpha = hl && !highlight.has(id) && id !== selected ? 0.2 : 1; ctx.beginPath(); ctx.arc(p.x, p.y, rad, 0, 6.3); ctx.fillStyle = COLORS[n.kind] || "#888"; ctx.fill();
      if (id === selected || id === hover) { ctx.lineWidth = 2 / scale; ctx.strokeStyle = "#fff"; ctx.stroke(); }
      if (SEC.has(n.kind) || ((n.attrs || {}).safe === false && n.kind === "sink")) { ctx.lineWidth = 1.5 / scale; ctx.strokeStyle = "#ff6b6b"; ctx.stroke(); }
      if (scale > 0.7 || id === selected || id === hover || highlight.has(id) || OVERVIEW.has(n.kind)) {
        ctx.fillStyle = getComputedStyle(document.body).color; ctx.font = `${11 / scale}px system-ui`; ctx.fillText(String(n.name).slice(0, 48), p.x + rad + 2, p.y + 3); } }
    ctx.globalAlpha = 1;
  }
  function frame() { step(); draw(); requestAnimationFrame(frame); }
  function hud(t) { $("hud").textContent = t || `${visible.size} shown · drag to pan · wheel to zoom · double-click to expand`; }

  function nodeAt(mx, my) { const x = (mx - ox) / scale, y = (my - oy) / scale; let best = null, bd = 1e9;
    for (const id of visible) { const p = pos.get(id); const d = (p.x - x) ** 2 + (p.y - y) ** 2; if (d < bd && d < 200 / scale) { bd = d; best = id; } } return best; }
  let drag = null;
  cv.addEventListener("mousedown", (ev) => { const id = nodeAt(ev.offsetX, ev.offsetY); drag = {id, x: ev.offsetX, y: ev.offsetY, moved: false}; });
  cv.addEventListener("mousemove", (ev) => { if (drag) { const dx = ev.offsetX - drag.x, dy = ev.offsetY - drag.y; drag.moved = drag.moved || Math.abs(dx) + Math.abs(dy) > 3;
      if (drag.id) { const p = pos.get(drag.id); p.x += dx / scale; p.y += dy / scale; alpha = Math.max(alpha, 0.3); } else { ox += dx; oy += dy; } drag.x = ev.offsetX; drag.y = ev.offsetY; }
    else { hover = nodeAt(ev.offsetX, ev.offsetY); cv.style.cursor = hover ? "pointer" : "grab"; } });
  cv.addEventListener("mouseup", () => { if (drag && !drag.moved && drag.id) select(drag.id); drag = null; });
  cv.addEventListener("dblclick", (ev) => { const id = nodeAt(ev.offsetX, ev.offsetY); if (id) expand(id); });
  cv.addEventListener("wheel", (ev) => { ev.preventDefault(); const f = ev.deltaY < 0 ? 1.12 : 1 / 1.12; ox = ev.offsetX - (ev.offsetX - ox) * f; oy = ev.offsetY - (ev.offsetY - oy) * f; scale *= f; }, {passive: false});

  // ---------------------------------------------------------------- live mode (local ckb server only)
  if (LIVE) {
    setInterval(async () => {
      try {
        const st = await (await fetch(`/api/status?token=${encodeURIComponent(LIVE.token)}`, {cache: "no-store"})).json();
        if (st.generated && st.generated !== generated) {
          const g = await (await fetch(`/api/graph?token=${encodeURIComponent(LIVE.token)}`, {cache: "no-store"})).json();
          if ($("level")) $("level").value = "full"; load(g); const keep = [...visible].filter(id => byId.has(id)); visible = new Set(keep); hud("graph reloaded: " + g.generated);
        }
      } catch (e) { hud("live server unreachable"); }
    }, 3000);
  }
  overview(); hud(); frame();
})();
