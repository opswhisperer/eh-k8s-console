"use strict";

// ---------- tiny DOM helpers (all text goes through textContent) ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
// fill replaces an element's children, flattening arrays and skipping null/false like h().
function fill(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false).map((k) => k instanceof Node ? k : document.createTextNode(String(k))));
  return el;
}
const ROLE = { viewer: 1, operator: 2, admin: 3 };
const app = { me: null, info: null, state: null, settings: null, pending: newPending(), timer: null, stream: null };
function newPending() { return { config: {}, secrets: {}, images: {} }; }
const can = (role) => app.me && ROLE[app.me.role] >= ROLE[role];
const writable = (role) => can(role) && !(app.info && app.info.readOnly);

function toast(msg, error) {
  const t = h("div", { class: "toast" + (error ? " error" : ""), role: "status" }, msg);
  document.body.append(t);
  setTimeout(() => t.remove(), error ? 7000 : 3500);
}

async function call(method, path, body) {
  const res = await fetch(path, {
    method, credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (res.status === 401 && !path.startsWith("/auth/")) { renderSignIn(); throw new Error("sign in required"); }
  if (!res.ok) { const e = new Error((data && data.error) || res.statusText); e.status = res.status; e.data = data; throw e; }
  return data;
}
const get = (p) => call("GET", p);
const post = (p, b) => call("POST", p, b || {});

function ago(iso) {
  const s = Math.round((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  return Math.round(s / 3600) + " h ago";
}
const sevClass = (s) => ({ critical: "critical", warning: "warning" }[s] || "ok");
const short = (fp) => (fp || "").slice(0, 11) + "…";

// ---------- sign-in ----------
async function renderSignIn() {
  const cfg = await get("/auth/config").catch(() => ({ modes: [] }));
  const root = document.getElementById("app");
  const next = location.pathname + location.hash;
  const parts = [h("h2", {}, "Sign in"), h("p", { class: "muted" }, "Use your organisation account to view and change this cluster's ExtraHop integration.")];
  if (cfg.modes.includes("oidc")) {
    parts.push(h("a", { class: "btn primary", href: "/auth/oidc?next=" + encodeURIComponent(next) }, "Sign in with " + (cfg.oidcName || "single sign-on")));
  }
  if (cfg.modes.includes("local")) {
    if (cfg.modes.includes("oidc")) parts.push(h("p", { class: "or" }, "or with a local account"));
    const err = h("p", { class: "err", role: "alert" });
    const user = h("input", { name: "username", autocomplete: "username", required: true, "aria-label": "Username", placeholder: "Username" });
    const pass = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true, "aria-label": "Password", placeholder: "Password" });
    parts.push(h("form", { onsubmit: async (e) => {
      e.preventDefault(); err.textContent = "";
      try { await post("/auth/login", { username: user.value, password: pass.value }); start(); }
      catch (x) { err.textContent = x.message; }
    } }, user, pass, h("button", { class: "primary", type: "submit" }, "Sign in"), err));
  }
  if (!cfg.modes.includes("oidc") && !cfg.modes.includes("local")) {
    parts.push(h("p", {}, "This console accepts API keys or a sign-in proxy only. Open it through your organisation's sign-in gateway."));
  }
  fill(root, h("div", { class: "signin-page" },
    h("section", { class: "signin-hero" },
      h("img", { src: "brand/logo-white.svg", alt: "ExtraHop Security" }),
      h("div", {}, h("h1", {}, "Kubernetes integration console"),
        h("p", {}, "Configure, verify and monitor how this cluster's traffic, metadata and session keys reach the ExtraHop sensor."),
        h("p", { class: "disclaimer" }, "Community project. Not supported by, endorsed by or affiliated with ExtraHop Networks."))),
    h("div", { class: "signin" }, parts)));
}

// ---------- frame ----------
const VIEWS = [
  ["overview", "Overview"], ["settings", "Settings"], ["filtering", "Traffic filtering"],
  ["certs", "Sensor certificate"], ["logs", "Logs"], ["history", "History"],
];

function route() { return (location.hash.replace(/^#\/?/, "").split("?")[0]) || "overview"; }
function routeParams() { return new URLSearchParams(location.hash.split("?")[1] || ""); }

function frame(content) {
  const counts = (app.state && app.state.counts) || {};
  const nav = VIEWS.map(([id, label]) => {
    const extra = id === "overview" && (counts.critical || counts.warning)
      ? h("span", { class: "count " + (counts.critical ? "critical" : "warning"), title: `${counts.critical || 0} critical, ${counts.warning || 0} warnings` }, String((counts.critical || 0) + (counts.warning || 0)))
      : null;
    return h("a", { class: "nav", href: "#/" + id, "aria-current": route() === id ? "page" : null }, label, extra);
  });
  const cluster = app.settings ? (app.settings.settings.find((s) => s.key === "clusterName") || {}).value : null;
  return h("div", { class: "frame" },
    h("nav", { class: "rail", "aria-label": "Sections" },
      h("div", { class: "brand" }, h("img", { src: "brand/logo-white.svg", alt: "ExtraHop Security" }),
        h("strong", {}, "Kubernetes integration"),
        h("small", {}, (cluster ? cluster + " cluster, " : "") + "namespace " + ((app.info && app.info.namespace) || ""))),
      nav,
      h("p", { class: "disclaimer" }, "Community project. Not supported by, endorsed by or affiliated with ExtraHop Networks."),
      h("div", { class: "who" }, h("strong", {}, app.me.name || app.me.user), app.me.role + " via " + app.me.via,
        app.me.via !== "none" && app.me.via !== "apikey" && app.me.via !== "proxy"
          ? h("div", {}, h("button", { class: "link", onclick: signOut }, "Sign out")) : null)),
    h("main", { id: "main" }, content));
}

async function signOut() {
  const r = await post("/auth/logout").catch(() => ({ redirect: "/" }));
  location.href = r.redirect || "/";
}

function topline(title, meta, ...actions) {
  return h("div", { class: "topline" }, h("h2", {}, title), meta ? h("span", { class: "meta" }, meta) : null, h("div", { class: "actions" }, actions));
}

function readOnlyBanner() {
  const out = [];
  if (app.info && app.info.readOnly) out.push(h("div", { class: "banner info" }, "Read-only console: you can review and export changes, but not apply them."));
  if (app.state && app.state.helm) out.push(h("div", { class: "banner" }, `Helm release “${app.state.helm.release}” manages the integration. Live changes are overwritten by the next helm upgrade, so export Helm values instead.`));
  if (app.state && app.state.argocd) out.push(h("div", { class: "banner" }, `Argo CD application “${app.state.argocd.application}” syncs the integration from git. A live change is put back by self-heal or the next sync, so change the git repository instead (Export → manifests shows the change).`));
  return out;
}

async function refreshState() {
  try { app.state = await get("/api/state"); } catch (e) { if (e.status !== 503) throw e; }
}

async function render() {
  clearInterval(app.timer);
  if (app.stream && route() !== "logs") { app.stream.close(); app.stream = null; }
  const v = route();
  const fn = { overview: viewOverview, settings: viewSettings, filtering: viewFiltering, certs: viewCerts, logs: viewLogs, history: viewHistory }[v] || viewOverview;
  try {
    const content = await fn();
    fill(document.getElementById("app"), frame(content));
    const m = document.getElementById("main"); if (m && m.firstElementChild) m.focus?.();
  } catch (e) {
    if (e.message === "sign in required") return;
    fill(document.getElementById("app"), frame([h("h2", {}, "Something went wrong"), h("p", {}, e.message)]));
  }
}

// ---------- overview ----------
function workloadOf(comp) { return (app.state.workloads || []).find((w) => w.component === comp); }

function pathNode(title, big, sub, cls) {
  return h("div", { class: "node " + cls }, h("h3", {}, title), h("div", { class: "big" }, big), h("div", { class: "sub" }, sub));
}
function wire(label, port, cls) {
  return h("div", { class: "link-row" }, h("div", { class: "wire-label" }, h("span", {}, label), h("span", {}, port)), h("div", { class: "wire " + cls }));
}
const wlState = (w) => !w ? "off" : w.ready === 0 && w.desired > 0 ? "critical" : (w.ready < w.desired || w.updated < w.desired) ? "warning" : "ok";

function signalPath() {
  const s = app.state;
  const fwd = workloadOf("exkpkt-forwarder"), coord = workloadOf("exkpkt-coordinator"), md = workloadOf("metadata-forwarder"), skf = workloadOf("session-key-forwarder");
  const all = s.workloads || [];
  const ready = all.reduce((a, w) => a + w.ready, 0), desired = all.reduce((a, w) => a + w.desired, 0);
  const forwarders = [fwd, coord, md, skf].filter(Boolean).map(wlState);
  const fwdCls = forwarders.includes("critical") ? "critical" : forwarders.includes("warning") ? "warning" : forwarders.length ? "ok" : "critical";
  const c = s.certs || {};
  const certCls = { OK: "ok", ROTATED_TRUSTED: "ok", BROKEN: "critical", SNI_MISMATCH: "critical", INVALID_BUNDLE: "critical", UNREACHABLE: "warning" }[c.state] || "warning";
  const pol = s.policy ? s.policy.policy : null;
  const filt = pol ? (pol.namespaced === "skip" ? (pol.mirrorNamespaces.length ? `only ${pol.mirrorNamespaces.length} namespace${pol.mirrorNamespaces.length > 1 ? "s" : ""}` : "annotated only") : (pol.skipNamespaces.length ? `all but ${pol.skipNamespaces.length}` : "all namespaces")) : "";
  const logWarn = (s.findings || []).some((f) => f.source === "logs" && f.severity !== "info" && (f.setting || "").startsWith("metadata-forwarder"));
  const sensor = (app.settings && app.settings.settings.find((x) => x.key === "mgmtTarget") || {}).value || "sensor";
  return h("div", { class: "path", role: "img", "aria-label": "Signal path from the cluster to the ExtraHop sensor" },
    pathNode("Cluster", `${ready}/${desired}`, "integration pods ready; mirroring " + filt, ready === desired ? "ok" : "warning"),
    h("div", { class: "links" },
      wire("coordinator", coord ? `${coord.ready}/${coord.desired}` : "missing", wlState(coord)),
      wire("forwarders", fwd ? `${fwd.ready}/${fwd.desired} nodes` : "missing", wlState(fwd))),
    pathNode("Forwarders", fwdCls === "ok" ? "Running" : fwdCls === "warning" ? "Degraded" : "Down", `${all.length} workloads`, fwdCls),
    h("div", { class: "links" },
      wire("traffic, Geneve", "UDP 6081", wlState(fwd)),
      wire("metadata, TLS", "443", md ? (wlState(md) === "ok" && logWarn ? "warning" : wlState(md)) : "off"),
      wire("session keys, TLS", skf ? "4873" : "not installed", skf ? wlState(skf) : "off")),
    pathNode("Sensor", sensor, (c.summary || "certificate not checked yet"), certCls));
}

function findingsList(findings, filter) {
  if (!findings.length) return h("p", { class: "muted" }, "No problems found in the last scan.");
  const where = (f) => {
    const target = f.source === "certs" ? "#/certs" : f.source === "logs" ? "#/logs?errors=1" : f.setting && /Namespaces|TrafficRule/.test(f.setting) ? "#/filtering" : f.source === "config" ? "#/settings" : null;
    return target ? h("a", { href: target }, { certs: "Certificate", logs: "Logs", config: "Settings", runtime: "Workloads", network: "Network" }[f.source] || "Open") : h("span", {}, f.source);
  };
  return h("ul", { class: "findings" }, findings.filter((f) => !filter || filter.includes(f.severity)).map((f) =>
    h("li", { class: f.severity }, h("span", { class: "bar", "aria-hidden": "true" }),
      h("div", {}, h("p", { class: "msg" }, f.message), f.fix ? h("p", { class: "fix" }, f.fix) : null),
      h("div", { class: "where" }, h("div", {}, f.severity), where(f)))));
}

async function viewOverview() {
  await Promise.all([refreshState(), loadSettings()]);
  app.timer = setInterval(async () => { await refreshState(); if (route() === "overview") render(); }, 30000);
  if (!app.state) return [h("h2", {}, "Scanning the integration…"), h("p", {}, "The first scan is still running. This page refreshes on its own.")];
  const s = app.state;
  const filterState = { sev: ["critical", "warning"] };
  const listHolder = h("div");
  const drawList = () => fill(listHolder, findingsList(s.findings || [], filterState.sev));
  const chip = (label, sevs) => h("button", { class: "chip", "aria-pressed": String(JSON.stringify(filterState.sev) === JSON.stringify(sevs)), onclick: (e) => {
    filterState.sev = sevs; e.target.parentElement.querySelectorAll(".chip").forEach((c) => c.setAttribute("aria-pressed", "false")); e.target.setAttribute("aria-pressed", "true"); drawList();
  } }, label);
  drawList();
  const rescan = can("operator") ? h("button", { onclick: async (e) => { e.target.disabled = true; try { await post("/api/scan"); await render(); toast("Scan finished"); } catch (x) { toast(x.message, true); e.target.disabled = false; } } }, "Scan now") : null;
  const restart = (w) => writable("operator") ? h("button", { onclick: () => review({ restart: [w.name], reason: "manual restart" }, { title: "Restart " + w.component, kind: "restart" }) }, "Restart") : null;
  return [
    topline("Overview", `Last scan ${ago(s.at)}` + (s.error ? " (failed)" : ""), rescan),
    readOnlyBanner(),
    s.notifyErrors && Object.keys(s.notifyErrors).length ? h("div", { class: "banner crit" }, "Alert delivery is failing: " + Object.entries(s.notifyErrors).map(([k, v]) => `${k}: ${v}`).join("; ")) : null,
    signalPath(),
    h("h3", {}, "Problems"),
    (s.ignoredLogs || []).length ? h("p", { class: "muted" }, `${(s.ignoredLogs || []).reduce((a, l) => a + l.count, 0)} errors in the last hour are hidden by ignore rules. `, h("a", { href: "#/logs" }, "Review the rules")) : null,
    h("div", { class: "sev-filter", role: "group", "aria-label": "Show" }, chip("Needs attention", ["critical", "warning"]), chip("Everything", ["critical", "warning", "info"])),
    listHolder,
    h("h3", {}, "Workloads"),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Component", "Kind", "Ready", "Image", "Restarts", ""].map((x) => h("th", {}, x)))),
      h("tbody", {}, (s.workloads || []).map((w) => h("tr", {},
        h("td", {}, h("strong", {}, w.component), h("div", { class: "muted mono" }, w.name)),
        h("td", {}, w.kind),
        h("td", { class: "num" }, h("span", { class: "state " + wlState(w) }, `${w.ready}/${w.desired}`)),
        h("td", { class: "mono" }, Object.values(w.images || {}).map((i) => h("div", {}, i.split("/").pop()))),
        h("td", { class: "num" }, (w.pods || []).reduce((a, p) => a + p.restarts, 0)),
        h("td", {}, restart(w))))))),
  ];
}

// ---------- settings ----------
async function loadSettings() { app.settings = await get("/api/settings"); }
function pendingCount() { const p = app.pending; return Object.keys(p.config).length + Object.keys(p.secrets).length + Object.keys(p.images).length; }

function pendingChange(reason) {
  const p = app.pending;
  const ch = { config: { ...p.config }, images: { ...p.images }, secrets: Object.entries(p.secrets).map(([k, value]) => { const [name, key] = k.split("|"); return { name, key, value }; }), reason };
  if (!ch.secrets.length) delete ch.secrets;
  if (!Object.keys(ch.images).length) delete ch.images;
  return ch;
}

function saveBar() {
  const n = pendingCount();
  if (!n) return null;
  return h("div", { class: "savebar" },
    h("span", { class: "grow" }, `${n} unsaved change${n > 1 ? "s" : ""}`),
    h("button", { onclick: () => { app.pending = newPending(); render(); } }, "Discard"),
    h("button", { onclick: exportPending }, "Export YAML"),
    h("button", { class: "primary", onclick: () => review(pendingChange(""), { title: "Review changes", clearPending: true }) }, "Review changes"));
}

async function exportPending() {
  try {
    const res = await fetch("/api/export", { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ change: pendingChange(""), format: "manifests" }) });
    if (!res.ok) throw new Error((await res.json()).error);
    download("extrahop-kubernetes-integration.yaml", await res.text());
  } catch (e) { toast(e.message, true); }
}
function download(name, text) {
  const a = h("a", { href: URL.createObjectURL(new Blob([text], { type: "text/yaml" })), download: name });
  document.body.append(a); a.click(); a.remove();
}

function setPending(key, value, original) {
  if (value === original) delete app.pending.config[key]; else app.pending.config[key] = value;
  if (route() === "filtering") { render(); return; }
  const bar = document.querySelector(".savebar"); const nb = saveBar();
  if (bar) bar.replaceWith(nb || h("span")); else if (nb) document.getElementById("main").append(nb);
}

function inputFor(s) {
  const current = s.key in app.pending.config ? app.pending.config[s.key] : s.value;
  const changed = s.key in app.pending.config;
  const onChange = (v) => setPending(s.key, v, s.value);
  const editable = can("admin") || (s.key === "sensorCert" && can("operator"));
  if (s.readOnly) return h("div", {}, h("code", { class: "readonly-value" }, s.value || "(not set)"), h("span", { class: "badge" }, "read-only"));
  let el;
  if (s.type === "enum") {
    el = h("select", { disabled: !editable, onchange: (e) => onChange(e.target.value) }, s.enum.map((o) => h("option", { value: o, selected: o === (current || s.default) ? true : null }, o)));
  } else if (s.type === "pem") {
    el = h("div", {},
      h("p", { class: "doc" }, `${(s.certs || []).length} certificate${(s.certs || []).length === 1 ? "" : "s"}. Manage it on the `, h("a", { href: "#/certs" }, "Sensor certificate"), " page."));
    return el;
  } else if (s.type === "nslist") {
    return namespacePicker(s, current, onChange, editable);
  } else {
    el = h("input", { value: current || "", disabled: !editable, spellcheck: "false", onchange: (e) => onChange(e.target.value.trim()) });
  }
  if (changed) el.classList.add("changed");
  return el;
}

function namespacePicker(s, current, onChange, editable) {
  const sep = (app.settings && app.settings.listSeparator) || ",";
  let chosen = (current || "").split(/[,\s]+/).filter(Boolean);
  const wrap = h("div", { class: "chips", role: "group", "aria-label": s.label });
  const draw = () => fill(wrap, ...(s.options || []).map((ns) => h("button", {
    class: "chip" + (s.key === "skipNamespaces" ? " skip" : ""), "aria-pressed": String(chosen.includes(ns)), disabled: !editable,
    onclick: () => { chosen = chosen.includes(ns) ? chosen.filter((x) => x !== ns) : [...chosen, ns].sort(); onChange(chosen.join(sep)); draw(); },
  }, ns)), ...chosen.filter((n) => !(s.options || []).includes(n)).map((n) => h("span", { class: "chip", title: "This namespace does not exist" }, n + " (missing)")));
  draw();
  return wrap;
}

function settingField(s) {
  const linked = (s.linked || []).filter((r) => r.workload);
  const used = s.consumers && s.consumers.length ? "Used by " + s.consumers.map((c) => c.replace(/^extrahop-kubernetes-integration-/, "")).join(", ") : "Not read by any workload";
  return h("div", { class: "field", id: "setting-" + s.key },
    h("div", {}, h("span", { class: "name" }, s.label), h("span", { class: "key" }, s.key), !s.present ? h("span", { class: "badge" }, "not set") : null),
    h("div", {}, inputFor(s), h("p", { class: "doc" }, s.doc),
      h("p", { class: "used" }, used + ".", linked.length ? ` Also passed as ${linked[0].via.replace("arg:", "")} to the session-key forwarder; saving updates both.` : ""),
      (s.problems || []).map((p) => h("p", { class: "err" }, p))));
}

async function viewSettings() {
  await Promise.all([loadSettings(), app.state ? null : refreshState()]);
  const st = app.settings;
  const groups = st.groups.filter((g) => g !== "Traffic filtering").map((g) => h("section", { class: "group" }, h("h3", {}, g), st.settings.filter((s) => s.group === g).map(settingField)));
  const secretRows = st.secrets.map((sec) => {
    const k = sec.name + "|" + sec.key;
    if (sec.readOnly) {
      const pair = sec.pairOK === true ? h("span", { class: "state ok" }, "Matches its public key")
        : sec.pairOK === false ? h("span", { class: "state critical" }, "Does not match its public key")
        : h("span", { class: "muted" }, "Pair not checked");
      return h("div", { class: "field" },
        h("div", {}, h("span", { class: "name" }, sec.label), h("span", { class: "key" }, `${sec.name} / ${sec.key}`), h("span", { class: "badge" }, "read-only")),
        h("div", {}, h("p", { class: "doc" }, sec.exists ? `Set (${sec.length} characters). ` : "Not set. ", pair, "."), h("p", { class: "doc" }, sec.doc),
          h("p", { class: "used" }, "Used by " + (sec.consumers.map((c) => c.replace(/^extrahop-kubernetes-integration-/, "")).join(", ") || "nothing") + ". Values are never shown.")));
    }
    const input = h("input", { type: "password", autocomplete: "new-password", placeholder: sec.exists ? `Set (${sec.length} characters). Type to replace.` : "Not set", disabled: !writable("admin") || null,
      value: app.pending.secrets[k] || "", class: app.pending.secrets[k] ? "changed" : null,
      onchange: (e) => { if (e.target.value) app.pending.secrets[k] = e.target.value; else delete app.pending.secrets[k]; render(); } });
    return h("div", { class: "field" },
      h("div", {}, h("span", { class: "name" }, sec.label), h("span", { class: "key" }, `${sec.name} / ${sec.key}`),
        sec.managedBy === "ExternalSecret" ? h("span", { class: "badge es", title: sec.externalSecret ? `Store ${sec.externalSecret.store}; ${sec.externalSecret.ready ? "synced" : "not ready"}` : "" }, "synced by ExternalSecret") : null,
        sec.managedBy === "Helm" ? h("span", { class: "badge helm" }, "Helm") : null),
      h("div", {}, input, h("p", { class: "doc" }, sec.doc), h("p", { class: "used" }, "Used by " + (sec.consumers.map((c) => c.replace(/^extrahop-kubernetes-integration-/, "")).join(", ") || "nothing") + ". Values are never shown.")));
  });
  const imageRows = st.images.map((im) => {
    const k = im.workload + "/" + im.container;
    return h("div", { class: "field" },
      h("div", {}, h("span", { class: "name" }, im.component), h("span", { class: "key" }, im.container)),
      h("div", {}, h("input", { value: app.pending.images[k] || im.image, spellcheck: "false", disabled: !writable("admin") || null, class: app.pending.images[k] ? "changed" : null,
        onchange: (e) => { const v = e.target.value.trim(); if (v && v !== im.image) app.pending.images[k] = v; else delete app.pending.images[k]; render(); } })));
  });
  return [
    topline("Settings", "Changes are reviewed before anything is applied.",
      h("a", { class: "btn", href: "/api/export/manifests" }, "Download manifests"),
      h("a", { class: "btn", href: "/api/export/helm-values" }, "Download Helm values")),
    readOnlyBanner(),
    groups,
    h("section", { class: "group" }, h("h3", {}, "Credentials"), secretRows),
    h("section", { class: "group" }, h("h3", {}, "Images"), imageRows),
    saveBar(),
  ];
}

// ---------- traffic filtering ----------
// evaluate mirrors internal/policy: the configured steps are tried in order, first match wins.
function evaluate(order, pol, peers) {
  const k8s = peers.filter((p) => p.kind === "pod" || p.kind === "node");
  if (!k8s.length) return { mirror: true, rule: 0, reason: "No Kubernetes peer, so these settings don't apply." };
  const label = (e) => e.kind === "pod" ? `a pod in ${e.namespace}` : "a node";
  for (const [i, step] of order.entries()) {
    for (const e of k8s) {
      const d = (mirror, reason) => ({ mirror, rule: i + 1, step, reason });
      if (step === "annotation:skip" && e.annotation === "skip") return d(false, `${label(e)} is annotated skip.`);
      if (step === "annotation:mirror" && e.annotation === "mirror") return d(true, `${label(e)} is annotated mirror.`);
      if (step === "namespace:skip-list" && e.kind === "pod" && pol.skipNamespaces.includes(e.namespace)) return d(false, `Namespace ${e.namespace} is in Skip namespaces.`);
      if (step === "namespace:mirror-list" && e.kind === "pod" && pol.mirrorNamespaces.includes(e.namespace)) return d(true, `Namespace ${e.namespace} is in Mirror namespaces.`);
      if (step === "namespace:rule" && e.kind === "pod") return d(pol.namespaced !== "skip", `${label(e)}: the namespace rule (${pol.namespaced}) applies.`);
      if (step === "cluster:rule") return d(pol.base !== "skip", `The cluster-scoped rule (${pol.base}) applies.`);
    }
  }
  return { mirror: true, rule: 0, reason: "No step in policy.order matched." };
}
const verdict = (d) => h("span", { class: "verdict " + (d.mirror ? "mirror" : "skip") }, d.mirror ? "Mirrored" : "Skipped");

function effectivePolicy(base) {
  const p = app.pending.config;
  const split = (v) => (v || "").split(/[,\s]+/).filter(Boolean);
  return {
    base: p.kubernetesBaseTrafficRule ?? base.base,
    namespaced: p.kubernetesNamespacedTrafficRule ?? base.namespaced,
    mirrorNamespaces: "mirrorNamespaces" in p ? split(p.mirrorNamespaces) : base.mirrorNamespaces,
    skipNamespaces: "skipNamespaces" in p ? split(p.skipNamespaces) : base.skipNamespaces,
  };
}

async function viewFiltering() {
  const [pol] = await Promise.all([get("/api/policy"), loadSettings()]);
  const eff = effectivePolicy(pol.policy);
  const setting = (k) => app.settings.settings.find((s) => s.key === k);
  const sep = app.settings.listSeparator || ",";
  const editable = can("admin");
  const applyMode = (id) => {
    const set = (k, v) => { if (v === setting(k).value) delete app.pending.config[k]; else app.pending.config[k] = v; };
    if (id === "all-except") { set("kubernetesNamespacedTrafficRule", "mirror"); set("mirrorNamespaces", ""); }
    if (id === "only-listed") { set("kubernetesNamespacedTrafficRule", "skip"); set("skipNamespaces", ""); }
    if (id === "only-annotated") { set("kubernetesNamespacedTrafficRule", "skip"); set("mirrorNamespaces", ""); set("skipNamespaces", ""); }
    app.pending.mode = id;
    render();
  };
  const mode = app.pending.mode || (() => {
    if (eff.namespaced === "mirror" && !eff.mirrorNamespaces.length) return "all-except";
    if (eff.namespaced === "skip" && eff.mirrorNamespaces.length && !eff.skipNamespaces.length) return "only-listed";
    if (eff.namespaced === "skip" && !eff.mirrorNamespaces.length && !eff.skipNamespaces.length) return "only-annotated";
    return "custom";
  })();
  const modes = h("div", { class: "modes", role: "radiogroup", "aria-label": "What to mirror" }, pol.modes.map((m) =>
    h("button", { class: "mode", role: "radio", "aria-checked": String(m.id === mode), disabled: !editable || m.id === "custom" ? (m.id === "custom" ? null : true) : null,
      onclick: () => m.id !== "custom" && applyMode(m.id) }, h("strong", {}, m.label), h("span", {}, m.description))));
  const lists = [];
  if (mode === "only-listed" || mode === "custom" || (eff.namespaced === "skip" && mode !== "only-annotated")) lists.push(settingField(setting("mirrorNamespaces")));
  if (mode === "all-except" || mode === "custom") lists.push(settingField(setting("skipNamespaces")));
  lists.push(settingField(setting("kubernetesBaseTrafficRule")));
  if (mode === "custom") lists.push(settingField(setting("kubernetesNamespacedTrafficRule")));

  const order = pol.order || [];
  const nsRows = (app.settings.settings.find((s) => s.key === "mirrorNamespaces").options || []).map((ns) => {
    const d = evaluate(order, eff, [{ kind: "pod", namespace: ns }]);
    return h("tr", {}, h("td", {}, ns), h("td", {}, verdict(d)), h("td", { class: "muted" }, d.reason));
  });
  const nodeD = evaluate(order, eff, [{ kind: "node" }]);
  const kinds = (pol.annotationKinds || []).map((k) => k.toLowerCase());
  const exceptions = (pol.exceptions || []).map((x) => {
    const a = x.annotated;
    const readKind = a.onTemplate ? "pod" : a.kind.toLowerCase();
    const honoured = !kinds.length || kinds.includes(readKind);
    const d = a.kind === "Node" ? evaluate(order, eff, [{ kind: "node", annotation: a.rule }]) : evaluate(order, eff, [{ kind: "pod", namespace: a.namespace, annotation: a.rule }]);
    const note = !honoured ? `Not read: this integration reads the annotation on ${pol.annotationKinds.join(", ")} only.` : a.onTemplate ? "On the pod template (kept for new pods)." : a.owner ? `Set directly on a pod of ${a.owner}; lost when the pod is replaced.` : "";
    return h("tr", {}, h("td", {}, a.kind), h("td", {}, (a.namespace ? a.namespace + "/" : "") + a.name), h("td", {}, h("code", {}, a.rule)),
      h("td", {}, !honoured || !pol.preview ? h("span", { class: "muted" }, "n/a") : verdict(d)), h("td", { class: "muted" }, note));
  });
  return [
    topline("Traffic filtering", pol.preview ? `Preview order: ${order.join(" → ")}` : "Settings for which traffic the integration mirrors."),
    readOnlyBanner(),
    h("p", {}, pol.notes[0]),
    h("h3", {}, "What to mirror"), modes, lists,
    pol.preview ? null : h("div", { class: "banner info" }, "The “what gets mirrored” preview is off. Set policy.order in the config to the evaluation order of your traffic-forwarder version to turn it on (see docs/filtering.md)."),
    h("div", { class: "split" },
      pol.preview ? h("section", {}, h("h3", {}, pendingCount() ? "Namespaces after your changes" : "Namespaces today"),
        h("p", { class: "muted" }, "For pods without an annotation. Nodes: ", verdict(nodeD), ". ", nodeD.reason),
        h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Namespace", "Traffic", "Why"].map((x) => h("th", {}, x)))), h("tbody", {}, nsRows))))
        : h("section", {}, h("h3", {}, "Namespace lists"), h("p", { class: "muted" }, `Mirror: ${eff.mirrorNamespaces.join(", ") || "none"}. Skip: ${eff.skipNamespaces.join(", ") || "none"}. Namespace rule: ${eff.namespaced}. Cluster-scoped rule: ${eff.base}.`)),
      h("section", {}, h("h3", {}, "Exceptions set by annotation"),
        exceptions.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Kind", "Name", "Rule", "Traffic", ""].map((x) => h("th", {}, x)))), h("tbody", {}, exceptions)))
          : h("p", { class: "muted" }, pol.annotationsEnabled ? "No pods or nodes carry the extrahop.com/traffic-mirror-rule annotation." : "Annotation listing is off. Enable integration.annotations to list and edit annotations."),
        pol.preview ? pairTester(order, eff, app.settings.settings.find((s) => s.key === "mirrorNamespaces").options || []) : null)),
    pol.annotationsEnabled ? await annotator(pol) : null,
    saveBar(),
  ];
}

function endpointPicker(label, namespaces, state) {
  const kind = h("select", { "aria-label": label + " kind", onchange: (e) => { state.kind = e.target.value; ns.hidden = state.kind !== "pod"; } },
    h("option", { value: "pod" }, "Pod in namespace"), h("option", { value: "node" }, "Node"), h("option", { value: "external" }, "Outside the cluster"));
  const ns = h("select", { "aria-label": label + " namespace", onchange: (e) => { state.namespace = e.target.value; } }, namespaces.map((n) => h("option", { value: n }, n)));
  const ann = h("select", { "aria-label": label + " annotation", onchange: (e) => { state.annotation = e.target.value; } },
    h("option", { value: "" }, "no annotation"), h("option", { value: "mirror" }, "annotated mirror"), h("option", { value: "skip" }, "annotated skip"));
  state.kind = "pod"; state.namespace = namespaces[0]; state.annotation = "";
  return h("div", { class: "endpoint" }, h("strong", {}, label), kind, ns, ann);
}

function pairTester(order, eff, namespaces) {
  const a = {}, b = {};
  const out = h("p", { "aria-live": "polite" });
  return h("section", {}, h("h3", {}, "Check a conversation"),
    h("div", { class: "tester" }, endpointPicker("From", namespaces, a), endpointPicker("To", namespaces, b),
      h("button", { onclick: () => { const d = evaluate(order, eff, [a, b]); fill(out, verdict(d), " ", d.reason); } }, "Check")), out);
}

async function annotator(pol) {
  const nsOptions = app.settings.settings.find((s) => s.key === "mirrorNamespaces").options || [];
  const st = { ns: nsOptions.find((n) => n !== app.info.namespace) || nsOptions[0], selector: "", picked: new Set(), nodes: new Set(), rule: "mirror", mode: "now" };
  const table = h("div", { class: "table-wrap" });
  const results = h("div", { "aria-live": "polite" });
  const load = async () => {
    try {
      const pods = await get(`/api/pods?namespace=${encodeURIComponent(st.ns)}&selector=${encodeURIComponent(st.selector)}`);
      st.picked.clear();
      fill(table, h("table", {}, h("thead", {}, h("tr", {}, ["", "Pod", "Owner", "Current rule"].map((x) => h("th", {}, x)))),
        h("tbody", {}, pods.length ? pods.map((p) => h("tr", {},
          h("td", {}, h("input", { type: "checkbox", "aria-label": "Select " + p.name, disabled: !p.editable || null, onchange: (e) => e.target.checked ? st.picked.add(p.name) : st.picked.delete(p.name) })),
          h("td", {}, p.name, p.hostNetwork ? h("div", { class: "muted" }, "host network: its traffic uses the node's address") : null),
          h("td", { class: "muted" }, p.owner || "none"), h("td", {}, p.rule ? h("code", {}, p.rule) : h("span", { class: "muted" }, "none"))))
          : h("tr", {}, h("td", { colspan: 4, class: "muted" }, "No pods match.")))));
    } catch (e) { fill(table, h("p", { class: "err" }, e.message)); }
  };
  const nodes = await get("/api/nodes").catch(() => []);
  const run = async (dryRun) => {
    const targets = [...st.picked].map((name) => ({ kind: "Pod", namespace: st.ns, name })).concat([...st.nodes].map((name) => ({ kind: "Node", name })));
    const body = { rule: st.rule === "remove" ? "" : st.rule, mode: st.mode, dryRun };
    if (targets.length) body.targets = targets; else if (st.selector) { body.namespace = st.ns; body.selector = st.selector; } else { toast("Pick pods or nodes, or enter a label selector", true); return; }
    if (!dryRun && !confirm(`${st.rule === "remove" ? "Remove the annotation from" : "Set " + st.rule + " on"} ${targets.length || "every matching"} target(s)?` + (st.mode !== "now" ? "\nWorkload templates change, so their pods roll." : ""))) return;
    try {
      const res = await post("/api/annotate", body);
      fill(results, h("h3", {}, dryRun ? "Dry run" : "Done"), h("ul", {}, res.map((r) => h("li", { class: r.error ? "err" : null },
        `${r.kind} ${r.namespace ? r.namespace + "/" : ""}${r.name}: ${r.error || r.action}${r.rolls ? " (pods roll)" : ""}`))));
      if (!dryRun) { toast("Annotations updated"); load(); }
    } catch (e) { toast(e.message, true); }
  };
  load();
  const nsSel = h("select", { "aria-label": "Namespace", onchange: (e) => { st.ns = e.target.value; load(); } }, nsOptions.map((n) => h("option", { value: n, selected: n === st.ns ? true : null }, n)));
  const sel = h("input", { placeholder: "Label selector, e.g. app=web (optional)", spellcheck: "false", onchange: (e) => { st.selector = e.target.value.trim(); load(); } });
  const radio = (name, value, label, hint) => h("label", { class: "check" }, h("input", { type: "radio", name, value, checked: st[name] === value, onchange: () => { st[name] = value; } }), h("span", {}, label, hint ? h("span", { class: "muted" }, " " + hint) : null));
  return h("section", {},
    h("h3", {}, "Annotate pods and nodes"),
    h("p", {}, pol.notes[1]),
    h("div", { class: "split" },
      h("div", {}, h("div", { class: "tester" }, nsSel, sel, h("button", { onclick: load }, "Refresh")), table),
      h("div", {},
        h("strong", {}, "Nodes"), h("div", { class: "chips" }, nodes.map((n) => h("button", { class: "chip", "aria-pressed": "false",
          onclick: (e) => { const on = e.target.getAttribute("aria-pressed") !== "true"; e.target.setAttribute("aria-pressed", String(on)); on ? st.nodes.add(n.name) : st.nodes.delete(n.name); } }, n.name + (n.rule ? ` (${n.rule})` : "")))),
        h("p", {}),
        h("strong", {}, "Rule"), h("div", {}, radio("rule", "mirror", "Mirror"), radio("rule", "skip", "Skip"), radio("rule", "remove", "Remove annotation")),
        h("p", {}),
        h("strong", {}, "Apply to"),
        h("div", {}, radio("mode", "now", "Running pods now", "(no restart; lost when pods are replaced)"),
          radio("mode", "persist", "Their workloads' pod templates", "(kept; pods roll; admin)"),
          radio("mode", "both", "Both")),
        h("p", {}),
        h("div", { class: "actions" }, h("button", { onclick: () => run(true) }, "Dry run"), " ",
          h("button", { class: "primary", disabled: !writable("operator") || null, onclick: () => run(false) }, "Apply annotation")),
        results)));
}

// ---------- certificates ----------
function lifeBar(c) {
  const total = (new Date(c.notAfter) - new Date(c.notBefore)) / 86400000;
  const pct = Math.max(0, Math.min(100, (c.daysLeft / total) * 100));
  const cls = c.daysLeft < 7 ? "critical" : c.daysLeft < 21 ? "warning" : "";
  return h("div", { class: "life " + cls, title: `${c.daysLeft} days left` }, h("i", { style: null, "data-pct": pct }));
}
function chainList(certs, anchorFP) {
  return h("ul", { class: "chain" }, certs.map((c) => h("li", { class: (c.sha256 === anchorFP ? "anchor" : "") + (c.expired ? " stale" : "") },
    h("strong", {}, c.subject.replace(/^CN=/, "").split(",")[0]), " ", h("span", { class: "badge" }, c.role), c.sha256 === anchorFP ? h("span", { class: "badge es" }, "trust anchor") : null,
    h("div", { class: "muted" }, `Expires ${c.notAfter.slice(0, 10)} (${c.expired ? "expired" : c.daysLeft + " days"}). Issued by ${c.issuer.replace(/^CN=/, "").split(",")[0]}.`),
    h("div", { class: "fp" }, c.sha256), lifeBar(c))));
}
function sizeLifeBars(root) { root.querySelectorAll(".life > i").forEach((i) => { i.style.width = i.dataset.pct + "%"; }); }

async function viewCerts() {
  await refreshState();
  const a = app.state && app.state.certs;
  if (!a) return [topline("Sensor certificate"), h("p", {}, "Not checked yet. The integration ConfigMap may be missing.")];
  const anchor = a.anchor ? a.anchor.sha256 : null;
  const cls = { OK: "ok", ROTATED_TRUSTED: "ok", BROKEN: "critical", SNI_MISMATCH: "critical", INVALID_BUNDLE: "critical", UNREACHABLE: "warning" }[a.state];
  const box = h("div");
  const refresh = (mode) => async () => {
    try {
      const c = await post("/api/certs/candidate", { mode });
      showCandidate(box, c);
    } catch (e) { toast(e.message, true); }
  };
  const paste = h("textarea", { placeholder: "-----BEGIN CERTIFICATE-----", spellcheck: "false", "aria-label": "PEM certificates" });
  const op = writable("operator");
  const content = [
    topline("Sensor certificate", `The forwarders trust sensorCert when they connect to ${a.probe ? a.probe.serverName : "the sensor"}.`,
      can("operator") ? h("button", { onclick: async () => { await post("/api/scan"); render(); } }, "Check again") : null),
    readOnlyBanner(),
    h("p", { class: "state " + cls }, a.summary),
    findingsList(a.findings || [], null),
    h("div", { class: "split" },
      h("section", {}, h("h3", {}, "Stored in sensorCert"), chainList(a.bundle || [], anchor)),
      h("section", {}, h("h3", {}, "Presented by the sensor"),
        a.probe && !a.probe.error ? [h("p", { class: "muted" }, `${a.probe.addr}, checked ${ago(a.probe.at)}`), chainList(a.probe.chain || [], null)] : h("p", { class: "err" }, (a.probe && a.probe.error) || "Not probed"))),
    h("h3", {}, "Update sensorCert"),
    h("p", {}, a.publicCA
      ? "The sensor's certificate comes from a public CA. Storing only the CA chain keeps working through every renewal."
      : "The sensor's certificate is not from a public CA, so sensorCert must hold its exact certificate. Confirm the fingerprint on the sensor's admin page before saving."),
    h("div", { class: "actions" },
      h("button", { class: a.recommended === "ca-chain" ? "primary" : null, disabled: !op || !a.publicCA || null, onclick: refresh("ca-chain") }, "Use the sensor's CA chain"), " ",
      h("button", { class: a.recommended === "full-chain" ? "primary" : null, disabled: !op || null, onclick: refresh("full-chain") }, "Use the full chain from the sensor")),
    h("details", {}, h("summary", {}, "Paste certificates instead"), paste,
      h("button", { disabled: !op || null, onclick: async () => { try { showCandidate(box, await post("/api/certs/candidate", { pem: paste.value })); } catch (e) { toast(e.message, true); } } }, "Check pasted certificates")),
    box,
    h("p", { class: "muted" }, app.info.certSource ? "sensorCert follows a configured source (certs.source)." : app.info.autoSync ? "Auto-sync is on: when a public-CA certificate changes, sensorCert is updated and the forwarders restart." : "Auto-sync is off. Turn on certs.autoSync to follow public-CA renewals automatically."),
  ];
  setTimeout(() => sizeLifeBars(document), 0);
  return content;
}

function showCandidate(box, c) {
  fill(box, h("h3", {}, "Proposed sensorCert"),
    c.trusts ? h("p", { class: "state ok" }, "This bundle trusts the sensor's current certificate.") : h("p", { class: "state critical" }, c.error || c.warning || "This bundle could not be checked."),
    c.warning ? h("p", { class: "muted" }, c.warning) : null,
    chainList(c.certs || [], null),
    h("button", { class: "primary", disabled: !c.trusts && !can("admin") || null, onclick: () => review({ config: { sensorCert: c.pem }, reason: "refresh sensor certificate", force: !c.trusts }, { title: "Review certificate change", kind: "cert-refresh" }) }, "Review change"));
  sizeLifeBars(box);
}

// ---------- logs ----------
const reEscape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const suggestPattern = (sig) => "^" + reEscape(sig) + "$";

// ignoreDialog proposes an ignore rule from a signature, previews what it would hide, and saves it.
function ignoreDialog(signature, component, onSaved) {
  const dlg = h("dialog", { class: "ignore-dialog", "aria-label": "Ignore this error" });
  const pattern = h("input", { value: suggestPattern(signature), spellcheck: "false", "aria-label": "Pattern (regular expression)" });
  const note = h("input", { placeholder: "Why it's safe to ignore (shown with the rule)", "aria-label": "Note" });
  const preview = h("div", { "aria-live": "polite", class: "preview" });
  const save = h("button", { class: "primary" }, "Add ignore rule");
  let timer = null;
  const test = async () => {
    try {
      const r = await post("/api/ignore/test", { pattern: pattern.value });
      if (!r.valid) { fill(preview, h("p", { class: "err" }, r.error)); save.disabled = true; return; }
      save.disabled = false;
      fill(preview, h("p", { class: "muted" }, `Would hide ${r.total} error${r.total === 1 ? "" : "s"} from the last ${r.window}, across ${r.matches.length} message${r.matches.length === 1 ? "" : "s"}:`),
        h("ul", { class: "sigs" }, r.matches.map((m) => h("li", {}, h("span", { class: "n" }, m.count), h("span", {}, h("strong", {}, m.component), " ", m.signature, m.ignoredBy ? h("span", { class: "badge" }, "already ignored") : null)))));
    } catch (e) { fill(preview, h("p", { class: "err" }, e.message)); }
  };
  pattern.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(test, 250); });
  save.addEventListener("click", async () => {
    save.disabled = true;
    try { await post("/api/ignore", { pattern: pattern.value.trim(), note: note.value }); dlg.close(); toast("Ignore rule added"); onSaved && onSaved(); }
    catch (e) { toast(e.message, true); save.disabled = false; }
  });
  fill(dlg,
    h("h2", {}, "Ignore this error"),
    h("p", {}, `Matching ${component ? component + " " : ""}errors stop counting as problems, metrics and alerts. They stay in the log viewer under “Ignored lines”.`),
    h("label", {}, h("strong", {}, "Pattern"), h("span", { class: "muted" }, " (regular expression on the normalized message: ids, addresses and numbers are already replaced)"), pattern),
    h("label", {}, h("strong", {}, "Note"), note),
    preview,
    h("div", { class: "actions" }, h("button", { onclick: () => dlg.close() }, "Cancel"), " ", save));
  dlg.addEventListener("close", () => dlg.remove());
  document.body.append(dlg);
  dlg.showModal();
  test();
}

async function viewLogs() {
  await refreshState();
  const params = routeParams();
  const st = { comp: params.get("component") || "", pod: "", level: params.get("errors") ? "warn" : "", q: "", re: false, paused: false, lines: [], ignored: "hide", rule: "" };
  const comps = (app.state.workloads || []).map((w) => w.component);
  const pods = (app.state.workloads || []).flatMap((w) => (w.pods || []).map((p) => ({ name: p.name, comp: w.component, node: p.node })));
  const canIgnore = writable("operator");
  const out = h("div", { class: "log", role: "log", "aria-label": "Log lines", tabindex: "0" });
  const count = h("span", { class: "muted" });
  const matches = (l) => {
    if (st.rule) return l.ignoredBy === st.rule;
    if (st.ignored === "hide" && l.ignoredBy) return false;
    if (st.ignored === "only" && !l.ignoredBy) return false;
    if (st.level === "error" && l.level !== "error") return false;
    if (st.level === "warn" && l.level !== "error" && l.level !== "warn") return false;
    if (st.q) { try { if (st.re ? !new RegExp(st.q, "i").test(l.raw) : !l.raw.toLowerCase().includes(st.q.toLowerCase())) return false; } catch { return false; } }
    return true;
  };
  const row = (l) => h("div", { class: "l " + l.level + (l.ignoredBy ? " ignored" : "") },
    h("span", { class: "t", title: l.time }, l.time ? new Date(l.time).toLocaleTimeString([], { hour12: false }) : ""),
    h("span", { class: "p" }, l.component + " " + l.pod.slice(-5)),
    h("span", {}, l.message || l.raw,
      l.ignoredBy ? h("span", { class: "badge", title: "Hidden by ignore rule " + l.ignoredBy }, "ignored") : null,
      l.signature && !l.ignoredBy && canIgnore ? h("button", { class: "link ign-btn", onclick: () => ignoreDialog(l.signature, l.component, reload) }, "Ignore…") : null));
  const redraw = () => { fill(out, ...st.lines.filter(matches).slice(-2000).map(row)); out.scrollTop = out.scrollHeight; count.textContent = `${st.lines.length} lines`; };
  // #/logs?follow=0 shows the last 15 minutes once, without a live stream (a frozen view).
  const follow = params.get("follow") !== "0";
  const loadOnce = async () => {
    const q = new URLSearchParams({ since: "15m" });
    if (st.comp) q.set("component", st.comp);
    if (st.pod) q.set("pod", st.pod);
    st.lines = (await get("/api/logs?" + q).catch(() => [])) || [];
    redraw();
  };
  const connect = () => {
    if (!follow) return loadOnce();
    if (app.stream) app.stream.close();
    st.lines = []; redraw();
    const q = new URLSearchParams({ tail: "300" });
    if (st.comp) q.set("component", st.comp);
    if (st.pod) q.set("pod", st.pod);
    const es = new EventSource("/api/logs/stream?" + q);
    app.stream = es;
    // Each pod's backlog arrives as a burst; collect it briefly and sort by time before showing.
    let warm = true;
    setTimeout(() => { warm = false; st.lines.sort((a, b) => (a.time || "").localeCompare(b.time || "")); redraw(); }, 1500);
    es.onmessage = (ev) => {
      const l = JSON.parse(ev.data);
      st.lines.push(l);
      if (st.lines.length > 5000) st.lines.splice(0, st.lines.length - 5000);
      if (warm) { count.textContent = `${st.lines.length} lines`; return; }
      if (!st.paused && matches(l)) {
        const nearBottom = out.scrollHeight - out.scrollTop - out.clientHeight < 60;
        out.append(row(l));
        if (out.childElementCount > 2000) out.firstElementChild.remove();
        if (nearBottom) out.scrollTop = out.scrollHeight;
      }
      count.textContent = `${st.lines.length} lines`;
    };
    es.addEventListener("end", () => es.close());
    es.onerror = () => { count.textContent = "Disconnected. Reconnecting…"; };
  };
  // After a rule change: rescan (so lines and counts are re-tagged), then rebuild the page.
  const reload = async () => { await post("/api/scan").catch(() => {}); render(); };
  const field = (label, el) => h("label", {}, h("span", { class: "muted" }, label), el);
  const ignoredSel = h("select", { onchange: (e) => { st.ignored = e.target.value; st.rule = ""; ruleNote.hidden = true; redraw(); } },
    h("option", { value: "hide" }, "Hide"), h("option", { value: "show" }, "Show"), h("option", { value: "only" }, "Only ignored"));
  const ruleNote = h("p", { class: "banner info", hidden: true });
  const showRule = (pattern) => {
    st.rule = pattern; st.comp = ""; ignoredSel.value = "only";
    fill(ruleNote, "Showing lines hidden by ", h("code", {}, pattern), ". ", h("button", { class: "link", onclick: () => { st.rule = ""; st.ignored = "hide"; ignoredSel.value = "hide"; ruleNote.hidden = true; redraw(); } }, "Clear"));
    ruleNote.hidden = false;
    connect();
    out.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  const controls = h("div", { class: "log-controls" },
    field("Component", h("select", { onchange: (e) => { st.comp = e.target.value; connect(); } }, h("option", { value: "" }, "All"), comps.map((c) => h("option", { value: c, selected: c === st.comp ? true : null }, c)))),
    field("Pod", h("select", { onchange: (e) => { st.pod = e.target.value; connect(); } }, h("option", { value: "" }, "All"), pods.map((p) => h("option", { value: p.name }, `${p.comp} on ${p.node}`)))),
    field("Level", h("select", { onchange: (e) => { st.level = e.target.value; redraw(); } }, h("option", { value: "" }, "All"), h("option", { value: "warn", selected: st.level === "warn" ? true : null }, "Warnings and errors"), h("option", { value: "error" }, "Errors"))),
    field("Ignored lines", ignoredSel),
    field("Search", h("input", { type: "search", spellcheck: "false", oninput: (e) => { st.q = e.target.value; redraw(); } })),
    h("label", { class: "check" }, h("input", { type: "checkbox", onchange: (e) => { st.re = e.target.checked; redraw(); } }), "Regex"),
    h("div", {}, follow ? h("button", { onclick: (e) => { st.paused = !st.paused; e.target.textContent = st.paused ? "Resume" : "Pause"; if (!st.paused) redraw(); } }, "Pause") : null, " ",
      h("a", { class: "btn", href: "/api/logs?format=text&since=1h" + (st.comp ? "&component=" + encodeURIComponent(st.comp) : "") }, "Download 1h")));

  const sigs = (app.state.logs || []).slice(0, 12);
  const ign = await get("/api/ignore").catch(() => ({ rules: [], window: "1h", readOnly: true }));
  const window = ign.window;
  const ruleRows = (ign.rules || []).map((r) => h("tr", {},
    h("td", {}, h("code", { class: "pattern" }, r.pattern), r.note ? h("div", { class: "muted" }, r.note) : null),
    h("td", {}, h("span", { class: "badge" + (r.source === "config" ? "" : " es") }, r.source === "config" ? "config file" : "console"),
      r.createdBy ? h("div", { class: "muted" }, `${r.createdBy}, ${new Date(r.createdAt).toLocaleDateString()}`) : null),
    h("td", { class: "num" }, r.hidden),
    h("td", {}, r.hidden ? h("button", { class: "link", onclick: () => showRule(r.pattern) }, "Show lines") : null,
      r.source === "console" && canIgnore && !ign.readOnly ? [" ", h("button", { class: "link", onclick: async () => {
        if (!confirm("Remove this ignore rule? Matching errors count as problems and alerts again.")) return;
        try { await post("/api/ignore/remove", { pattern: r.pattern }); toast("Ignore rule removed"); reload(); } catch (e) { toast(e.message, true); }
      } }, "Remove")] : null)));
  setTimeout(connect, 0);
  const events = h("div");
  get("/api/events").then((ev) => fill(events, ev.length ? h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["When", "Type", "Object", "Reason", "Message"].map((x) => h("th", {}, x)))),
    h("tbody", {}, ev.slice(0, 50).map((e) => h("tr", {}, h("td", {}, ago(e.time)), h("td", { class: e.type === "Warning" ? "state warning" : "" }, e.type), h("td", { class: "mono" }, e.object), h("td", {}, e.reason), h("td", {}, e.message)))))) : h("p", { class: "muted" }, "No recent events."))).catch(() => {});
  return [
    topline("Logs", follow ? "Live from every integration pod." : "The last 15 minutes from every integration pod.", count),
    h("h3", {}, `Recurring errors in the last ${window}`),
    sigs.length ? h("ul", { class: "sigs" }, sigs.map((s) => h("li", {},
      h("span", { class: "n" }, s.count),
      h("span", { class: "grow" }, h("strong", {}, s.component), " ", h("button", { class: "link", onclick: () => { st.comp = s.component; st.level = "warn"; connect(); } }, s.signature)),
      canIgnore ? h("button", { class: "link", onclick: () => ignoreDialog(s.signature, s.component, reload) }, "Ignore…") : null)))
      : h("p", { class: "muted" }, "None outside the ignore rules."),
    h("h3", {}, "Ignore rules"),
    h("p", { class: "muted" }, "Errors matching these rules don't count as problems, metrics or alerts. Add one from any error line or recurring error with “Ignore…”. Rules from the config file (logs.ignore) are changed there."),
    ruleRows.length ? h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Pattern", "Source", `Hidden (${window})`, ""].map((x) => h("th", {}, x)))), h("tbody", {}, ruleRows)))
      : h("p", { class: "muted" }, "No ignore rules."),
    h("h3", {}, follow ? "Live logs" : "Recent logs"),
    controls, ruleNote, out,
    h("h3", {}, "Kubernetes events"), events,
  ];
}

// ---------- history ----------
async function viewHistory() {
  const hist = await get("/api/history");
  const rows = hist.map((r) => h("tr", {},
    h("td", { class: "num" }, r.n), h("td", {}, new Date(r.time).toLocaleString()), h("td", {}, r.user), h("td", {}, r.kind),
    h("td", {}, r.reason ? h("div", {}, r.reason) : null, h("ul", {}, (r.changes || []).map((c) => h("li", {}, `${c.object} ${c.field}: `, c.secret ? "secret value replaced" : h("span", {}, h("code", {}, c.old || "(empty)"), " to ", h("code", {}, c.new)))))),
    h("td", {}, writable("admin") ? h("button", { onclick: async () => {
      try { const r2 = await post(`/api/history/${r.n}/rollback`); review(r2.change, { title: `Undo change ${r.n}`, kind: "rollback", plan: r2.plan }); } catch (e) { toast(e.message, true); }
    } }, "Undo") : null)));
  return [
    topline("History", "Each change keeps the state before it, so it can be undone. Secret values are never stored.",
      writable("admin") && app.info.webhooks ? h("button", { onclick: async () => { try { const r = await post("/api/alerts/test"); toast(Object.entries(r).map(([k, v]) => `${k}: ${v}`).join("; ")); } catch (e) { toast(e.message, true); } } }, "Send test alert") : null),
    hist.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["#", "When", "Who", "Kind", "What changed", ""].map((x) => h("th", {}, x)))), h("tbody", {}, rows)))
      : h("p", { class: "muted" }, "No changes have been made from this console yet."),
  ];
}

// ---------- review drawer ----------
function diffBlock(text) {
  return h("pre", { class: "diff" }, text.split("\n").map((line) => h("span", { class: line.startsWith("@@") ? "hunk" : line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : null }, line + "\n")));
}

async function review(change, opts) {
  const close = () => { scrim.remove(); drawer.remove(); document.removeEventListener("keydown", esc); };
  const esc = (e) => { if (e.key === "Escape") close(); };
  const scrim = h("div", { class: "scrim", onclick: close });
  const body = h("div", { class: "body" }, h("p", {}, "Checking the change…"));
  const foot = h("footer", {});
  const drawer = h("aside", { class: "drawer", role: "dialog", "aria-modal": "true", "aria-label": opts.title },
    h("header", {}, h("h2", {}, opts.title), h("button", { onclick: close, "aria-label": "Close" }, "Close")), body, foot);
  document.body.append(scrim, drawer);
  document.addEventListener("keydown", esc);
  drawer.querySelector("header button").focus();
  let plan = opts.plan;
  try { if (!plan) plan = await post("/api/plan", change); } catch (e) { fill(body, h("p", { class: "err" }, e.message)); return; }
  const draw = () => {
    const f = (list, label) => list && list.length ? [h("h3", {}, label), findingsList(list, null)] : null;
    fill(body, 
      plan.empty ? h("p", {}, "Nothing to change: the cluster already matches.") : null,
      plan.blocked ? h("div", { class: "banner crit" }, "Blocked: " + plan.blockReason) : null,
      (plan.notes || []).map((n) => h("div", { class: "banner info" }, n)),
      plan.changes && plan.changes.length ? [h("h3", {}, "Changes"), h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, plan.changes.map((c) => h("tr", {}, h("td", {}, c.object, h("div", { class: "muted" }, c.field)), h("td", {}, h("code", {}, c.old || "(empty)")), h("td", {}, h("code", {}, c.new))))))) ] : null,
      plan.restarts && plan.restarts.length ? [h("h3", {}, "Restarts"), h("ul", {}, plan.restarts.map((r) => h("li", {}, `${r.kind} ${r.name.replace(/^extrahop-kubernetes-integration-/, "")}: ${r.why.join(", ")}`, r.rolls ? " (pod template changes)" : "")))] : null,
      f(plan.introduced, "New problems this change creates"),
      f(plan.resolved, "Problems this change fixes"),
      (plan.diffs || []).map((d) => [h("h3", {}, `${d.kind} ${d.name}`), diffBlock(d.diff)]));
    const force = plan.blocked && can("admin") ? h("label", { class: "check" }, h("input", { type: "checkbox", onchange: async (e) => {
      change = { ...change, force: e.target.checked }; plan = await post("/api/plan", change); draw();
    } }), "Apply anyway") : null;
    const role = plan.requiredRole || "admin";
    const allowed = writable(role);
    const label = plan.restarts && plan.restarts.length ? `Apply and restart ${plan.restarts.length}` : "Apply";
    fill(foot, h("span", { class: "grow" }, !allowed ? (app.info.readOnly ? "Read-only console." : `Needs the ${role} role.`) : plan.restarts && plan.restarts.length ? "Pods restart one by one; the forwarders may restart with the coordinator." : ""),
      force, h("button", { onclick: close }, "Cancel"),
      h("button", { class: "primary", disabled: !allowed || plan.empty || (plan.blocked && !change.force) || null, onclick: doApply }, label));
  };
  const doApply = async (e) => {
    e.target.disabled = true;
    try {
      const res = await post("/api/apply", { change, hash: plan.hash, kind: opts.kind || "apply" });
      if (opts.clearPending) app.pending = newPending();
      showProgress(res);
    } catch (x) {
      if (x.status === 409 && x.data && x.data.plan) { plan = x.data.plan; draw(); toast(x.message, true); return; }
      toast(x.message, true); e.target.disabled = false;
    }
  };
  const showProgress = (res) => {
    const list = h("ul", { class: "progress" });
    fill(body, h("p", { class: "state ok" }, `Applied as revision ${res.revision}.`), res.restarted && res.restarted.length ? [h("h3", {}, "Rollout"), list] : null);
    fill(foot, h("span", { class: "grow" }), h("button", { class: "primary", onclick: () => { close(); render(); } }, "Done"));
    if (!res.restarted || !res.restarted.length) return;
    const started = Date.now();
    const poll = async () => {
      const st = await get("/api/rollout?names=" + encodeURIComponent(res.restarted.join(","))).catch(() => []);
      fill(list, ...st.map((r) => h("li", {}, h("span", {}, r.name.replace(/^extrahop-kubernetes-integration-/, "")),
        h("span", { class: "state " + (r.failed ? "critical" : r.done ? "ok" : "warning") }, r.failed ? "Failed: " + r.message : r.done ? "Done" : `${r.updated}/${r.desired} updated, ${r.ready} ready`))));
      if (st.length && st.every((r) => r.done)) { toast("Rollout finished"); return; }
      if (st.some((r) => r.failed) || Date.now() - started > 10 * 60000) { toast("Rollout did not finish. Check the logs, or undo the change from History.", true); return; }
      if (document.body.contains(list)) setTimeout(poll, 3000);
    };
    poll();
  };
  draw();
}

// ---------- start ----------
async function start() {
  try { app.me = await get("/auth/me"); } catch { renderSignIn(); return; }
  app.info = await get("/api/info");
  await loadSettings().catch(() => {}); // the brand block shows the cluster name on every page
  window.addEventListener("hashchange", render);
  render();
}
start();
