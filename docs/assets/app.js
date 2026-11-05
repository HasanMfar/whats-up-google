/* Workbench behaviour.
 *
 * Everything here runs in the tab: decoding, parsing, filtering, inspecting and
 * exporting. The only network calls are to the loopback bridge, which exists
 * because an Xray probe needs real sockets and a process - things a tab cannot
 * do. See the "What runs where" table on the page.
 */
import { nodeKey, parseAny, parseLinks, dedupe } from "./parse.js";
import { CHECK_LABELS, CHECK_ORDER, buildTiers, checkTally, summarize } from "./tiers.js";
import { getLang, setLang, t } from "./i18n.js";

const $ = (id) => document.getElementById(id);

const VERDICTS = ["CLEAN", "FLAGGED", "DEAD", "ERROR", "PENDING", "UNSCANNED"];
const VERDICT_CLASS = {
  CLEAN: "is-clean",
  FLAGGED: "is-flagged",
  DEAD: "is-dead",
  ERROR: "is-error",
  PENDING: "is-pending",
  UNSCANNED: "is-unscanned",
};
const COLUMNS = [
  { key: "index", label: "col.index", sortable: true, cls: "row-index" },
  { key: "remark", label: "col.remark", sortable: true, cls: "wide" },
  { key: "protocol", label: "col.protocol", sortable: true },
  { key: "server", label: "col.server", sortable: true, cls: "wide" },
  { key: "id", label: "col.id", sortable: false, cls: "dim" },
  { key: "country", label: "col.country", sortable: true },
  { key: "latency", label: "col.latency", sortable: true },
  { key: "channels", label: "col.channels", sortable: false },
  { key: "verdict", label: "col.verdict", sortable: true },
];
const PLACEHOLDERS = {
  "paste-input": "load.placeholder",
  "report-input": "load.report.placeholder",
  "url-input": "load.url.placeholder",
  "search-input": "probe.search",
};

const state = {
  nodes: [],
  rows: [],
  byKey: new Map(),
  source: "",
  loadedStats: null,
  filters: { q: "", verdict: "all", proto: "all", net: "all" },
  sort: { key: "index", dir: "asc" },
  visibleLimit: 200,
  selectedKey: null,
  lang: "en",
  bridge: {
    url: "http://127.0.0.1:8787",
    token: "",
    online: false,
    xray: "",
    checking: false,
  },
  job: null,
  scannedCount: 0,
  toastTimer: null,
};

/* ------------------------------------------------------------------ helpers */

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
  });
}

function idPrefix(id, n = 10) {
  const s = String(id || "");
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("is-error", isError);
  el.classList.add("is-visible");
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => el.classList.remove("is-visible"), 3200);
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  }
}

function download(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

/* -------------------------------------------------------------------- i18n */

function applyStaticText() {
  const lang = state.lang;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "fa" ? "rtl" : "ltr";
  for (const el of document.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const [id, key] of Object.entries(PLACEHOLDERS)) {
    const el = $(id);
    if (el) el.placeholder = t(key);
  }
  $("lang-toggle").textContent = t("lang.switch");
  const probeIdle = $("probe-idle");
  if (!probeIdle.hidden) probeIdle.textContent = t("probe.idle");
  renderAll();
}

/* --------------------------------------------------------------- rendering */

function verdictLabel(verdict) {
  return t(`verdict.${verdict || "UNSCANNED"}`);
}

function renderSteps() {
  const done = {
    load: state.rows.length > 0,
    probe: state.scannedCount > 0,
    export: buildTiers(state.rows).some((tier) => tier.count > 0),
    about: false,
  };
  for (const el of document.querySelectorAll(".step")) {
    const key = el.dataset.step;
    el.classList.toggle("is-done", Boolean(done[key]));
    const activeKey = done.export ? "export" : done.probe ? "probe" : "load";
    el.classList.toggle("is-active", key === activeKey);
  }
}

function renderReadout() {
  const counts = summarize(state.rows);
  const total = counts.TOTAL;
  const ruler = $("ruler");
  const legend = $("readout-legend");

  if (!total) {
    $("readout-label").textContent = t("hero.readout.empty");
    $("readout-clean").textContent = "0";
    $("readout-total").textContent = "0";
    $("readout-unit").textContent = t("hero.readout.clean");
    ruler.innerHTML = Array.from({ length: 60 }, () => '<span class="ruler__tick"></span>').join("");
    $("ruler-mid").textContent = t("hero.readout.hint");
    $("ruler-end").textContent = "—";
    legend.innerHTML = "";
    return;
  }

  $("readout-label").textContent = t("hero.readout.tested");
  $("readout-clean").textContent = String(counts.CLEAN);
  $("readout-total").textContent = String(total);
  $("readout-unit").textContent = t("hero.readout.clean");
  $("ruler-mid").textContent = `${counts.FLAGGED} ${verdictLabel("FLAGGED").toLowerCase()}`;
  $("ruler-end").textContent = `${total} ${t("hero.readout.tested")}`;

  // 60 proportional ticks: the bar reads like a ruler, not a rounded progress pill.
  const order = ["CLEAN", "FLAGGED", "DEAD", "ERROR", "PENDING", "UNSCANNED"];
  const marks = [];
  let acc = 0;
  for (const verdict of order) {
    acc += (counts[verdict] || 0) / total;
    marks.push({ until: acc, verdict });
  }
  const ticks = 60;
  let html = "";
  for (let i = 0; i < ticks; i += 1) {
    const point = (i + 0.5) / ticks;
    const hit = marks.find((mark) => point <= mark.until) || marks[marks.length - 1];
    const cls = hit.verdict === "CLEAN" ? "is-clean" : hit.verdict === "FLAGGED" ? "is-flagged" : hit.verdict === "DEAD" ? "is-dead" : hit.verdict === "ERROR" ? "is-error" : "";
    html += `<span class="ruler__tick ${cls}"></span>`;
  }
  ruler.innerHTML = html;

  const legendParts = [];
  for (const verdict of order) {
    if (!counts[verdict]) continue;
    const cls = verdict === "CLEAN" ? "clean" : verdict === "FLAGGED" ? "flagged" : verdict === "DEAD" ? "dead" : "idle";
    legendParts.push(
      `<span class="legend-key ${cls}">${counts[verdict]} ${escapeHtml(verdictLabel(verdict))}</span>`,
    );
  }
  legend.innerHTML = legendParts.join("");
}

function renderSummary() {
  const counts = summarize(state.rows);
  const strip = $("summary-strip");
  if (!state.scannedCount) {
    strip.hidden = true;
    return;
  }
  strip.hidden = false;
  const cells = [
    [t("hero.readout.tested"), counts.TOTAL, ""],
    [verdictLabel("CLEAN"), counts.CLEAN, "is-clean"],
    [verdictLabel("FLAGGED"), counts.FLAGGED, "is-flagged"],
    [verdictLabel("DEAD"), counts.DEAD, "is-dead"],
    [verdictLabel("ERROR"), counts.ERROR, ""],
    [verdictLabel("UNSCANNED"), (counts.PENDING || 0) + (counts.UNSCANNED || 0), ""],
  ];
  strip.innerHTML = cells
    .map(
      ([label, value, cls]) => `
      <div class="summary-strip__cell ${cls}">
        <span class="summary-strip__value">${value}</span>
        <span class="summary-strip__label">${escapeHtml(label)}</span>
      </div>`,
    )
    .join("");
}

function renderTally() {
  const el = $("tally");
  if (!state.scannedCount) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  const tally = checkTally(state.rows);
  el.innerHTML = CHECK_ORDER.map((name) => {
    const entry = tally[name];
    const tested = entry.tested || 1;
    const passPct = (entry.pass / tested) * 100;
    const failPct = (entry.fail / tested) * 100;
    const errPct = (entry.err / tested) * 100;
    return `
      <div class="tally__item">
        <div class="tally__head">
          <span>${escapeHtml(CHECK_LABELS[name])}</span>
          <span>${entry.pass}/${entry.tested}</span>
        </div>
        <div class="tally__bar">
          <span class="is-pass" style="width:${passPct}%"></span>
          <span class="is-fail" style="width:${failPct}%"></span>
          <span class="is-err" style="width:${errPct}%"></span>
        </div>
      </div>`;
  }).join("");
}

function renderToolbarOptions() {
  const verdictSelect = $("verdict-filter");
  const currentVerdict = state.filters.verdict;
  verdictSelect.innerHTML = [
    `<option value="all">${escapeHtml(t("probe.filter.all"))}</option>`,
    ...VERDICTS.map(
      (v) => `<option value="${v}">${escapeHtml(verdictLabel(v))}</option>`,
    ),
  ].join("");
  verdictSelect.value = currentVerdict;

  const protocols = [...new Set(state.rows.map((r) => r.node.protocol))].sort();
  const protoSelect = $("proto-filter");
  protoSelect.innerHTML = [
    `<option value="all">${escapeHtml(t("probe.all"))}</option>`,
    ...protocols.map((p) => `<option value="${escapeHtml(p)}">${escapeHtml(p)}</option>`),
  ].join("");
  if (!protocols.includes(state.filters.proto)) state.filters.proto = "all";
  protoSelect.value = state.filters.proto;

  const nets = [...new Set(state.rows.map((r) => r.node.network || "tcp"))].sort();
  const netSelect = $("net-filter");
  netSelect.innerHTML = [
    `<option value="all">${escapeHtml(t("probe.all"))}</option>`,
    ...nets.map((n) => `<option value="${escapeHtml(n)}">${escapeHtml(n)}</option>`),
  ].join("");
  if (!nets.includes(state.filters.net)) state.filters.net = "all";
  netSelect.value = state.filters.net;
}

function visibleRows() {
  const { q, verdict, proto, net } = state.filters;
  const needle = q.trim().toLowerCase();
  let rows = state.rows.filter((row) => {
    if (verdict !== "all") {
      const v = row.verdict || "UNSCANNED";
      if (verdict === "PENDING" ? !(v === "PENDING" || v === "UNSCANNED") : v !== verdict) return false;
    }
    if (proto !== "all" && row.node.protocol !== proto) return false;
    if (net !== "all" && (row.node.network || "tcp") !== net) return false;
    if (!needle) return true;
    const hay = `${row.node.remark} ${row.node.server} ${row.node.id} ${row.node.protocol}`.toLowerCase();
    return hay.includes(needle);
  });

  const dir = state.sort.dir === "asc" ? 1 : -1;
  const key = state.sort.key;
  const value = (row) => {
    switch (key) {
      case "remark":
        return (row.node.remark || "").toLowerCase();
      case "protocol":
        return row.node.protocol;
      case "server":
        return `${row.node.server}:${row.node.port}`;
      case "country":
        return (row.exit_ip && row.exit_ip.country_code) || "";
      case "latency":
        return row.latency_ms === null || row.latency_ms === undefined ? Infinity : row.latency_ms;
      case "verdict":
        return row.verdict || "UNSCANNED";
      default:
        return row.order;
    }
  };
  rows = rows.slice().sort((a, b) => {
    const av = value(a);
    const bv = value(b);
    if (av === bv) return a.order - b.order;
    if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
    return String(av).localeCompare(String(bv)) * dir;
  });
  return rows;
}

function channelCells(row) {
  const cells = [];
  for (const name of CHECK_ORDER) {
    const res = row.results ? row.results[name] : null;
    let cls = "is-off";
    let symbol = "·";
    let label = "not tested";
    if (res) {
      if (res.ok === true) {
        cls = "is-pass";
        symbol = "";
        label = "passed";
      } else if (res.ok === false) {
        cls = "is-flagged";
        symbol = "";
        label = "blocked";
      } else {
        cls = "is-error";
        symbol = "!";
        label = "error";
      }
    } else if (row.verdict === "DEAD") {
      cls = "is-dead";
      symbol = "×";
      label = "no response";
    }
    cells.push(
      `<span class="ladder__cell ${cls}" title="${escapeHtml(name)}: ${escapeHtml(label)}" aria-label="${escapeHtml(name)} ${escapeHtml(label)}">${symbol}</span>`,
    );
  }
  return `<span class="ladder">${cells.join("")}</span>`;
}

function renderTableHead() {
  $("table-head").innerHTML = COLUMNS.map((col) => {
    const ariaSort =
      state.sort.key === col.key ? `aria-sort="${state.sort.dir === "asc" ? "ascending" : "descending"}"` : "";
    return `<th data-col="${col.key}" data-sortable="${col.sortable}" ${ariaSort}>${escapeHtml(t(col.label))}</th>`;
  }).join("");
}

function renderTable() {
  const wrap = $("table-wrap");
  const toolbar = $("toolbar");
  const foot = $("table-foot");
  const empty = $("empty-state");

  $("probe-idle").hidden = state.rows.length > 0;

  if (!state.rows.length) {
    wrap.hidden = true;
    toolbar.hidden = true;
    foot.hidden = true;
    empty.hidden = true; // the idle note above already says this
    return;
  }

  toolbar.hidden = false;
  const rows = visibleRows();
  renderTableHead();

  if (!rows.length) {
    wrap.hidden = true;
    foot.hidden = true;
    empty.hidden = false;
    empty.textContent = t("probe.empty.filtered");
    return;
  }

  empty.hidden = true;
  wrap.hidden = false;
  foot.hidden = false;

  const shown = rows.slice(0, state.visibleLimit);
  $("table-body").innerHTML = shown
    .map((row) => {
      const node = row.node;
      const country = (row.exit_ip && row.exit_ip.country_code) || "—";
      const latency = row.latency_ms === null || row.latency_ms === undefined ? "—" : row.latency_ms;
      const verdict = row.verdict || "UNSCANNED";
      return `
        <tr data-key="${escapeHtml(row.key)}" tabindex="0" class="${row.key === state.selectedKey ? "is-selected" : ""}">
          <td class="row-index">${row.order + 1}</td>
          <td class="wide" title="${escapeHtml(node.remark || "")}">${escapeHtml(node.remark || "—")}</td>
          <td>${escapeHtml(node.protocol)}</td>
          <td class="wide" title="${escapeHtml(`${node.server}:${node.port}`)}">${escapeHtml(node.server)}:${node.port}</td>
          <td class="dim">${escapeHtml(idPrefix(node.id))}</td>
          <td class="country">${escapeHtml(country)}</td>
          <td>${latency}</td>
          <td>${channelCells(row)}</td>
          <td><span class="badge ${VERDICT_CLASS[verdict] || "is-unscanned"}">${escapeHtml(verdictLabel(verdict))}</span></td>
        </tr>`;
    })
    .join("");

  $("showing").textContent = t("probe.showing", { shown: shown.length, total: rows.length });
  const moreBtn = $("more-btn");
  if (rows.length > shown.length) {
    moreBtn.hidden = false;
    moreBtn.textContent = t("probe.more", { n: Math.min(200, rows.length - shown.length) });
  } else {
    moreBtn.hidden = true;
  }
}

function renderTiers() {
  const tiers = buildTiers(state.rows);
  const grid = $("tier-grid");
  grid.innerHTML = tiers
    .map((tier) => {
      const primary = tier.key === "best" ? "tier--primary" : "";
      const empty = tier.count === 0 ? "is-empty" : "";
      return `
        <div class="tier ${primary} ${empty}">
          <div class="tier__head">
            <span class="tier__name">${escapeHtml(t(`export.tier.${tier.key}.name`))}</span>
            <span class="tier__count">${tier.count ? escapeHtml(t(tier.count === 1 ? "export.config" : "export.configs", { n: tier.count })) : escapeHtml(t("export.none"))}</span>
          </div>
          <p class="tier__desc">${escapeHtml(t(`export.tier.${tier.key}.desc`))}</p>
          <div class="tier__actions">
            <button class="btn btn--solid" data-download="${tier.key}" ${tier.count ? "" : "disabled"}>
              ${escapeHtml(t("export.download"))}
            </button>
            <button class="btn btn--quiet" data-copy="${tier.key}" ${tier.count ? "" : "disabled"} title="${escapeHtml(t("export.copy"))}">
              ${escapeHtml(t("export.copy"))}
            </button>
          </div>
        </div>`;
    })
    .join("");
  $("export-note").hidden = state.scannedCount > 0;
}

function renderBridge() {
  const { online, xray, checking } = state.bridge;
  $("bridge-state").textContent = checking
    ? `${t("bridge.title")} · ${t("bridge.state.checking")}`
    : online
      ? `${t("bridge.title")} · ${t("bridge.state.online", { version: xray || "—" })}`
      : `${t("bridge.title")} · ${t("bridge.state.offline")}`;
  const dot = $("bridge-dot");
  dot.classList.toggle("is-online", online && !state.job);
  dot.classList.toggle("is-busy", Boolean(state.job));
  $("bridge-toggle").textContent = online ? t("bridge.disconnect") : t("bridge.connect");
  $("fetch-urls-btn").disabled = !online;
  $("url-note").innerHTML = online
    ? `<span>${escapeHtml(t("load.url.bridge_only"))}</span>`
    : `<span>${escapeHtml(t("load.url.need_bridge"))}</span>`;
  renderScanButton();
}

function renderScanButton() {
  const btn = $("scan-btn");
  const hasRows = state.rows.length > 0;
  if (state.job) {
    btn.disabled = true;
    btn.textContent = t("probe.running", { done: state.scannedCount, total: state.job.total });
    $("cancel-btn").hidden = false;
    return;
  }
  $("cancel-btn").hidden = true;
  btn.disabled = !hasRows || !state.bridge.online;
  if (!hasRows) btn.textContent = t("probe.start_disabled");
  else if (!state.bridge.online) btn.textContent = t("probe.need_bridge");
  else btn.textContent = t("probe.start", { n: Math.min(state.rows.length, 3000) });
}

function renderProgress() {
  const box = $("progress");
  if (!state.job) {
    box.hidden = true;
    return;
  }
  box.hidden = false;
  const total = state.job.total || 1;
  const pct = Math.min(100, Math.round((state.scannedCount / total) * 100));
  $("progress-fill").style.width = `${pct}%`;
  $("progress-text").textContent = t("probe.running", {
    done: state.scannedCount,
    total: state.job.total,
  });
  $("progress-pct").textContent = `${pct}%`;
}

function renderAll() {
  renderSteps();
  renderReadout();
  renderSummary();
  renderTally();
  renderToolbarOptions();
  renderTable();
  renderTiers();
  renderBridge();
  renderProgress();
  $("probe-count-note").textContent = state.rows.length
    ? t(state.rows.length === 1 ? "export.config" : "export.configs", { n: state.rows.length })
    : "";
  $("probe").classList.toggle("is-scanning", Boolean(state.job));
}

/* ------------------------------------------------------------------ loading */

function setLoadStatus(message, isError = false) {
  const el = $("load-status");
  if (!message) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  el.textContent = message;
  el.classList.toggle("note--warn", isError);
}

function adoptNodes(nodes, source, extraNote = "") {
  const { nodes: unique, duplicates } = dedupe(nodes);
  state.nodes = unique;
  state.rows = unique.map((node, order) => ({
    order,
    key: nodeKey(node),
    node,
    results: {},
    exit_ip: {},
    latency_ms: null,
    verdict: "UNSCANNED",
    error: "",
    tested_at: "",
  }));
  state.byKey = new Map(state.rows.map((row) => [row.key, row]));
  state.source = source;
  state.scannedCount = 0;
  state.visibleLimit = 200;
  state.filters = { q: "", verdict: "all", proto: "all", net: "all" };
  $("search-input").value = "";
  const parts = [t("load.loaded", { n: unique.length, source })];
  if (duplicates) parts.push(t("load.dupes", { n: duplicates }));
  if (extraNote) parts.push(extraNote);
  setLoadStatus(parts.join(" · "));
  renderAll();
}

function adoptReport(payload) {
  const rows = (payload.rows || []).map((row, order) => ({ ...row, order }));
  if (!rows.length) throw new Error("That report contains no results.");
  state.nodes = rows.map((row) => row.node);
  state.rows = rows;
  state.byKey = new Map(rows.map((row) => [row.key, row]));
  state.scannedCount = rows.filter((row) => row.verdict && row.verdict !== "PENDING").length;
  state.source = "scan report";
  state.visibleLimit = 200;
  setLoadStatus(
    t("load.loaded", { n: rows.length, source: "scan report" }) +
      (payload.report && payload.report.generated ? ` · ${payload.report.generated}` : ""),
  );
  renderAll();
}

function handleInput(text, source) {
  try {
    const result = parseAny(text, source);
    if (result.kind === "report") {
      adoptReport(result);
    } else {
      if (!result.nodes.length) {
        setLoadStatus(t("load.empty"), true);
        return;
      }
      const note = result.stats.badLines ? t("load.badlines", { n: result.stats.badLines }) : "";
      adoptNodes(result.nodes, source, note);
    }
  } catch (e) {
    setLoadStatus(e.message || String(e), true);
    toast(e.message || String(e), true);
  }
}

function readFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => handleInput(String(reader.result || ""), file.name);
  reader.onerror = () => toast(`Could not read ${file.name}`, true);
  reader.readAsText(file);
}

/* ------------------------------------------------------------------- bridge */

function bridgeBase() {
  return state.bridge.url.replace(/\/+$/, "");
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", "X-Scanner-Token": state.bridge.token };
  const response = await fetch(`${bridgeBase()}${path}`, { ...options, headers });
  if (response.status === 403) throw new Error(t("bridge.bad_token"));
  const text = await response.text();
  let payload = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const detail = (payload && (payload.error || payload.detail)) || `HTTP ${response.status}`;
    throw new Error(detail);
  }
  return payload;
}

async function connectBridge({ quiet = false } = {}) {
  state.bridge.url = $("bridge-url").value.trim() || "http://127.0.0.1:8787";
  state.bridge.token = $("bridge-token").value.trim();
  state.bridge.checking = true;
  renderBridge();
  try {
    const pong = await api("/api/ping");
    state.bridge.online = true;
    state.bridge.xray = (pong && pong.xray && pong.xray.version) || "";
    localStorage.setItem("wug.bridge.url", state.bridge.url);
    localStorage.setItem("wug.bridge.token", state.bridge.token);
    $("bridge-form").hidden = true;
    if (!quiet) toast(t("bridge.state.online", { version: state.bridge.xray || "—" }));
  } catch (e) {
    state.bridge.online = false;
    const unreachable = e instanceof TypeError || /Failed to fetch|NetworkError/i.test(e.message);
    if (!quiet) toast(unreachable ? t("bridge.unreachable") : e.message, true);
  } finally {
    state.bridge.checking = false;
    renderAll();
  }
}

async function fetchSubscriptionUrls() {
  const urls = $("url-input").value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  if (!urls.length) {
    toast("Paste at least one subscription URL.", true);
    return;
  }
  const btn = $("fetch-urls-btn");
  btn.disabled = true;
  btn.textContent = "…";
  try {
    const payload = await api("/api/fetch-subs", {
      method: "POST",
      body: JSON.stringify({ urls }),
    });
    const nodes = [];
    const problems = [];
    for (const result of payload.results || []) {
      if (result.status === "ok" || (result.nodes && result.nodes.length)) {
        nodes.push(...(result.nodes || []));
      } else {
        problems.push(`${result.url} — ${result.detail || result.status}`);
      }
    }
    if (!nodes.length) throw new Error(problems.join(" · ") || t("load.empty"));
    adoptNodes(nodes, `${urls.length} subscription URL${urls.length > 1 ? "s" : ""}`);
    if (problems.length) setLoadStatus(problems.join(" · "), true);
  } catch (e) {
    toast(e.message, true);
  } finally {
    btn.textContent = t("load.url.fetch");
    btn.disabled = !state.bridge.online;
  }
}

const SCAN_CAP = 3000;

function selectedChecks() {
  const checks = {};
  for (const checkbox of document.querySelectorAll("#check-group input[type=checkbox]")) {
    checks[checkbox.value] = checkbox.checked;
  }
  return checks;
}

async function startScan() {
  const checks = selectedChecks();
  if (!Object.values(checks).some(Boolean)) {
    toast("Select at least one check.", true);
    return;
  }
  const targets = state.rows.slice(0, SCAN_CAP);
  if (state.rows.length > SCAN_CAP) {
    toast(`Probing the first ${SCAN_CAP} of ${state.rows.length} configs.`);
  }
  try {
    const payload = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({
        links: targets.map((row) => row.node.raw),
        checks,
        concurrency: Number($("concurrency").value) || 20,
      }),
    });
    state.job = { id: payload.job_id, total: payload.total, status: "running" };
    state.scannedCount = 0;
    renderAll();
    pollJob();
  } catch (e) {
    toast(e.message, true);
  }
}

async function pollJob() {
  if (!state.job) return;
  const job = state.job;
  try {
    const payload = await api(`/api/job/${job.id}?since=${job.since || 0}`);
    job.since = payload.since;
    for (const row of payload.rows || []) {
      const key = nodeKey(row.node);
      const target = state.byKey.get(key);
      if (!target) continue;
      target.results = row.results || {};
      target.exit_ip = row.exit_ip || {};
      target.latency_ms = row.latency_ms ?? null;
      target.verdict = row.verdict || "ERROR";
      target.error = row.error || "";
      target.tested_at = row.tested_at || "";
      state.scannedCount += 1;
    }
    job.total = payload.total ?? job.total;
    job.status = payload.status;
    renderAll();
    if (payload.status === "running") {
      setTimeout(pollJob, 700);
    } else {
      const finished = state.job;
      state.job = null;
      renderAll();
      if (finished.status === "cancelled") toast(t("probe.cancelled", { done: state.scannedCount, total: finished.total }));
      else toast(t("probe.done", { s: payload.elapsed ? Math.round(payload.elapsed) : 0 }));
    }
  } catch (e) {
    state.job = null;
    renderAll();
    toast(e.message, true);
  }
}

async function cancelScan() {
  if (!state.job) return;
  try {
    await api("/api/cancel", { method: "POST", body: JSON.stringify({ job_id: state.job.id }) });
  } catch (e) {
    toast(e.message, true);
  }
}

/* ------------------------------------------------------------------- drawer */

function openDrawer(key) {
  const row = state.byKey.get(key);
  if (!row) return;
  state.selectedKey = key;
  const node = row.node;
  const exitIp = row.exit_ip || {};
  const rows = [
    ["server", `${node.server}:${node.port}`],
    ["protocol", node.protocol],
    ["network", node.network || "tcp"],
    ["security", node.security || "none"],
    ["sni", node.sni],
    ["host", node.host],
    ["path", node.path],
    ["service", node.service_name],
    ["flow", node.flow],
    ["fp", node.fingerprint],
    ["pbk", node.public_key],
    ["sid", node.short_id],
    ["cipher", node.method || node.cipher],
    [t("detail.ip"), exitIp.ip],
    [t("detail.isp"), exitIp.isp],
    [t("detail.latency"), row.latency_ms === null || row.latency_ms === undefined ? "" : `${row.latency_ms} ms`],
    [t("detail.tested"), row.tested_at],
    [t("detail.error"), row.error],
  ]
    .filter(([, value]) => value !== "" && value !== undefined && value !== null)
    .map(([label, value]) => `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd>`)
    .join("");

  const checks = CHECK_ORDER.map((name) => {
    const res = row.results ? row.results[name] : null;
    let cls = "is-off";
    let label = "not tested";
    let detail = "";
    if (res) {
      cls = res.ok === true ? "is-pass" : res.ok === false ? "is-flagged" : "is-error";
      label = res.ok === true ? "passed" : res.ok === false ? "blocked" : "error";
      detail = res.detail ? `${res.detail}${res.status ? ` · ${res.status}` : ""}` : "";
    }
    return `<div class="check-line">
      <span class="check-line__name">${escapeHtml(CHECK_LABELS[name])}</span>
      <span class="check-line__detail">${escapeHtml(detail)}</span>
      <span class="check-line__state ${cls}">${escapeHtml(label)}</span>
    </div>`;
  }).join("");

  $("drawer-title").textContent = node.remark || t("detail.node");
  $("drawer-body").innerHTML = `
    <div style="margin-bottom:12px">
      <span class="badge ${VERDICT_CLASS[row.verdict || "UNSCANNED"]}">${escapeHtml(verdictLabel(row.verdict || "UNSCANNED"))}</span>
    </div>
    <dl class="detail-list">${rows || `<dt>${escapeHtml(t("detail.none"))}</dt><dd></dd>`}</dl>
    <div class="detail-section">
      <h4>${escapeHtml(t("detail.checks"))}</h4>
      ${checks}
    </div>
    <div class="detail-section">
      <h4>${escapeHtml(t("detail.raw"))}</h4>
      <pre class="raw-link">${escapeHtml(node.raw)}</pre>
    </div>`;

  $("drawer").classList.add("is-open");
  $("drawer").setAttribute("aria-hidden", "false");
  $("drawer-backdrop").classList.add("is-open");
  $("drawer-copy").dataset.key = key;
  renderTable();
}

function closeDrawer() {
  $("drawer").classList.remove("is-open");
  $("drawer").setAttribute("aria-hidden", "true");
  $("drawer-backdrop").classList.remove("is-open");
  state.selectedKey = null;
  renderTable();
}

/* -------------------------------------------------------------- interactions */

function selectTab(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    const active = tab.dataset.tab === name;
    tab.setAttribute("aria-selected", String(active));
    $(`panel-${tab.dataset.tab}`).hidden = !active;
  }
}

function wireEvents() {
  $("lang-toggle").addEventListener("click", () => {
    state.lang = setLang(getLang() === "en" ? "fa" : "en");
    localStorage.setItem("wug.lang", state.lang);
    applyStaticText();
  });

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => selectTab(tab.dataset.tab));
  }

  $("read-btn").addEventListener("click", () => {
    handleInput($("paste-input").value, "pasted links");
  });

  $("read-report-btn").addEventListener("click", () => {
    handleInput($("report-input").value, "scan report");
  });

  $("file-input").addEventListener("change", (event) => {
    readFile(event.target.files && event.target.files[0]);
    event.target.value = "";
  });

  document.addEventListener("dragover", (event) => {
    if (event.dataTransfer && [...event.dataTransfer.types].includes("Files")) event.preventDefault();
  });
  document.addEventListener("drop", (event) => {
    if (event.dataTransfer && event.dataTransfer.files.length) {
      event.preventDefault();
      readFile(event.dataTransfer.files[0]);
    }
  });

  $("fetch-urls-btn").addEventListener("click", fetchSubscriptionUrls);

  $("bridge-toggle").addEventListener("click", () => {
    if (state.bridge.online) {
      state.bridge.online = false;
      state.bridge.xray = "";
      $("bridge-form").hidden = false;
      renderAll();
      return;
    }
    if (state.bridge.token && state.bridge.url) {
      connectBridge();
      return;
    }
    $("bridge-form").hidden = false;
    $("bridge-token").focus();
  });

  $("bridge-token").addEventListener("keydown", (event) => {
    if (event.key === "Enter") connectBridge();
  });

  $("bridge-copy").addEventListener("click", async () => {
    const command = "python whats-up-google-bridge.pyz --serve";
    toast((await copyText(command)) ? t("bridge.get.copied") : "Copy failed", false);
  });

  $("scan-btn").addEventListener("click", startScan);
  $("cancel-btn").addEventListener("click", cancelScan);

  $("search-input").addEventListener("input", (event) => {
    state.filters.q = event.target.value;
    state.visibleLimit = 200;
    renderTable();
  });
  $("verdict-filter").addEventListener("change", (event) => {
    state.filters.verdict = event.target.value;
    renderTable();
  });
  $("proto-filter").addEventListener("change", (event) => {
    state.filters.proto = event.target.value;
    renderTable();
  });
  $("net-filter").addEventListener("change", (event) => {
    state.filters.net = event.target.value;
    renderTable();
  });

  $("table-head").addEventListener("click", (event) => {
    const th = event.target.closest("th");
    if (!th || th.dataset.sortable !== "true") return;
    const key = th.dataset.col;
    if (state.sort.key === key) state.sort.dir = state.sort.dir === "asc" ? "desc" : "asc";
    else state.sort = { key, dir: "asc" };
    renderTable();
  });

  $("table-body").addEventListener("click", (event) => {
    const tr = event.target.closest("tr[data-key]");
    if (tr) openDrawer(tr.dataset.key);
  });

  $("table-body").addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const tr = event.target.closest("tr[data-key]");
    if (tr) {
      event.preventDefault();
      openDrawer(tr.dataset.key);
    }
  });

  $("more-btn").addEventListener("click", () => {
    state.visibleLimit += 200;
    renderTable();
  });

  $("drawer-close").addEventListener("click", closeDrawer);
  $("drawer-backdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeDrawer();
  });

  $("drawer-copy").addEventListener("click", async () => {
    const key = $("drawer-copy").dataset.key;
    const row = state.byKey.get(key);
    if (!row) return;
    toast((await copyText(row.node.raw)) ? t("detail.copied") : "Copy failed", false);
  });

  $("tier-grid").addEventListener("click", async (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    const tiers = buildTiers(state.rows);
    const key = button.dataset.download || button.dataset.copy;
    const tier = tiers.find((entry) => entry.key === key);
    if (!tier || !tier.count) return;
    const block = `${tier.links.join("\n")}\n`;

    if (button.dataset.download) {
      download(`${key}_links.txt`, block);
    } else if (button.dataset.copy) {
      toast((await copyText(block.trimEnd())) ? t("export.copied") : "Copy failed", false);
    }
  });
}

/* --------------------------------------------------------------------- init */

function init() {
  const savedLang = localStorage.getItem("wug.lang");
  const browserLang = (navigator.language || "").toLowerCase().startsWith("fa") ? "fa" : "en";
  state.lang = setLang(savedLang || browserLang);

  const params = new URLSearchParams(location.search);
  const tokenFromUrl = params.get("token");
  // The one-file bridge opens this page itself, already paired.
  const bridgeFromUrl = params.get("bridge");
  const savedUrl = localStorage.getItem("wug.bridge.url");
  const savedToken = localStorage.getItem("wug.bridge.token");
  const localOrigin = /^(127\.0\.0\.1|localhost)$/.test(location.hostname)
    ? location.origin
    : "http://127.0.0.1:8787";
  state.bridge.url = (bridgeFromUrl || savedUrl || localOrigin).replace(/\/+$/, "");
  state.bridge.token = tokenFromUrl || savedToken || "";
  $("bridge-url").value = state.bridge.url;
  $("bridge-token").value = state.bridge.token;

  wireEvents();
  applyStaticText();
  selectTab("paste");

  // A token in the URL means the bridge just printed a ready-to-use link.
  if (tokenFromUrl) connectBridge({ quiet: true });
  else if (state.bridge.token) connectBridge({ quiet: true });
}

init();
