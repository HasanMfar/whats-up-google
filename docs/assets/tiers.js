/* Hand-picking + export, in the browser.
 *
 * A port of scanner/clean_sub.py: the same four tiers, picked by the same
 * predicate, encoded exactly like the CLI writes them (newline-joined links,
 * one base64 subscription per tier).
 */
import { b64EncodeUtf8 } from "./parse.js";

export const CHECK_ORDER = ["search", "gemini", "gemini_api", "antigravity"];

export const CHECK_LABELS = {
  search: "Search",
  gemini: "Gemini",
  gemini_api: "Gemini API",
  antigravity: "Antigravity",
};

// The services this scanner exists for: getting into Gemini and Antigravity.
export const TARGET_SERVICES = ["gemini", "gemini_api", "antigravity"];

/** true = every requested check passed, false = a check was flagged, null = nothing tested. */
export function serviceOk(results, services) {
  let sawAny = false;
  let ok = true;
  for (const name of services) {
    const res = results ? results[name] : null;
    if (!res) continue; // check disabled for this run
    sawAny = true;
    if (res.ok === false) return false;
    if (res.ok === null || res.ok === undefined) ok = null;
  }
  return sawAny ? ok : null;
}

export function pickForServices(rows, services) {
  return rows.filter((row) => serviceOk(row.results, services) === true);
}

const latencyOrder = (row) => (row.latency_ms === null || row.latency_ms === undefined ? Infinity : row.latency_ms);

/** Subscription lists repeat the same exit IP many times; keep the fastest config per IP. */
export function bestPerIp(rows) {
  const byIp = new Map();
  for (const row of rows) {
    const ip = (row.exit_ip && row.exit_ip.ip) || `noip:${row.key}`;
    const current = byIp.get(ip);
    if (!current || latencyOrder(row) < latencyOrder(current)) byIp.set(ip, row);
  }
  return [...byIp.values()].sort((a, b) => latencyOrder(a) - latencyOrder(b));
}

/**
 * Build the four importable subscriptions from scanned rows.
 * Returns [{ key, links, base64, count }] with empty links when nothing passed.
 */
export function buildTiers(rows) {
  const scored = rows.filter((row) => row && row.node && row.node.raw && row.verdict && row.verdict !== "PENDING");
  const definitions = [
    {
      key: "best",
      links: bestPerIp(pickForServices(scored, TARGET_SERVICES)).map((r) => r.node.raw),
    },
    { key: "clean", links: scored.filter((r) => r.verdict === "CLEAN").map((r) => r.node.raw) },
    {
      key: "gemini",
      links: pickForServices(scored, ["gemini", "gemini_api"]).map((r) => r.node.raw),
    },
    {
      key: "antigravity",
      links: pickForServices(scored, ["antigravity"]).map((r) => r.node.raw),
    },
  ];
  return definitions.map(({ key, links }) => ({
    key,
    links,
    count: links.length,
    base64: links.length ? b64EncodeUtf8(links.join("\n")) : "",
  }));
}

export function summarize(rows) {
  const counts = { TOTAL: rows.length, CLEAN: 0, FLAGGED: 0, DEAD: 0, ERROR: 0, PENDING: 0, UNSCANNED: 0 };
  for (const row of rows) {
    const verdict = row.verdict || "UNSCANNED";
    counts[verdict] = (counts[verdict] || 0) + 1;
  }
  return counts;
}

/** Per-check pass rate over rows that actually have a result: {check: {pass, fail, err}}. */
export function checkTally(rows) {
  const tally = {};
  for (const name of CHECK_ORDER) {
    const entry = { pass: 0, fail: 0, err: 0, tested: 0 };
    for (const row of rows) {
      const res = row.results ? row.results[name] : null;
      if (!res) continue;
      entry.tested += 1;
      if (res.ok === true) entry.pass += 1;
      else if (res.ok === false) entry.fail += 1;
      else entry.err += 1;
    }
    tally[name] = entry;
  }
  return tally;
}
