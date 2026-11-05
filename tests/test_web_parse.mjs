/* Run with: node tests/test_web_parse.mjs
 *
 * The browser port writes the files people import, so its output rules are
 * tested like the CLI's. Two real risks found in review:
 *
 *  1. A remark containing U+2028/U+2029/U+0085 used to merge two link lines in
 *     the page (Python's str.splitlines() splits there, JS /\r?\n/ does not),
 *     so the exported line carried one link inside another's fragment.
 *  2. A scan report is just JSON: a hand-edited or malformed `raw` field used
 *     to reach the exported subscription verbatim.
 */
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const load = (name) => import(pathToFileURL(path.join(HERE, "..", "docs", "assets", name)).href);

const { parseAny, parseLinks, splitLines, isExportableLink } = await load("parse.js");
const { buildTiers } = await load("tiers.js");

let failures = 0;
function expect(condition, label) {
  if (condition) {
    console.log(`ok   ${label}`);
  } else {
    failures += 1;
    console.error(`FAIL ${label}`);
  }
}

const US = "vless://11111111-2222-3333-4444-555555555555@us.example.com:443?security=tls&type=ws#US%20node";
const DE = "vless://99999999-2222-3333-4444-555555555555@de.example.com:443#DE";
const JP = "trojan://p%40ss@jp.example.com:8443#JP";
const ALL_OK = {
  search: { ok: true },
  gemini: { ok: true },
  gemini_api: { ok: true },
  antigravity: { ok: true },
};

// -- line splitting matches Python's str.splitlines() ----------------------
expect(splitLines(`a\u2028b`).length === 2, "U+2028 splits a line");
expect(splitLines(`a\u2029b`).length === 2, "U+2029 splits a line");
expect(splitLines(`a\u0085b`).length === 2, "U+0085 splits a line");
expect(splitLines("a\r\nb").length === 2, "CRLF splits a line");

// -- the merge bug: two links separated by U+2028 stay two nodes ------------
const merged = parseAny(`${US}\u2028${DE}`, "test");
expect(merged.nodes.length === 2, "U+2028 between two links yields two nodes");
expect(
  merged.nodes.every((node) => !node.remark.includes("vless://")),
  "a link is never swallowed into another node's remark",
);
expect(merged.nodes.every((node) => isExportableLink(node.raw)), "both nodes stay exportable");

// -- inputs that are not subscriptions fail with a specific reason ----------
for (const [text, needle, label] of [
  ["https://a.example/sub\nhttps://b.example/sub", "web addresses", "a URL list says what it is"],
  ["<!doctype html><html><body>x</body></html>", "HTML page", "an HTML page is named"],
  ["proxies:\n  - name: a\n    cipher: aes-128-gcm", "Clash", "Clash YAML is named"],
]) {
  try {
    parseAny(text, "test");
    expect(false, label);
  } catch (e) {
    expect(String(e.message).includes(needle), label);
  }
}

// -- nothing but a single-line supported link is ever exported --------------
const forged = [
  {
    key: "a", node: { raw: "javascript:alert(1)" }, results: ALL_OK,
    verdict: "CLEAN", latency_ms: 1, exit_ip: { ip: "1.1.1.1" },
  },
  {
    key: "b", node: { raw: "vless://a@b:1#n\nsecond-line" }, results: ALL_OK,
    verdict: "CLEAN", latency_ms: 2, exit_ip: { ip: "2.2.2.2" },
  },
  {
    key: "c", node: { raw: "" }, results: ALL_OK,
    verdict: "CLEAN", latency_ms: 3, exit_ip: { ip: "3.3.3.3" },
  },
];
const forgedTiers = buildTiers(forged);
expect(
  forgedTiers.every((tier) => tier.links.length === 0),
  "non-link raws never reach an export",
);

// -- a real export round-trips: every line reparses to the same node --------
const nodes = parseAny([US, DE, JP].join("\n"), "test").nodes;
const rows = nodes.map((node, index) => ({
  key: `${node.protocol}|${node.server}|${node.port}|${node.id}`,
  node,
  results: ALL_OK,
  verdict: "CLEAN",
  latency_ms: index,
  exit_ip: { ip: `10.0.0.${index}` },
}));
const tiers = buildTiers(rows);
const clean = tiers.find((tier) => tier.key === "clean");
expect(clean.count === 3, "every clean node is exported");

const reparsed = parseLinks(clean.links.join("\n"), "export").nodes;
expect(reparsed.length === 3, "the exported block reparses into the same number of nodes");
expect(
  reparsed.map((node) => node.remark).join(",") === nodes.map((node) => node.remark).join(","),
  "round trip preserves every remark",
);
expect(
  reparsed.every((node, index) => node.raw === nodes[index].raw),
  "round trip preserves every link byte for byte",
);
expect(
  tiers.every((tier) => !("base64" in tier)),
  "the export is plain links, with no base64 payload",
);
expect(
  tiers.every((tier) => tier.links.every((link) => isExportableLink(link))),
  "every tier holds only well-formed links",
);

if (failures) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall workbench parser tests passed");
