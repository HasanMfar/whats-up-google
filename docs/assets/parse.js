/* Node parsing + subscription decoding, in the browser.
 *
 * A faithful port of scanner/nodes.py and scanner/subscriptions.py: same field
 * names, same tolerances (URL-safe/unpadded/double base64, per-line base64,
 * percent-encoded bodies, zero-width prefixes), so a link parsed here and a link
 * parsed by the CLI describe the same node.
 */

export const SCHEMES = ["vmess://", "vless://", "trojan://", "ss://"];
const ZW_PREFIX = /^[\ufeff\u200b\u200c\u200d\u2060]+/;
// Python's str.splitlines() breaks on more than \n: U+2028, U+2029 and \x85 too.
// Splitting differently would merge two links into one line whose fragment
// swallows the second link - and that merged line is what gets exported.
const LINE_BREAK = /\r\n|[\n\r\v\f\x1c\x1d\x1e\x85\u2028\u2029]/;

export function splitLines(text) {
  return String(text).split(LINE_BREAK);
}

/** True when a raw link can be written to an export as one well-formed line. */
export function isExportableLink(link) {
  const s = String(link ?? "");
  if (!s || s.length > 8192) return false;              // same per-link cap as the bridge
  if (/[\u0000-\u001f\u2028\u2029\x85]/.test(s)) return false; // never inject a second line
  return SCHEMES.some((scheme) => s.startsWith(scheme));
}

export class LinkParseError extends Error {}

const utf8Decoder = new TextDecoder("utf-8", { fatal: false });

export function b64Bytes(data) {
  let s = String(data).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64Text(data) {
  return utf8Decoder.decode(b64Bytes(data));
}

export function b64EncodeUtf8(text) {
  const bytes = new TextEncoder().encode(text);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function stripZeroWidth(line) {
  return line.replace(ZW_PREFIX, "");
}

function splitHostPort(hostport) {
  const hp = String(hostport).trim().replace(/\/+$/, "");
  if (hp.startsWith("[")) {
    const close = hp.indexOf("]");
    const host = hp.slice(1, close);
    const port = parseInt(hp.slice(close + 1).replace(/^:/, ""), 10);
    return [host, Number.isFinite(port) ? port : 443];
  }
  const idx = hp.lastIndexOf(":");
  if (idx < 1) throw new LinkParseError(`bad host:port ${JSON.stringify(hostport)}`);
  const port = parseInt(hp.slice(idx + 1), 10);
  return [hp.slice(0, idx), Number.isFinite(port) ? port : 443];
}

function normalizeNetwork(net) {
  const n = String(net || "tcp").trim().toLowerCase();
  return n === "splithttp" ? "xhttp" : n;
}

function decodeComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function splitLink(link) {
  // Split like Python's urlsplit, without relying on URL's handling of
  // non-special schemes: [userinfo@]host:port[?query][#fragment]
  let rest = link.slice(link.indexOf("://") + 3);
  let fragment = "";
  const hash = rest.indexOf("#");
  if (hash >= 0) {
    fragment = rest.slice(hash + 1);
    rest = rest.slice(0, hash);
  }
  let query = "";
  const q = rest.indexOf("?");
  if (q >= 0) {
    query = rest.slice(q + 1);
    rest = rest.slice(0, q);
  }
  let userinfo = "";
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    userinfo = rest.slice(0, at);
    rest = rest.slice(at + 1);
  }
  return { userinfo, hostport: rest, params: new URLSearchParams(query), fragment };
}

function firstParam(params, key) {
  const v = params.get(key);
  return v === null ? "" : v;
}

export function emptyNode() {
  return {
    protocol: "",
    id: "",
    server: "",
    port: 443,
    remark: "",
    scheme: "",
    raw: "",
    source: "",
    network: "tcp",
    security: "none",
    sni: "",
    host: "",
    path: "",
    fingerprint: "",
    flow: "",
    public_key: "",
    short_id: "",
    method: "",
    alter_id: 0,
    cipher: "auto",
    service_name: "",
    extra: {},
  };
}

function parseVmess(link, source) {
  const payload = b64Text(link.slice("vmess://".length));
  let cfg;
  try {
    cfg = JSON.parse(payload);
  } catch (e) {
    throw new LinkParseError(`vmess payload is not JSON: ${e.message}`);
  }
  const port = parseInt(String(cfg.port ?? 443).trim(), 10);
  const node = emptyNode();
  node.protocol = "vmess";
  node.id = String(cfg.id ?? "").trim();
  node.server = String(cfg.add ?? "").trim();
  node.port = Number.isFinite(port) ? port : 443;
  node.remark = String(cfg.ps ?? "");
  node.scheme = "vmess";
  node.raw = link;
  node.source = source;
  node.network = normalizeNetwork(cfg.net);
  node.security = String(cfg.tls ?? "").toLowerCase() === "tls" ? "tls" : "none";
  node.sni = String(cfg.sni ?? "");
  node.host = String(cfg.host ?? "");
  node.path = String(cfg.path ?? "");
  node.alter_id = parseInt(cfg.aid ?? 0, 10) || 0;
  node.cipher = String(cfg.scy ?? "") || "auto";
  node.service_name = String(cfg.path ?? "");
  node.extra = { header_type: String(cfg.type ?? "") };
  return node;
}

function parseUserinfoLink(link, source, proto) {
  const parts = splitLink(link);
  const [host, port] = splitHostPort(parts.hostport);
  if (!host) throw new LinkParseError("missing host");
  const p = parts.params;
  const node = emptyNode();
  node.protocol = proto;
  node.id = decodeComponent(parts.userinfo);
  node.server = host;
  node.port = port;
  node.remark = decodeComponent(parts.fragment);
  node.scheme = proto;
  node.raw = link;
  node.source = source;
  node.network = normalizeNetwork(firstParam(p, "type"));
  node.security = (firstParam(p, "security").trim().toLowerCase() || "none");
  if (proto === "trojan" && node.security === "none") node.security = "tls";
  node.sni = firstParam(p, "sni");
  node.host = firstParam(p, "host");
  node.path = firstParam(p, "path");
  node.fingerprint = firstParam(p, "fp");
  node.flow = proto === "vless" ? firstParam(p, "flow") : "";
  node.public_key = firstParam(p, "pbk");
  node.short_id = firstParam(p, "sid");
  node.service_name = firstParam(p, "serviceName");
  node.extra = { encryption: firstParam(p, "encryption") };
  return node;
}

function parseSs(link, source) {
  let rest = link.slice("ss://".length);
  let remark = "";
  const hash = rest.indexOf("#");
  if (hash >= 0) {
    remark = decodeComponent(rest.slice(hash + 1));
    rest = rest.slice(0, hash);
  }
  let plugin = "";
  const q = rest.indexOf("?");
  if (q >= 0) {
    plugin = firstParam(new URLSearchParams(rest.slice(q + 1)), "plugin");
    rest = rest.slice(0, q);
  }
  let methodPass;
  let hostport;
  const at = rest.lastIndexOf("@");
  if (at >= 0) {
    // SIP002: base64(method:password)@host:port
    const userinfo = rest.slice(0, at);
    hostport = rest.slice(at + 1);
    methodPass = userinfo.includes(":") ? decodeComponent(userinfo) : b64Text(userinfo);
  } else {
    // legacy: base64(method:password@host:port)
    const decoded = b64Text(rest);
    if (!decoded.includes("@")) throw new LinkParseError("ss link missing @host:port");
    const cut = decoded.lastIndexOf("@");
    methodPass = decoded.slice(0, cut);
    hostport = decoded.slice(cut + 1);
  }
  if (!methodPass.includes(":")) throw new LinkParseError("ss link missing method:password");
  const split = methodPass.indexOf(":");
  const [host, port] = splitHostPort(hostport);
  const node = emptyNode();
  node.protocol = "shadowsocks";
  node.id = methodPass.slice(split + 1);
  node.server = host;
  node.port = port;
  node.remark = remark;
  node.scheme = "ss";
  node.raw = link;
  node.source = source;
  node.method = methodPass.slice(0, split);
  node.extra = { plugin };
  return node;
}

export function parseLink(link, source = "") {
  const line = String(link).trim();
  if (line.startsWith("vmess://")) return parseVmess(line, source);
  if (line.startsWith("vless://")) return parseUserinfoLink(line, source, "vless");
  if (line.startsWith("trojan://")) return parseUserinfoLink(line, source, "trojan");
  if (line.startsWith("ss://")) return parseSs(line, source);
  throw new LinkParseError("unknown scheme");
}

export function parseLinks(text, source = "") {
  const nodes = [];
  const errors = [];
  for (const rawLine of splitLines(text)) {
    const line = stripZeroWidth(rawLine.trim());
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    try {
      nodes.push(parseLink(line, source));
    } catch (e) {
      errors.push({ line: line.slice(0, 80), error: `${e.name || "Error"}: ${e.message}` });
    }
  }
  return { nodes, errors };
}

export function nodeKey(node) {
  return [node.protocol, node.server, node.port, node.id].join("|");
}

export function dedupe(nodes) {
  const seen = new Set();
  const unique = [];
  let duplicates = 0;
  for (const node of nodes) {
    const key = nodeKey(node);
    if (seen.has(key)) {
      duplicates += 1;
      continue;
    }
    seen.add(key);
    unique.push(node);
  }
  return { nodes: unique, duplicates };
}

/* ---------------------------------------------------------------- subscriptions */

export function extractLinks(text) {
  const links = [];
  for (const rawLine of splitLines(text)) {
    const line = stripZeroWidth(rawLine.trim());
    if (SCHEMES.some((scheme) => line.startsWith(scheme))) links.push(line);
  }
  return links;
}

function decodeB64Blob(text) {
  let s = text;
  for (let round = 0; round < 3; round += 1) {
    if (extractLinks(s).length) return s;
    s = b64Text(s);
  }
  return s;
}

function decodeB64PerLine(text) {
  const out = [];
  for (const rawLine of splitLines(text)) {
    const line = stripZeroWidth(rawLine.trim());
    if (!line || line.startsWith("#")) continue;
    try {
      out.push(...extractLinks(b64Text(line)));
    } catch {
      /* not base64: ignore this line */
    }
  }
  return out.join("\n");
}

/** Every non-comment line is an http(s) address - a subscription index, not a config body. */
function isUrlList(text) {
  const lines = splitLines(text)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  if (!lines.length) return false;
  return lines.every((line) => /^https?:\/\//i.test(line));
}

/** Decode any known subscription payload shape into plain link lines. */
export function decodeSubscription(text) {
  const input = String(text);
  const strategies = [
    (s) => s,
    decodeB64Blob,
    decodeB64PerLine,
    (s) => decodeB64Blob(decodeURIComponent(s)),
  ];
  let best = [];
  for (const strategy of strategies) {
    let candidate;
    try {
      candidate = strategy(input);
    } catch {
      continue;
    }
    const links = extractLinks(candidate);
    if (links.length > best.length) best = links;
  }
  if (best.length) return best.join("\n");
  const preview = input.trim().slice(0, 150).replace(/\s+/g, " ");
  if (isUrlList(input)) {
    throw new Error(
      "That is a list of web addresses, not a subscription: these look like subscription URLs " +
        "(or a page), and there is no config in them. Paste the subscription body, or use the " +
        "\"Subscription URL\" tab.",
    );
  }
  throw new Error(
    "No vmess/vless/trojan/ss links found. This does not look like a V2Ray subscription. " +
      `First 150 characters: ${JSON.stringify(preview)}`,
  );
}

/**
 * Parse anything a user can paste or drop: a subscription body, base64 payload,
 * a plain list of links, a Clash config (rejected with a clear reason), or a
 * scan report exported by the CLI.
 */
export function parseAny(text, sourceLabel = "pasted") {
  const trimmed = String(text).trim();
  if (!trimmed) throw new Error("Nothing to read: the input is empty.");

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const data = JSON.parse(trimmed);
      const rows = Array.isArray(data) ? data : data.results;
      if (Array.isArray(rows) && rows.length && rows[0] && rows[0].node) {
        return { kind: "report", rows: normalizeReportRows(rows), report: data };
      }
    } catch {
      /* not JSON, fall through to link parsing */
    }
  }

  if (/proxies\s*:/.test(trimmed) && /cipher\s*:/.test(trimmed)) {
    throw new Error("This is a Clash YAML subscription. Only V2Ray/Xray subscriptions are supported.");
  }
  if (/^<!doctype html|^<html/i.test(trimmed)) {
    throw new Error("This is an HTML page, not a subscription. Check the subscription URL.");
  }

  const links = decodeSubscription(trimmed);
  const { nodes, errors } = parseLinks(links, sourceLabel);
  const { nodes: unique, duplicates } = dedupe(nodes);
  return {
    kind: "nodes",
    nodes: unique,
    errors,
    stats: { parsed: nodes.length + errors.length, duplicates, badLines: errors.length },
  };
}

/** Turn CLI report rows into workbench rows. */
export function normalizeReportRows(rows) {
  return rows.map((row, index) => ({
    index,
    key: nodeKey(row.node),
    node: { ...emptyNode(), ...row.node, extra: parseExtra(row.node.extra) },
    results: row.results || {},
    exit_ip: row.exit_ip || {},
    latency_ms: row.latency_ms ?? null,
    verdict: row.verdict || "PENDING",
    error: row.error || "",
    tested_at: row.tested_at || "",
  }));
}

function parseExtra(extra) {
  if (!extra) return {};
  if (typeof extra === "object") return extra;
  try {
    return JSON.parse(extra);
  } catch {
    return {};
  }
}
