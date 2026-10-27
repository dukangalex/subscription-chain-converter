// subscription-converter — Cloudflare Workers variant.
//
// A port of the VPS Python service (landing_server.py) to a single
// Worker. Behavioural parity target: the Python service's PRIMARY
// (own-skeleton) builders. The node-script fallback path and the
// templates/ fallback of the Python service are not portable to
// Workers and are intentionally absent (see README.md).
//
// Storage (single KV binding "KV"):
//   link:<code>        JSON short-link record
//   idx:<sha256hex>    content identity index -> code
//   rule:<dst>         mirrored rule file bytes (manifest dst paths)
//   meta:rules_status  JSON of the last rules refresh
//
// The bundled skeletons (skeleton_clash.json / skeleton_singbox.json)
// carry the literal placeholder __PUBLIC_ORIGIN__ in their rule URLs;
// it is replaced at generation time with the origin of the incoming
// request, so generated configs always point back at this deployment.
import { load as yamlLoad, dump as yamlDump } from "js-yaml";
import skeletonClash from "./skeleton_clash.json" with { type: "json" };
import skeletonSingbox from "./skeleton_singbox.json" with { type: "json" };
import rulesManifest from "./rules_manifest.json" with { type: "json" };

const BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/126.0 Safari/537.36");
const REFRESH_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36");
const GROUP_TYPES = new Set(["selector", "urltest"]);
const BUILTIN_TYPES = new Set(["direct", "block", "dns"]);
const ENTRY_AUTO = "⛓ 入口优选";
const EXIT_AUTO = "⛓ 出口优选";
const MEMBER_TOKENS = new Set(["@ENTRIES@", "@EXITS@", "@ALL@"]);
const LINK_ALPHABET =
  "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const CODE_CHARS = ("abcdefghijklmnopqrstuvwxyz" +
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_");
const MANIFEST = rulesManifest;
const DST_SET = new Set(MANIFEST.map((e) => e.dst));
const STAGE = { cur: "-" };
const ECH_CFG_CACHE = new Map();

const PAGE = "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>订阅转换</title>\n<style>\nbody{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:24px}\n.wrap{max-width:560px;margin:0 auto}\nh1{font-size:20px}\n.tabs{display:flex;gap:8px;margin-bottom:8px}\n.tabs button{flex:1;padding:10px;border:1px solid #444;border-radius:8px;background:#1c1c1e;color:#bbb;font-size:15px}\n.tabs button.on{background:#0a84ff;color:#fff;border-color:#0a84ff}\nlabel{display:block;margin:16px 0 6px;color:#bbb;font-size:14px}\nselect,textarea,input{width:100%;padding:10px;border-radius:8px;border:1px solid #444;background:#1c1c1e;color:#eee;box-sizing:border-box}\ntextarea{resize:vertical;font-family:inherit}\nbutton.go{margin-top:18px;width:100%;padding:12px;border:0;border-radius:8px;background:#0a84ff;color:#fff;font-size:16px}\n.out{margin-top:18px;word-break:break-all;background:#1c1c1e;border:1px solid #333;border-radius:8px;padding:12px;display:none}\n.row{display:flex;gap:10px;margin-top:10px}\n.row button{flex:1;padding:10px;border:0;border-radius:8px;background:#333;color:#eee}\n.hide{display:none}\n</style>\n</head>\n<body>\n<div class=\"wrap\">\n<h1>订阅转换</h1>\n<div class=\"tabs\">\n<button id=\"tabN\" class=\"on\" onclick=\"mode('n')\">普通转换</button>\n<button id=\"tabC\" onclick=\"mode('c')\">链式代理</button>\n</div>\n\n<div id=\"secN\">\n<label>节点 / 订阅（每行一个，可任意混填）</label>\n<textarea id=\"u\" rows=\"6\" placeholder=\"ss://...&#10;trojan://...&#10;https://订阅地址\"></textarea>\n<label>目标格式</label>\n<select id=\"t\">\n<option value=\"clash\">Clash / Mihomo</option>\n<option value=\"singbox\">sing-box</option>\n<option value=\"v2ray\">V2Ray</option>\n<option value=\"surge\">Surge</option>\n<option value=\"loon\">Loon</option>\n<option value=\"quanx\">Quantumult X</option>\n</select>\n<label>自定义后缀（可选，不填则随机）</label>\n<input id=\"codeN\" placeholder=\"如 home，只用字母、数字、-、_\">\n<button class=\"go\" onclick=\"genN()\">生成转换链接</button>\n<div class=\"out\" id=\"outN\"><div id=\"linkN\"></div>\n<div class=\"row\"><button onclick=\"openL('N')\">打开链接</button><button onclick=\"copyL('N')\">复制链接</button></div></div>\n</div>\n\n<div id=\"secC\" class=\"hide\">\n<label>入口（每行一个，可混填节点与订阅）</label>\n<textarea id=\"ein\" rows=\"4\" placeholder=\"链的第一站，如日本入口节点或入口订阅\"></textarea>\n<label>出口（每行一个，可混填节点与订阅）</label>\n<textarea id=\"eout\" rows=\"4\" placeholder=\"链的第二站，如美国出口节点或出口订阅\"></textarea>\n<label>目标格式</label>\n<select id=\"tc\">\n<option value=\"singbox\">sing-box</option>\n<option value=\"clash\">Mihomo / Clash</option>\n</select>\n<label>自定义后缀（可选，不填则随机）</label>\n<input id=\"codeC\" placeholder=\"如 chain，只用字母、数字、-、_\">\n<button class=\"go\" onclick=\"genC()\">生成链式订阅链接</button>\n<div class=\"out\" id=\"outC\"><div id=\"linkC\"></div>\n<div class=\"row\"><button onclick=\"openL('C')\">打开链接</button><button onclick=\"copyL('C')\">复制链接</button></div></div>\n<p style=\"color:#777;font-size:13px\">生成的链接可直接当订阅地址填进客户端，每次更新都会重新按入口到出口串好。短链里的字母代表格式：/m/ 是 Mihomo、/s/ 是 sing-box，同一个码改字母就能切换格式，不用重新生成。</p>\n</div>\n\n<p style=\"color:#777;font-size:13px\">后端运行在你自己的 VPS 上，订阅链接不经过任何第三方。</p>\n</div>\n<script>\nvar cur={N:\"\",C:\"\"};\nfunction mode(m){\n  document.getElementById(\"secN\").className = m==\"n\" ? \"\" : \"hide\";\n  document.getElementById(\"secC\").className = m==\"c\" ? \"\" : \"hide\";\n  document.getElementById(\"tabN\").className = m==\"n\" ? \"on\" : \"\";\n  document.getElementById(\"tabC\").className = m==\"c\" ? \"on\" : \"\";\n}\nfunction items(id){\n  return document.getElementById(id).value.split(/\\n+/).map(function(s){return s.trim()}).filter(function(s){return s.length>0});\n}\nfunction show(k){\n  document.getElementById(\"link\"+k).textContent=cur[k];\n  document.getElementById(\"out\"+k).style.display=\"block\";\n}\nfunction shorten(body,cb){\n  fetch(\"/shorten\",{method:\"POST\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify(body)})\n    .then(function(r){return r.text().then(function(t){cb(r.ok?t:null,r.ok?null:t)})})\n    .catch(function(){cb(null,null)});\n}\nfunction genN(){\n  var it=items(\"u\"); if(!it.length){alert(\"先粘贴节点或订阅链接\");return}\n  var tg=document.getElementById(\"t\").value;\n  var cd=document.getElementById(\"codeN\").value.trim();\n  var body={target:tg,url:it.join(\"|\")}; if(cd)body.code=cd;\n  shorten(body,function(u,err){\n    if(!u){\n      if(cd){alert(err||\"生成失败\");return}\n      var base=(tg==\"clash\"||tg==\"singbox\")?\"/conv\":\"/sub\";u=location.origin+base+\"?target=\"+tg+\"&url=\"+encodeURIComponent(it.join(\"|\"));\n    }\n    cur.N=u;show(\"N\");\n  });\n}\nfunction genC(){\n  var a=items(\"ein\"), b=items(\"eout\");\n  if(!a.length||!b.length){alert(\"入口和出口都要填\");return}\n  var tg=document.getElementById(\"tc\").value;\n  var cd=document.getElementById(\"codeC\").value.trim();\n  var body={target:tg,entry:a.join(\"|\"),exit:b.join(\"|\")}; if(cd)body.code=cd;\n  shorten(body,function(u,err){\n    if(!u){\n      if(cd){alert(err||\"生成失败\");return}\n      u=location.origin+\"/chain?target=\"+tg+\"&entry=\"+encodeURIComponent(a.join(\"|\"))+\"&exit=\"+encodeURIComponent(b.join(\"|\"));\n    }\n    cur.C=u;show(\"C\");\n  });\n}\nfunction openL(k){if(cur[k])location.href=cur[k]}\nfunction copyL(k){if(cur[k])navigator.clipboard.writeText(cur[k])}\n</script>\n</body>\n</html>\n";

// ------------------------------------------------------------ utilities
const _enc = new TextEncoder();
const _dec = new TextDecoder();

function isObj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function nonEmptyObj(v) {
  return isObj(v) && Object.keys(v).length > 0;
}

function safeDecode(s) {
  s = s ?? "";
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function b64ToBytes(s) {
  let t = String(s).replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  t += "=".repeat((4 - (t.length % 4)) % 4);
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64ToText(s) {
  return _dec.decode(b64ToBytes(s));
}

function intOr(v, dflt) {
  if (!v) return dflt;
  const n = Number(v);
  if (Number.isNaN(n)) throw new Error("bad int");
  return Math.trunc(n);
}

function toPort(v, dflt) {
  if (v === null || v === undefined || v === "" || v === 0) return dflt;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : dflt;
}

function partition(s, sep) {
  const i = s.indexOf(sep);
  if (i < 0) return [s, ""];
  return [s.slice(0, i), s.slice(i + sep.length)];
}

function rpartition(s, sep) {
  const i = s.lastIndexOf(sep);
  if (i < 0) return ["", s];
  return [s.slice(0, i), s.slice(i + sep.length)];
}

function qmap(searchParams) {
  const m = new Map();
  for (const k of new Set(searchParams.keys())) m.set(k, searchParams.getAll(k));
  return m;
}

function q1(q, key) {
  const v = q.get(key);
  return v && v.length ? v[0] : undefined;
}

function errMsg(e) {
  return e instanceof Error ? e.message : String(e);
}

// ------------------------------------------------------------- URI -> node
function applyTransport(node, q) {
  const net = (q1(q, "type") || "tcp").toLowerCase();
  node.network = net;
  if (net === "ws") {
    const ws = {};
    const path = q1(q, "path");
    if (path) ws.path = path;
    const host = q1(q, "host");
    if (host) ws.headers = { Host: host };
    if (Object.keys(ws).length) node["ws-opts"] = ws;
  } else if (net === "grpc") {
    const sn = q1(q, "serviceName");
    if (sn) node["grpc-opts"] = { "grpc-service-name": sn };
  }
}

function applyTlsUri(node, q) {
  const sec = (q1(q, "security") || "none").toLowerCase();
  if (sec === "reality") {
    node.tls = true;
    const ro = {};
    const pbk = q1(q, "pbk");
    if (pbk) ro["public-key"] = pbk;
    const sid = q1(q, "sid");
    if (sid) ro["short-id"] = sid;
    node["reality-opts"] = ro;
  } else if (sec === "tls") {
    node.tls = true;
  }
  const sni = q1(q, "sni") ?? q1(q, "peer");
  if (sni) node.servername = sni;
  const fp = q1(q, "fp");
  if (fp) node["client-fingerprint"] = fp;
  const flow = q1(q, "flow");
  if (flow) node.flow = flow;
  const ai = q1(q, "allowInsecure");
  if (ai === "1" || ai === "true") node["skip-cert-verify"] = true;
}

function parseUri(line) {
  line = String(line).trim();
  if (!line.includes("://")) return null;
  const idx = line.indexOf("://");
  const scheme = line.slice(0, idx).toLowerCase();
  const rest = line.slice(idx + 3);
  try {
    if (scheme === "vmess") {
      const doc = JSON.parse(b64ToText(rest.split("#")[0]));
      const node = {
        name: doc.ps || "vmess", type: "vmess", server: doc.add,
        port: intOr(doc.port, 443), uuid: doc.id,
        alterId: intOr(doc.aid, 0), cipher: doc.scy || "auto",
        network: String(doc.net || "tcp").toLowerCase(),
      };
      if (doc.tls === "tls") node.tls = true;
      if (doc.sni) node.servername = doc.sni;
      if (node.network === "ws") {
        const ws = {};
        if (doc.path) ws.path = doc.path;
        if (doc.host) ws.headers = { Host: doc.host };
        if (Object.keys(ws).length) node["ws-opts"] = ws;
      } else if (node.network === "grpc" && doc.path) {
        node["grpc-opts"] = { "grpc-service-name": doc.path };
      }
      return node;
    }
    const u = new URL(line);
    const host = u.hostname || null;
    const port = u.port ? Number(u.port) : null;
    const name = safeDecode(u.hash ? u.hash.slice(1) : "") || scheme;
    const q = qmap(u.searchParams);
    const user = safeDecode(u.username || "");
    if (scheme === "vless") {
      const node = {
        name, type: "vless", server: host, port: port || 443, uuid: user,
      };
      applyTlsUri(node, q);
      applyTransport(node, q);
      return node;
    }
    if (scheme === "trojan") {
      const node = {
        name, type: "trojan", server: host, port: port || 443,
        password: user, tls: true,
      };
      applyTlsUri(node, q);
      applyTransport(node, q);
      return node;
    }
    if (scheme === "ss") {
      if (u.username && u.hostname) {
        const ui = u.username;
        let dec;
        try {
          dec = b64ToText(safeDecode(ui));
        } catch {
          dec = safeDecode(ui);
        }
        const [method, pwd] = partition(dec, ":");
        return {
          name, type: "ss", server: host, port: port || 8388,
          cipher: method, password: pwd,
        };
      }
      const doc = b64ToText(rest.split("#")[0]);
      const [cred, addr] = rpartition(doc, "@");
      const [method, pwd] = partition(cred, ":");
      const [h, p] = rpartition(addr, ":");
      return {
        name, type: "ss", server: h, port: intOr(p, 8388),
        cipher: method, password: pwd,
      };
    }
    if (scheme === "hysteria2" || scheme === "hy2") {
      const node = {
        name, type: "hysteria2", server: host, port: port || 443,
        password: user,
      };
      const sni = q1(q, "sni");
      if (sni) node.sni = sni;
      const obfs = q1(q, "obfs");
      if (obfs) node.obfs = obfs;
      const op = q1(q, "obfs-password");
      if (op) node["obfs-password"] = op;
      const ins = q1(q, "insecure");
      if (ins === "1" || ins === "true") node["skip-cert-verify"] = true;
      return node;
    }
    if (scheme === "tuic") {
      const [uuid, pwd] = partition(user, ":");
      const node = {
        name, type: "tuic", server: host, port: port || 443,
        uuid, password: pwd,
      };
      const sni = q1(q, "sni");
      if (sni) node.sni = sni;
      const alpn = q1(q, "alpn");
      if (alpn) node.alpn = [alpn];
      const cc = q1(q, "congestion_control");
      if (cc) node["congestion-controller"] = cc;
      const urm = q1(q, "udp_relay_mode");
      if (urm) node["udp-relay-mode"] = urm;
      return node;
    }
    if (scheme === "anytls") {
      const node = {
        name, type: "anytls", server: host, port: port || 443,
        password: user, tls: true,
      };
      const sni = q1(q, "sni");
      if (sni) node.servername = sni;
      return node;
    }
  } catch {
    return null;
  }
  return null;
}

// ------------------------------------------------- sing-box outbound -> node
function sbToNode(o) {
  const t = o.type;
  const node = { name: o.tag, type: t, server: o.server, port: o.server_port };
  const tls = o.tls || {};
  if (tls.enabled) {
    node.tls = true;
    if (tls.server_name) node.servername = tls.server_name;
    if (tls.insecure) node["skip-cert-verify"] = true;
    if (tls.utls && tls.utls.fingerprint) {
      node["client-fingerprint"] = tls.utls.fingerprint;
    }
    if (tls.reality && tls.reality.enabled) {
      node["reality-opts"] = {
        "public-key": tls.reality.public_key ?? "",
        "short-id": tls.reality.short_id ?? "",
      };
    }
  }
  const tr = o.transport || {};
  if (tr.type === "ws") {
    node.network = "ws";
    const ws = {};
    if (tr.path) ws.path = tr.path;
    const host = (tr.headers || {}).Host;
    if (host) ws.headers = { Host: host };
    if (Object.keys(ws).length) node["ws-opts"] = ws;
  } else if (tr.type === "grpc") {
    node.network = "grpc";
    if (tr.service_name) {
      node["grpc-opts"] = { "grpc-service-name": tr.service_name };
    }
  }
  if (t === "vless" || t === "vmess" || t === "tuic") node.uuid = o.uuid;
  if (t === "vless" && o.flow) node.flow = o.flow;
  if (t === "vmess") {
    node.alterId = o.alter_id || 0;
    node.cipher = o.security || "auto";
  }
  if (t === "trojan" || t === "anytls") node.password = o.password;
  if (t === "shadowsocks") {
    node.type = "ss";
    node.cipher = o.method;
    node.password = o.password;
  }
  if (t === "tuic") {
    node.password = o.password;
    if (o.congestion_control) node["congestion-controller"] = o.congestion_control;
    if (o.udp_relay_mode) node["udp-relay-mode"] = o.udp_relay_mode;
  }
  if (t === "hysteria2") {
    node.password = o.password || o.auth;
    if (o.obfs && o.obfs.password) {
      node.obfs = o.obfs.type || "salamander";
      node["obfs-password"] = o.obfs.password;
    }
  }
  return node;
}

// ---------------------------------------------------------------- gathering
async function classifyText(text, depth) {
  text = String(text).trim();
  if (!text) return [];
  if (text.startsWith("{")) {
    try {
      const doc = JSON.parse(text);
      if (isObj(doc) && Array.isArray(doc.outbounds)) {
        return doc.outbounds
          .filter((o) => isObj(o) && !GROUP_TYPES.has(o.type) &&
            !BUILTIN_TYPES.has(o.type) && o.server)
          .map(sbToNode);
      }
    } catch {
      // fall through to the YAML attempt, like the Python service
    }
  }
  try {
    const doc = yamlLoad(text);
    if (isObj(doc)) {
      if (Array.isArray(doc.proxies) && doc.proxies.length) {
        return doc.proxies.filter(isObj);
      }
      if (nonEmptyObj(doc["proxy-providers"]) && depth < 2) {
        // Full Mihomo configs often carry nodes only via providers:
        // resolve each provider URL and gather its nodes instead.
        const nodes = [];
        for (const pv of Object.values(doc["proxy-providers"])) {
          const url = isObj(pv) ? pv.url : undefined;
          if (url) nodes.push(...await nodesFromUrl(url, depth + 1));
        }
        if (nodes.length) return nodes;
      }
    }
  } catch {
    // fall through
  }
  try {
    const decoded = b64ToText(text);
    if (decoded.includes("://") || decoded.includes("proxies:")) {
      const inner = await classifyText(decoded, depth);
      if (inner.length) return inner;
    }
  } catch {
    // fall through
  }
  const out = [];
  for (const l of text.split(/\r\n|\r|\n/)) {
    const n = parseUri(l);
    if (n) out.push(n);
  }
  return out;
}

async function fetchTextWithUa(url, ua) {
  const resp = await fetch(url, {
    headers: { "User-Agent": ua },
    signal: AbortSignal.timeout(20000),
  });
  if (!resp.ok) throw new Error("HTTP " + resp.status);
  return resp.text();
}

async function nodesFromUrl(url, depth) {
  // Aggregators serve different renditions per UA: a Mihomo client UA
  // gets the full Clash YAML (incl. ECH options); a browser UA gets a
  // reduced format. Try the client UA first, browser UA as fallback.
  for (const ua of ["clash-verge/2.2.3", "clash-verge/2.2.3",
    "sing-box/1.15.0", BROWSER_UA]) {
    try {
      const found = await classifyText(await fetchTextWithUa(url, ua), depth);
      if (found.length) return found;
    } catch {
      continue;
    }
  }
  return [];
}

async function gather(items) {
  const nodes = [];
  const seen = new Map();
  for (let item of String(items).split("|")) {
    item = item.trim();
    if (!item) continue;
    let found;
    if (item.startsWith("http://") || item.startsWith("https://")) {
      found = await nodesFromUrl(item, 0);
    } else {
      const n = parseUri(item);
      found = n ? [n] : [];
    }
    for (let n of found) {
      if (!n.server || !n.type) continue;
      let name = String(n.name || n.type);
      if (seen.has(name)) {
        const c = seen.get(name) + 1;
        seen.set(name, c);
        name = `${name}-${c}`;
        n = { ...n, name };
      } else {
        seen.set(name, 1);
      }
      nodes.push(n);
    }
  }
  return nodes;
}

// ------------------------------------------------------------- node -> emit
function tlsSb(node) {
  const tls = { enabled: true };
  const sni = node.servername || node.sni;
  if (sni) tls.server_name = sni;
  if (node["skip-cert-verify"]) tls.insecure = true;
  if (node["client-fingerprint"]) {
    tls.utls = { enabled: true, fingerprint: node["client-fingerprint"] };
  }
  const ro = node["reality-opts"];
  if (nonEmptyObj(ro)) {
    tls.reality = {
      enabled: true,
      public_key: ro["public-key"] ?? "",
      short_id: ro["short-id"] ?? "",
    };
  }
  const eo = node["ech-opts"];
  if (isObj(eo) && eo.enable && eo["query-server-name"]) {
    tls.ech = { enabled: true, query_server_name: eo["query-server-name"] };
  }
  return tls;
}

function transportSb(node) {
  const net = String(node.network || "tcp").toLowerCase();
  if (net === "ws") {
    const ws = node["ws-opts"] || {};
    const tr = { type: "ws", path: ws.path || "/" };
    const host = (ws.headers || {}).Host;
    if (host) tr.headers = { Host: host };
    return tr;
  }
  if (net === "grpc") {
    return {
      type: "grpc",
      service_name: (node["grpc-opts"] || {})["grpc-service-name"] || "",
    };
  }
  return null;
}

function sbEmit(node) {
  const t = String(node.type || "").toLowerCase();
  const ob = {
    type: t, tag: String(node.name || t), server: node.server,
    server_port: toPort(node.port, 443),
    // sing-box 1.12 migration: replaces the legacy outbound DNS rule.
    // The chain builders repoint it at dns-cn via sbLeafFix.
    domain_resolver: "dns_resolver",
  };
  if (t === "shadowsocks" || t === "ss") {
    ob.type = "shadowsocks";
    ob.method = node.cipher || "aes-256-gcm";
    ob.password = node.password || "";
  } else if (t === "vless") {
    ob.uuid = node.uuid || "";
    if (node.flow) ob.flow = node.flow;
    if (node.tls || nonEmptyObj(node["reality-opts"])) ob.tls = tlsSb(node);
    const tr = transportSb(node);
    if (tr) ob.transport = tr;
  } else if (t === "vmess") {
    ob.uuid = node.uuid || "";
    ob.alter_id = intOr(node.alterId, 0);
    ob.security = node.cipher || "auto";
    if (node.tls || nonEmptyObj(node["reality-opts"])) ob.tls = tlsSb(node);
    const tr = transportSb(node);
    if (tr) ob.transport = tr;
  } else if (t === "trojan") {
    ob.password = node.password || "";
    ob.tls = tlsSb(node);
    const tr = transportSb(node);
    if (tr) ob.transport = tr;
  } else if (t === "tuic") {
    ob.uuid = node.uuid || "";
    ob.password = node.password || "";
    if (node["congestion-controller"]) {
      ob.congestion_control = node["congestion-controller"];
    }
    if (node["udp-relay-mode"]) ob.udp_relay_mode = node["udp-relay-mode"];
    const tls = { enabled: true };
    if (node.sni) tls.server_name = node.sni;
    if (node.alpn) tls.alpn = node.alpn;
    if (node["skip-cert-verify"]) tls.insecure = true;
    ob.tls = tls;
  } else if (t === "hysteria2" || t === "hy2") {
    ob.type = "hysteria2";
    ob.password = node.password || "";
    if (node.obfs) {
      ob.obfs = { type: node.obfs, password: node["obfs-password"] || "" };
    }
    const tls = { enabled: true };
    if (node.sni) tls.server_name = node.sni;
    if (node["skip-cert-verify"]) tls.insecure = true;
    ob.tls = tls;
  } else if (t === "anytls") {
    ob.password = node.password || "";
    ob.tls = tlsSb(node);
  } else {
    throw new Error(`unsupported node type for sing-box: ${t}`);
  }
  return ob;
}

function clashEmit(node) {
  const p = {};
  for (const [k, v] of Object.entries(node)) {
    if (v !== null && v !== undefined) p[k] = v;
  }
  if (String(p.type || "").toLowerCase() === "ss" && !("cipher" in p)) {
    p.cipher = "aes-256-gcm";
  }
  return p;
}

// ------------------------------------------------------- own rule system
// The chain configs are assembled from the bundled skeletons (copied
// verbatim from the VPS backend): groups, rules, DNS and sniffer are
// frozen, and every rule file is an official source (MetaCubeX
// meta-rules-dat for mihomo, SagerNet sing-geosite / sing-geoip for
// sing-box) served from this deployment's own KV mirror under /rules/.
// The __PUBLIC_ORIGIN__ placeholder inside the skeletons is replaced
// with the request origin at generation time.
function materialize(raw, origin) {
  return JSON.parse(JSON.stringify(raw).replaceAll("__PUBLIC_ORIGIN__", origin));
}

function fillMembers(mem, entryNames, exitNames) {
  if (Array.isArray(mem) && mem.length === 1 && MEMBER_TOKENS.has(mem[0])) {
    if (mem[0] === "@ENTRIES@") return [...entryNames];
    if (mem[0] === "@EXITS@") return [...exitNames];
    return [...entryNames, ...exitNames];
  }
  return mem;
}

function isRegionalIndicator(ch) {
  const cp = ch.codePointAt(0);
  return cp >= 0x1F1E6 && cp <= 0x1F1FF;
}

function clashPrefixedName(prefix, name) {
  // Prefix a clash node name the way the override script's name
  // normalization leaves it: a leading flag emoji stays first and the
  // prefix becomes the second word ("🇺🇸 出口- 美国 ...").
  name = name || "";
  const cps = [...name];
  if (cps.length >= 2 && isRegionalIndicator(cps[0]) &&
    isRegionalIndicator(cps[1])) {
    return cps[0] + cps[1] + " " + prefix + cps.slice(2).join("");
  }
  return prefix + name;
}

function sbLeafFix(o) {
  // Per-node normalization the sing-box overlay script applies:
  // domain_resolver is repointed at the skeleton's CN DNS (any legacy
  // domain_strategy is folded into it and dropped), TCP keep-alive
  // defaults are set on non-endpoint outbounds, and a stray name field
  // differing from the tag is removed.
  const st = String(o.domain_strategy || "");
  const cur = o.domain_resolver;
  if (isObj(cur)) {
    cur.server = "dns-cn";
    if (st && !cur.strategy) cur.strategy = st;
  } else if (cur || st) {
    o.domain_resolver = st ? { server: "dns-cn", strategy: st } : "dns-cn";
  }
  delete o.domain_strategy;
  if (o.type !== "wireguard") {
    o.tcp_keep_alive = "60s";
    if (!o.tcp_keep_alive_interval) o.tcp_keep_alive_interval = "60s";
  }
  if (o.name && o.name !== o.tag) delete o.name;
  return o;
}

function ownClashChain(eprox, xprox, origin) {
  const sk = materialize(skeletonClash, origin);
  const entries = [], exits = [];
  for (const p of eprox) {
    const q = { ...p };
    q.name = clashPrefixedName("入口-", q.name);
    entries.push(q);
  }
  for (const p of xprox) {
    const q = { ...p };
    q.name = clashPrefixedName("出口-", q.name);
    q["dialer-proxy"] = ENTRY_AUTO;
    exits.push(q);
  }
  const en = entries.map((p) => p.name);
  const xn = exits.map((p) => p.name);
  const specials = (sk.proxies || []).filter((x) => x !== "@NODES@");
  sk.proxies = [...entries, ...exits, ...specials];
  for (const g of sk["proxy-groups"] || []) {
    g.proxies = fillMembers(g.proxies, en, xn);
  }
  return [yamlDump(sk, { noRefs: true, lineWidth: 80 }),
    "text/yaml; charset=utf-8"];
}

function ownSingboxChain(enodes, xnodes, origin) {
  const sk = materialize(skeletonSingbox, origin);
  const entries = [], exits = [];
  for (const o0 of enodes) {
    const o = sbLeafFix({ ...o0 });
    delete o.detour;
    o.tag = "入口-" + o.tag;
    entries.push(o);
  }
  for (const o0 of xnodes) {
    const o = sbLeafFix({ ...o0 });
    o.tag = "出口-" + o.tag;
    o.detour = ENTRY_AUTO;
    exits.push(o);
  }
  const en = entries.map((o) => o.tag);
  const xn = exits.map((o) => o.tag);
  const out = [];
  for (const o of sk.outbounds || []) {
    if (o.type === "@nodes@") {
      out.push(...entries, ...exits);
      continue;
    }
    if ("outbounds" in o) o.outbounds = fillMembers(o.outbounds, en, xn);
    out.push(o);
  }
  sk.outbounds = out;
  return [JSON.stringify(sk, null, 2), "application/json; charset=utf-8"];
}

// ------------------------------------------------------------- ECH fix
function echQueryNames(cfg) {
  // ECH query names that need a live DNS HTTPS fetch at dial time:
  // outbounds/endpoints whose tls.ech has no inline config list.
  const names = [];
  for (const key of ["outbounds", "endpoints"]) {
    for (const o of cfg[key] || []) {
      if (!isObj(o)) continue;
      const tls = o.tls || {};
      const ech = tls.ech || {};
      if (!isObj(ech) || !Object.keys(ech).length) continue;
      if (ech.enabled === false) continue;
      let q = String(ech.query_server_name || ech["query-server-name"] || "").trim();
      if (!q && !ech.config) q = String(tls.server_name || "").trim();
      if (q && !names.includes(q)) names.push(q);
    }
  }
  return names;
}

async function fetchEchConfig(name) {
  // Fetch the live ECHConfigList for a query name via AliDNS DoH (JSON
  // API), generation-side where the network is clean. The HTTPS
  // record's TTL is about a minute, so a phone-side fetch lands on
  // nearly every fresh chained connection; inlining the config at
  // generation time removes that round trip from the dial path.
  if (ECH_CFG_CACHE.has(name)) return ECH_CFG_CACHE.get(name);
  let result = null;
  try {
    const url = "https://dns.alidns.com/resolve?name=" +
      encodeURIComponent(name) + "&type=HTTPS";
    const resp = await fetch(url, {
      headers: { Accept: "application/dns-json", "User-Agent": BROWSER_UA },
      signal: AbortSignal.timeout(6000),
    });
    const data = await resp.json();
    for (const ans of data.Answer || []) {
      const text = String(ans.data || "");
      if (text.includes('ech="')) {
        result = text.split('ech="', 2)[1].split('"', 1)[0] || null;
        if (result) break;
        result = null;
      }
    }
  } catch {
    result = null;
  }
  ECH_CFG_CACHE.set(name, result);
  return result;
}

async function ensureEchRoute(cfg) {
  // ECH self-sufficiency for generated full configs: airport entry
  // nodes carry ECH whose config list is fetched with a DNS HTTPS
  // query at dial time, but the generated DNS rules reject HTTPS/SVCB
  // queries wholesale, so every chained dial would die with
  // "fetch ECH config list: REFUSED". The current ECHConfigList is
  // inlined into each ECH outbound at generation time, a dedicated
  // AliDNS DoH server detoured via a plain direct outbound serves as
  // the fallback route, and a prepended domain rule routes the ECH
  // names to it (before the reject rule).
  const names = echQueryNames(cfg);
  if (!names.length) return cfg;
  for (const key of ["outbounds", "endpoints"]) {
    for (const o of cfg[key] || []) {
      if (!isObj(o)) continue;
      const ech = (o.tls || {}).ech || {};
      if (!isObj(ech) || !Object.keys(ech).length) continue;
      if (ech.enabled === false || ech.config) continue;
      const q = String(ech.query_server_name || ech["query-server-name"] || "").trim();
      if (!q) continue;
      const fetched = await fetchEchConfig(q);
      if (fetched) {
        // sing-box wants the ECHConfigList PEM-armored; the label
        // must be "ECH CONFIGS" (with the space, hard-checked in
        // sing-box's source) or it refuses to start.
        const chunks = [];
        for (let i = 0; i < fetched.length; i += 64) {
          chunks.push(fetched.slice(i, i + 64));
        }
        ech.config = ["-----BEGIN ECH CONFIGS-----\n" + chunks.join("\n") +
          "\n-----END ECH CONFIGS-----"];
      }
    }
  }
  const outs = cfg.outbounds || (cfg.outbounds = []);
  let bypass = null;
  for (const o of outs) {
    if (isObj(o) && o.type === "direct" && o.tag) {
      if (String(o.tag).toLowerCase() === "direct") {
        bypass = o;
        break;
      }
      if (bypass === null) bypass = o;
    }
  }
  if (bypass === null) {
    bypass = { type: "direct", tag: "direct", connect_timeout: "8s" };
    outs.push(bypass);
  } else if (!["connect_timeout", "domain_resolver", "override_address",
    "override_port", "proxy_protocol"].some((k) => k in bypass)) {
    // An empty direct outbound is not a valid detour target.
    bypass.connect_timeout = "8s";
  }
  const dns = cfg.dns || (cfg.dns = {});
  const servers = dns.servers || (dns.servers = []);
  let tag = null;
  for (const s of servers) {
    if (isObj(s) && String(s.tag || "").startsWith("ech-")) {
      tag = s.tag;
      s.detour = bypass.tag;
      break;
    }
  }
  if (tag === null) {
    tag = "ech-dns";
    if (!servers.some((s) => isObj(s) && s.tag === tag)) {
      servers.push({
        type: "https", tag: "ech-dns", server: "223.5.5.5",
        server_port: 443, path: "/dns-query",
        tls: { enabled: true, server_name: "dns.alidns.com" },
        detour: bypass.tag,
      });
    }
  }
  const rules = dns.rules || (dns.rules = []);
  const covered = new Set();
  for (const r of rules) {
    if (isObj(r) && r.server === tag) {
      if (typeof r.domain === "string") covered.add(r.domain.toLowerCase());
      else if (Array.isArray(r.domain)) {
        for (const x of r.domain) covered.add(String(x).toLowerCase());
      }
    }
  }
  const missing = names.filter((n) => !covered.has(n.toLowerCase()));
  if (missing.length) {
    rules.unshift({ domain: missing, action: "route", server: tag });
  }
  return cfg;
}

async function echFixBody(body) {
  let cfg;
  try {
    cfg = JSON.parse(body);
  } catch {
    return body;
  }
  if (echQueryNames(cfg).length) {
    await ensureEchRoute(cfg);
    return JSON.stringify(cfg, null, 2);
  }
  return body;
}

// ------------------------------------------------------------------ merges
async function mergeSingbox(entryItems, exitItems, origin) {
  STAGE.cur = "entry-convert";
  const enodesRaw = await gather(entryItems);
  if (!enodesRaw.length) throw new Error("没有可用节点");
  const enodes = enodesRaw.map(sbEmit);
  STAGE.cur = "exit-convert";
  const xnodesRaw = await gather(exitItems);
  if (!xnodesRaw.length) throw new Error("没有可用节点");
  const xnodes = xnodesRaw.map(sbEmit);
  STAGE.cur = "merge";
  if (!enodes.length || !xnodes.length) {
    throw new Error("入口或出口没有可用节点");
  }
  const built = ownSingboxChain(enodes, xnodes, origin);
  return [await echFixBody(built[0]), built[1]];
}

async function mergeClash(entryItems, exitItems, origin) {
  STAGE.cur = "entry-convert";
  const eproxRaw = await gather(entryItems);
  if (!eproxRaw.length) throw new Error("没有可用节点");
  const eprox = eproxRaw.map(clashEmit);
  STAGE.cur = "exit-convert";
  const xproxRaw = await gather(exitItems);
  if (!xproxRaw.length) throw new Error("没有可用节点");
  const xprox = xproxRaw.map(clashEmit);
  STAGE.cur = "merge";
  if (!eprox.length || !xprox.length) {
    throw new Error("入口或出口没有可用节点");
  }
  return ownClashChain(eprox, xprox, origin);
}

// ------------------------------------------------------- plain conversion
// The VPS service builds plain (non-chain) conversions from its
// captured subconverter templates, which are not part of this port.
// Here a plain conversion is assembled from the same own skeleton
// with the entry tier removed: nodes form the exit/manual tiers and
// the ⛓ 入口优选 group (and every reference to it) is dropped.
async function buildConfig(target, items, origin) {
  const nodes = await gather(items);
  if (!nodes.length) throw new Error("没有可用节点");
  if (target === "singbox") {
    const emitted = nodes.map((n) => {
      const o = sbLeafFix(sbEmit(n));
      delete o.detour;
      return o;
    });
    const tags = emitted.map((o) => o.tag);
    const sk = materialize(skeletonSingbox, origin);
    const out = [];
    for (const o of sk.outbounds || []) {
      if (o.type === "@nodes@") {
        out.push(...emitted);
        continue;
      }
      if ("outbounds" in o) o.outbounds = fillMembers(o.outbounds, [], tags);
      out.push(o);
    }
    sk.outbounds = out.filter((o) => o.tag !== ENTRY_AUTO);
    for (const g of sk.outbounds) {
      if (Array.isArray(g.outbounds)) {
        g.outbounds = g.outbounds.filter((m) => m !== ENTRY_AUTO);
      }
    }
    return [JSON.stringify(sk, null, 2), "application/json; charset=utf-8"];
  }
  const proxies = nodes.map(clashEmit);
  const names = proxies.map((p) => String(p.name));
  const sk = materialize(skeletonClash, origin);
  const specials = (sk.proxies || []).filter((x) => x !== "@NODES@");
  sk.proxies = [...proxies, ...specials];
  const groups = [];
  for (const g of sk["proxy-groups"] || []) {
    if (g.name === ENTRY_AUTO) continue;
    g.proxies = fillMembers(g.proxies, [], names);
    if (Array.isArray(g.proxies)) {
      g.proxies = g.proxies.filter((m) => m !== ENTRY_AUTO);
    }
    groups.push(g);
  }
  sk["proxy-groups"] = groups;
  return [yamlDump(sk, { noRefs: true, lineWidth: 80 }),
    "text/yaml; charset=utf-8"];
}

// ------------------------------------------------------------- short links
// Generated subscription URLs used to embed the original entry/exit
// subscription URLs (tokens included) in plaintext. A short link
// keeps only an opaque code in the URL; the mapping lives in KV.
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", _enc.encode(text));
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

function linkIdentity(record) {
  // A link's identity is its content only (kind + entry/exit, resp.
  // kind + url). The target format is NOT part of the identity; the
  // /m/ vs /s/ path letter picks it at fetch time.
  return JSON.stringify([
    record.kind ?? null, record.entry ?? null,
    record.exit ?? null, record.url ?? null,
  ]);
}

function samePayload(a, b) {
  return isObj(a) && isObj(b) &&
    (a.kind ?? null) === (b.kind ?? null) &&
    (a.entry ?? null) === (b.entry ?? null) &&
    (a.exit ?? null) === (b.exit ?? null) &&
    (a.url ?? null) === (b.url ?? null);
}

function validCode(code) {
  // User-chosen codes accept the full ASCII letter/digit set (the
  // random generator's alphabet is narrower on purpose, dropping
  // look-alike characters, but users will type 0/1/i/l/o).
  const cps = [...String(code)];
  return cps.length >= 3 && cps.length <= 32 &&
    cps.every((ch) => CODE_CHARS.includes(ch));
}

function genCode() {
  const L = LINK_ALPHABET.length;
  const limit = 256 - (256 % L);
  const buf = new Uint8Array(1);
  let code = "";
  while (code.length < 10) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) code += LINK_ALPHABET[buf[0] % L];
  }
  return code;
}

async function storeLink(env, record, wantCode) {
  // With wantCode: return it when free or already bound to the same
  // payload, and null when taken by a different payload. Without:
  // reuse the code of an identical payload (via the identity index),
  // else generate a random one.
  if (wantCode) {
    const existing = await env.KV.get("link:" + wantCode, "json");
    if (existing) return samePayload(existing, record) ? wantCode : null;
    await env.KV.put("link:" + wantCode, JSON.stringify(record));
    await env.KV.put("idx:" + await sha256Hex(linkIdentity(record)), wantCode);
    return wantCode;
  }
  const idxKey = "idx:" + await sha256Hex(linkIdentity(record));
  const existingCode = await env.KV.get(idxKey);
  if (existingCode) {
    const rec = await env.KV.get("link:" + existingCode, "json");
    if (rec && samePayload(rec, record)) return existingCode;
  }
  let code = genCode();
  while (await env.KV.get("link:" + code)) code = genCode();
  await env.KV.put("link:" + code, JSON.stringify(record));
  await env.KV.put(idxKey, code);
  return code;
}

async function getLink(env, code) {
  return env.KV.get("link:" + code, "json");
}

// ------------------------------------------------------------ rules mirror
function validRule(dst, bytes) {
  if (bytes.length < 64) return false;
  if (dst.endsWith(".svg")) {
    const head = _dec.decode(bytes.slice(0, 2048));
    return head.includes("<svg") || head.trimStart().startsWith("<?xml");
  }
  // Binary rule files must not be an HTML error page in disguise.
  let i = 0;
  while (i < bytes.length &&
    [0x20, 0x09, 0x0a, 0x0d, 0x0b, 0x0c].includes(bytes[i])) i++;
  return !(i < bytes.length && bytes[i] === 0x3c);
}

async function refreshRules(env) {
  // Download every manifest entry from its official source, validate
  // it, and put it into KV under rule:<dst>. A failed download keeps
  // the previous copy. Status lands in meta:rules_status.
  const results = new Map();
  const chunk = 8;
  for (let i = 0; i < MANIFEST.length; i += chunk) {
    const part = MANIFEST.slice(i, i + chunk);
    await Promise.all(part.map(async (entry) => {
      const { dst, src } = entry;
      try {
        const resp = await fetch(src, {
          headers: { "User-Agent": REFRESH_UA },
          signal: AbortSignal.timeout(120000),
        });
        if (!resp.ok) throw new Error("HTTP " + resp.status);
        const buf = new Uint8Array(await resp.arrayBuffer());
        if (!validRule(dst, buf)) throw new Error("validation failed");
        await env.KV.put("rule:" + dst, buf);
        results.set(dst, true);
      } catch {
        results.set(dst, false);
      }
    }));
  }
  let ok = 0;
  const failed = [];
  for (const e of MANIFEST) {
    if (results.get(e.dst)) ok++;
    else failed.push(e.dst);
  }
  const status = { time: new Date().toISOString(), ok, failed };
  await env.KV.put("meta:rules_status", JSON.stringify(status));
  return status;
}

// -------------------------------------------------------------- HTTP layer
function send(body, { status = 200, ctype = "text/plain; charset=utf-8" } = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": ctype,
      // Browser-based converter frontends call this backend cross-origin.
      "Access-Control-Allow-Origin": "*",
    },
  });
}

async function proxyToConverter(env, pathAndQuery, ua) {
  const base = (env.EXTERNAL_SUBCONVERTER_URL || "").replace(/\/+$/, "");
  if (!base) {
    return send(
      "This Cloudflare Workers variant has no built-in subconverter " +
      "for targets other than clash/singbox. Set the " +
      "EXTERNAL_SUBCONVERTER_URL variable to an external subconverter " +
      "base URL to enable those formats.", { status: 501 });
  }
  try {
    const resp = await fetch(base + pathAndQuery, {
      headers: { "User-Agent": ua },
    });
    const body = await resp.arrayBuffer();
    return send(body, {
      status: resp.status,
      ctype: resp.headers.get("Content-Type") || "text/plain",
    });
  } catch (e) {
    return send(`backend proxy failed: ${errMsg(e)}`, { status: 502 });
  }
}

async function handleShorten(request, env) {
  let data = {};
  const text = await request.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      return send("bad request", { status: 400 });
    }
    if (!isObj(data)) return send("bad request", { status: 400 });
  }
  const S = (v) => (v ? String(v) : "");
  const target = S(data.target);
  const entry = S(data.entry);
  const exit_ = S(data.exit);
  const items = S(data.url);
  const want = S(data.code).trim();
  if (want && !validCode(want)) {
    return send("自定义后缀只能用字母、数字、-、_，长度 3 到 32",
      { status: 400 });
  }
  let record;
  if (entry || exit_) {
    if (!["singbox", "clash"].includes(target) || !entry || !exit_) {
      return send("bad request", { status: 400 });
    }
    record = { kind: "chain", target, entry, exit: exit_ };
  } else if (items && target) {
    record = { kind: "conv", target, url: items };
  } else {
    return send("bad request", { status: 400 });
  }
  const code = await storeLink(env, record, want || null);
  if (code === null) {
    return send("这个后缀已被占用，换一个试试", { status: 409 });
  }
  const host = request.headers.get("Host") || new URL(request.url).host;
  const p = { clash: "m", singbox: "s" }[target];
  if (p) return send(`https://${host}/${p}/${code}`);
  return send(`https://${host}/c/${code}`);
}

async function handleFetch(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const origin = url.origin;

  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Content-Length": "0",
      },
    });
  }

  if (request.method === "POST") {
    if (path === "/shorten") return handleShorten(request, env);
    if (path === "/admin/refresh") {
      const token = env.REFRESH_TOKEN;
      if (!token ||
        request.headers.get("Authorization") !== `Bearer ${token}`) {
        return send("unauthorized", { status: 401 });
      }
      const status = await refreshRules(env);
      return send(JSON.stringify(status),
        { ctype: "application/json; charset=utf-8" });
    }
    return send("not found", { status: 404 });
  }
  if (request.method !== "GET") return send("not found", { status: 404 });

  if (path === "/" || path === "/index.html") {
    return send(PAGE, { ctype: "text/html; charset=utf-8" });
  }
  if (path.startsWith("/rules/")) {
    const rel = path.slice("/rules/".length);
    if (!DST_SET.has(rel)) return send("not found", { status: 404 });
    const data = await env.KV.get("rule:" + rel, "arrayBuffer");
    if (!data) return send("not found", { status: 404 });
    const ctype = rel.endsWith(".svg")
      ? "image/svg+xml" : "application/octet-stream";
    return send(data, { ctype });
  }

  const fmt = { c: null, m: "clash", s: "singbox" };
  const sm = path.match(/^\/([cms])\/(.+)$/);
  if (sm && path.length > 3) {
    const code = sm[2].replace(/^\/+|\/+$/g, "");
    const rec = code ? await getLink(env, code) : null;
    if (!rec) return send("link not found", { status: 404 });
    // The path letter picks the output format (m = Mihomo / clash,
    // s = sing-box); /c/ falls back to the format the link was
    // created with.
    const want = fmt[sm[1]] || rec.target || "";
    if (rec.kind === "chain") {
      STAGE.cur = "start";
      try {
        const [body, ctype] = want === "singbox"
          ? await mergeSingbox(rec.entry, rec.exit, origin)
          : await mergeClash(rec.entry, rec.exit, origin);
        return send(body, { ctype });
      } catch (e) {
        return send(`chain generate failed at ${STAGE.cur}: ${errMsg(e)}`,
          { status: 502 });
      }
    }
    const target = want;
    const items = rec.url || "";
    if ((target === "singbox" || target === "clash") && items) {
      try {
        const [body, ctype] = await buildConfig(target, items, origin);
        return send(body, { ctype });
      } catch (e) {
        return send(`convert failed: ${errMsg(e)}`, { status: 502 });
      }
    }
    const q = new URLSearchParams({ target, url: items }).toString();
    return proxyToConverter(env, "/sub?" + q, BROWSER_UA);
  }

  if (path === "/version") {
    return send("subscription-converter cf-worker");
  }
  if (path === "/sub") {
    const target = url.searchParams.get("target") || "";
    const items = url.searchParams.get("url") || "";
    if ((target === "singbox" || target === "clash") && items) {
      try {
        const [body, ctype] = await buildConfig(target, items, origin);
        return send(body, { ctype });
      } catch (e) {
        return send(`convert failed: ${errMsg(e)}`, { status: 502 });
      }
    }
    return proxyToConverter(env, path + url.search,
      request.headers.get("User-Agent") || BROWSER_UA);
  }
  if (path === "/conv") {
    const target = url.searchParams.get("target") || "";
    const items = url.searchParams.get("url") || "";
    if (!["singbox", "clash"].includes(target) || !items) {
      return send("bad request", { status: 400 });
    }
    try {
      const [body, ctype] = await buildConfig(target, items, origin);
      return send(body, { ctype });
    } catch (e) {
      return send(`convert failed: ${errMsg(e)}`, { status: 502 });
    }
  }
  if (path === "/chain") {
    const target = url.searchParams.get("target") || "";
    const entry = url.searchParams.get("entry") || "";
    const exit_ = url.searchParams.get("exit") || "";
    if (!["singbox", "clash"].includes(target) || !entry || !exit_) {
      return send("bad request: need target=singbox|clash, entry, exit",
        { status: 400 });
    }
    STAGE.cur = "start";
    try {
      const [body, ctype] = target === "singbox"
        ? await mergeSingbox(entry, exit_, origin)
        : await mergeClash(entry, exit_, origin);
      return send(body, { ctype });
    } catch (e) {
      return send(`chain generate failed at ${STAGE.cur}: ${errMsg(e)}`,
        { status: 502 });
    }
  }
  return send("not found", { status: 404 });
}

export default {
  fetch: handleFetch,
  async scheduled(event, env, ctx) {
    ctx.waitUntil(refreshRules(env));
  },
};
