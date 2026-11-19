// textchain.js — native text-format chain renderer for the VPS
// (Python) edition, extracted verbatim from the Cloudflare
// edition's worker.js (same project, subscription-chain-converter
// family) so the two editions render Surge / Loon / Quantumult X /
// V2Ray chain configs byte-identically. Driven by
// landing_server.py: JSON {target, entries, exits} of clash-style
// proxy objects on stdin, the assembled config on stdout.
"use strict";

const ENTRY_AUTO = "⛓ 入口优选";
const EXIT_AUTO = "⛓ 出口优选";

const TEST_URL = "https://www.gstatic.com/generate_204";
const AUTO_GROUP = "自动测速";
const CHAIN_GROUP = "⛓ 链式代理";

function intOr(v, dflt) {
  if (!v) return dflt;
  const n = Number(v);
  if (Number.isNaN(n)) throw new Error("bad int");
  return Math.trunc(n);
}

function textToB64(s) {
  const bytes = _enc.encode(s);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

function sniOf(node) {
  return node.servername || node.sni || "";
}

function wsHostOf(node) {
  return ((node["ws-opts"] || {}).headers || {}).Host || "";
}

function wsPathOf(node) {
  return (node["ws-opts"] || {}).path || "";
}

function grpcNameOf(node) {
  return (node["grpc-opts"] || {})["grpc-service-name"] || "";
}

function netOf(node) {
  return String(node.network || "tcp").toLowerCase();
}

function realityOf(node) {
  return nonEmptyObj(node["reality-opts"]) ? node["reality-opts"] : null;
}


function txtName(name) {
  // Remarks in the INI-style formats: '=' breaks Surge's parser
  // (subconverter replaces it with '-') and ',' is the parameter
  // separator, so both are neutralized. References are built from the
  // same sanitized names, so groups and rules stay consistent.
  return String(name ?? "").replace(/=/g, "-").replace(/,/g, " ")
    .replace(/\s+/g, " ").trim();
}


function nodeToShareLink(node) {
  const t = nodeType(node);
  const host = urlHost(hostOf(node));
  const port = portOf(node);
  const frag = "#" + encodeURIComponent(String(node.name || t));
  const sni = sniOf(node);
  const scv = node["skip-cert-verify"] === true;
  const net = netOf(node);
  const q = (pairs) => {
    const p = pairs.filter(([, v]) => v !== "" && v !== undefined &&
      v !== null);
    return p.length
      ? "?" + p.map(([k, v]) => k + "=" + encodeURIComponent(v)).join("&")
      : "";
  };
  if (t === "ss" || t === "shadowsocks") {
    const cred = b64UrlText(
      `${node.cipher || "aes-256-gcm"}:${node.password || ""}`);
    const plugin = ssPluginSip002(node);
    return `ss://${cred}@${host}:${port}` +
      (plugin ? "/?plugin=" + encodeURIComponent(plugin) : "") + frag;
  }
  if (t === "vmess") {
    const doc = {
      v: "2", ps: String(node.name || "vmess"), add: hostOf(node),
      port: String(port), id: node.uuid || "",
      aid: String(intOr(node.alterId, 0)),
      scy: node.cipher || "auto", net, type: "none",
      host: wsHostOf(node), path: wsPathOf(node),
      tls: node.tls ? "tls" : "",
    };
    if (net === "grpc") doc.path = grpcNameOf(node);
    if (sni) doc.sni = sni;
    if (Array.isArray(node.alpn) && node.alpn.length) {
      doc.alpn = node.alpn.join(",");
    }
    if (node["client-fingerprint"]) doc.fp = node["client-fingerprint"];
    return "vmess://" + textToB64(JSON.stringify(doc));
  }
  if (t === "vless") {
    const ro = realityOf(node);
    return `vless://${node.uuid || ""}@${host}:${port}` + q([
      ["encryption", "none"],
      ["security", ro ? "reality" : node.tls ? "tls" : "none"],
      ["sni", sni], ["fp", node["client-fingerprint"] || ""],
      ["pbk", ro ? ro["public-key"] || "" : ""],
      ["sid", ro ? ro["short-id"] || "" : ""],
      ["flow", node.flow || ""], ["type", net],
      ["host", wsHostOf(node)], ["path", wsPathOf(node)],
      ["serviceName", net === "grpc" ? grpcNameOf(node) : ""],
      ["allowInsecure", scv ? "1" : ""],
    ]) + frag;
  }
  if (t === "trojan") {
    return `trojan://${encodeURIComponent(node.password || "")}` +
      `@${host}:${port}` + q([
        ["sni", sni], ["type", net], ["host", wsHostOf(node)],
        ["path", wsPathOf(node)],
        ["serviceName", net === "grpc" ? grpcNameOf(node) : ""],
        ["allowInsecure", scv ? "1" : ""],
      ]) + frag;
  }
  if (t === "hysteria2") {
    return `hysteria2://${encodeURIComponent(node.password || "")}` +
      `@${host}:${port}` + q([
        ["sni", sni], ["obfs", node.obfs || ""],
        ["obfs-password", node["obfs-password"] || ""],
        ["insecure", scv ? "1" : ""],
      ]) + frag;
  }
  if (t === "tuic") {
    return `tuic://${node.uuid || ""}:` +
      `${encodeURIComponent(node.password || "")}@${host}:${port}` + q([
        ["sni", sni],
        ["alpn", Array.isArray(node.alpn) ? node.alpn.join(",") : ""],
        ["congestion_control", node["congestion-controller"] || ""],
        ["udp_relay_mode", node["udp-relay-mode"] || ""],
        ["allowInsecure", scv ? "1" : ""],
      ]) + frag;
  }
  if (t === "anytls") {
    return `anytls://${encodeURIComponent(node.password || "")}` +
      `@${host}:${port}` + q([
        ["sni", sni], ["insecure", scv ? "1" : ""],
      ]) + frag;
  }
  // snell, ssr, socks5, http, wireguard, ... have no standard share
  // link; skip rather than emit something no client can import.
  return null;
}

function surgeEmit(node) {
  const t = nodeType(node);
  const host = hostOf(node);
  const port = portOf(node);
  const sni = sniOf(node);
  const scv = node["skip-cert-verify"] === true;
  const net = netOf(node);
  const parts = [];
  const wsParams = () => {
    parts.push("ws=true");
    const p = wsPathOf(node);
    if (p) parts.push("ws-path=" + p);
    const h = wsHostOf(node);
    if (h) parts.push("ws-headers=Host:" + h);
  };
  if (t === "ss" || t === "shadowsocks") {
    parts.push("ss", host, String(port),
      "encrypt-method=" + (node.cipher || "aes-256-gcm"),
      "password=" + (node.password || ""));
    const pl = String(node.plugin || "");
    const o = node["plugin-opts"] || {};
    if (pl === "obfs") {
      parts.push("obfs=" + (o.mode || "http"));
      if (o.host) parts.push("obfs-host=" + o.host);
    } else if (pl) {
      return null; // v2ray-plugin & friends: Surge cannot express them
    }
  } else if (t === "vmess") {
    if (net !== "tcp" && net !== "ws") return null;
    parts.push("vmess", host, String(port),
      "username=" + (node.uuid || ""),
      "tls=" + (node.tls ? "true" : "false"),
      "vmess-aead=" + (intOr(node.alterId, 0) === 0 ? "true" : "false"));
    if (net === "ws") wsParams();
    const effSni = sni || wsHostOf(node);
    if (node.tls && effSni) parts.push("sni=" + effSni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "trojan") {
    if (net !== "tcp" && net !== "ws") return null;
    parts.push("trojan", host, String(port),
      "password=" + (node.password || ""));
    if (net === "ws") wsParams();
    const effSni = sni || wsHostOf(node);
    if (effSni) parts.push("sni=" + effSni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "hysteria2") {
    parts.push("hysteria2", host, String(port),
      "password=" + (node.password || ""));
    if (node.obfs) {
      parts.push("obfs=" + node.obfs);
      if (node["obfs-password"]) {
        parts.push("obfs-password=" + node["obfs-password"]);
      }
    }
    if (sni) parts.push("sni=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "anytls") {
    if (realityOf(node)) return null; // AnyTLS+Reality needs a kernel
    parts.push("anytls", host, String(port),
      "password=" + (node.password || ""));
    if (sni) parts.push("sni=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "snell") {
    parts.push("snell", host, String(port),
      "psk=" + (node.psk || node.password || ""));
    const o = node["obfs-opts"] || {};
    if (o.mode) {
      parts.push("obfs=" + o.mode);
      if (o.host) parts.push("obfs-host=" + o.host);
    }
    if (node.version) parts.push("version=" + node.version);
  } else if (t === "socks5") {
    parts.push(node.tls ? "socks5-tls" : "socks5", host, String(port));
    if (node.username) parts.push("username=" + node.username);
    if (node.password) parts.push("password=" + node.password);
    if (node.tls && sni) parts.push("sni=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "http") {
    parts.push("http", host, String(port));
    if (node.username) parts.push("username=" + node.username);
    if (node.password) parts.push("password=" + node.password);
    parts.push("tls=" + (node.tls ? "true" : "false"));
    if (scv) parts.push("skip-cert-verify=true");
  } else {
    // vless, tuic, ssr, wireguard, ... — Surge has no native syntax
    // for them (see the header note); skip.
    return null;
  }
  if (node.tfo === true) parts.push("tfo=true");
  if (node.udp === true) parts.push("udp-relay=true");
  return parts.join(", ");
}

// ------------------------------------------------------------------- Loon
// Line style follows subconverter's proxyToLoon: "Name = type,host,
// port,..." with positional credentials in double quotes. VLESS is
// emitted in Loon 3.x's own syntax (transport / over-tls / flow /

function loonEmit(node) {
  const t = nodeType(node);
  const host = hostOf(node);
  const port = portOf(node);
  const sni = sniOf(node);
  const scv = node["skip-cert-verify"] === true;
  const net = netOf(node);
  const parts = [];
  const quoted = (v) => `"${String(v ?? "")}"`;
  if (t === "ss" || t === "shadowsocks") {
    parts.push("Shadowsocks", host, String(port),
      node.cipher || "aes-256-gcm", quoted(node.password || ""));
    const pl = String(node.plugin || "");
    const o = node["plugin-opts"] || {};
    if (pl === "obfs") {
      parts.push(String(o.mode || "http"));
      if (o.host) parts.push(String(o.host));
    } else if (pl) {
      return null;
    }
  } else if (t === "ssr") {
    parts.push("ShadowsocksR", host, String(port),
      node.cipher || "aes-256-cfb", quoted(node.password || ""),
      "protocol=" + (node.protocol || "origin"),
      "protocol-param=" + (node["protocol-param"] || ""),
      "obfs=" + (node.obfs || "plain"),
      "obfs-param=" + (node["obfs-param"] || ""));
  } else if (t === "vmess") {
    if (net !== "tcp" && net !== "ws") return null;
    const method = !node.cipher || node.cipher === "auto"
      ? "chacha20-ietf-poly1305" : node.cipher;
    parts.push("vmess", host, String(port), method,
      quoted(node.uuid || ""),
      "over-tls=" + (node.tls ? "true" : "false"));
    if (node.tls && sni) parts.push("tls-name=" + sni);
    if (net === "ws") {
      parts.push("transport=ws");
      if (wsPathOf(node)) parts.push("path=" + wsPathOf(node));
      if (wsHostOf(node)) parts.push("host=" + wsHostOf(node));
    } else {
      parts.push("transport=tcp");
    }
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "vless") {
    if (net !== "tcp" && net !== "ws") return null;
    parts.push("VLESS", host, String(port), quoted(node.uuid || ""));
    if (net === "ws") {
      parts.push("transport=ws");
      if (wsPathOf(node)) parts.push("path=" + wsPathOf(node));
      if (wsHostOf(node)) parts.push("host=" + wsHostOf(node));
    } else {
      parts.push("transport=tcp");
    }
    if (node.flow) parts.push("flow=" + node.flow);
    const ro = realityOf(node);
    if (ro) {
      parts.push("public-key=" + quoted(ro["public-key"] || ""));
      if (ro["short-id"]) parts.push("short-id=" + ro["short-id"]);
    }
    parts.push("over-tls=" + (node.tls || ro ? "true" : "false"));
    if (sni) parts.push("sni=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "trojan") {
    parts.push("trojan", host, String(port), quoted(node.password || ""));
    if (net === "ws") {
      parts.push("transport=ws");
      if (wsPathOf(node)) parts.push("path=" + wsPathOf(node));
      if (wsHostOf(node)) parts.push("host=" + wsHostOf(node));
    }
    if (sni) parts.push("tls-name=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "hysteria2") {
    parts.push("hysteria2", host, String(port), quoted(node.password || ""));
    if (node.obfs) {
      parts.push("obfs=" + node.obfs);
      if (node["obfs-password"]) {
        parts.push("obfs-password=" + node["obfs-password"]);
      }
    }
    if (sni) parts.push("sni=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "tuic") {
    parts.push("tuic", host, String(port), quoted(node.uuid || ""),
      quoted(node.password || ""));
    const alpn = Array.isArray(node.alpn) && node.alpn.length
      ? node.alpn[0] : "h3";
    parts.push("alpn=" + alpn);
    if (node["congestion-controller"]) {
      parts.push("congestion-controller=" + node["congestion-controller"]);
    }
    if (node["udp-relay-mode"]) {
      parts.push("udp-relay-mode=" + node["udp-relay-mode"]);
    }
    if (sni) parts.push("sni=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "anytls") {
    parts.push("anytls", host, String(port), quoted(node.password || ""));
    if (sni) parts.push("sni=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "snell") {
    parts.push("snell", host, String(port),
      "psk=" + (node.psk || node.password || ""));
    const o = node["obfs-opts"] || {};
    if (o.mode) {
      parts.push("obfs=" + o.mode);
      if (o.host) parts.push("obfs-host=" + o.host);
    }
    if (node.version) parts.push("version=" + node.version);
  } else if (t === "socks5") {
    parts.push("socks5", host, String(port));
    if (node.username || node.password) {
      parts.push(String(node.username || ""), quoted(node.password || ""));
    }
    parts.push("over-tls=" + (node.tls ? "true" : "false"));
    if (node.tls && sni) parts.push("tls-name=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else if (t === "http") {
    parts.push(node.tls ? "https" : "http", host, String(port));
    if (node.username || node.password) {
      parts.push(String(node.username || ""), quoted(node.password || ""));
    }
    if (node.tls && sni) parts.push("tls-name=" + sni);
    if (scv) parts.push("skip-cert-verify=true");
  } else {
    return null;
  }
  if (node.tfo === true) parts.push("fast-open=true");
  if (node.udp === true) parts.push("udp=true");
  return parts.join(",");
}

// ------------------------------------------------------------------ QuanX
// Line style follows the official sample.conf: "type=host:port,
// key=value, ..., tag=Name" in [server_local]; groups are [policy]
// lines. Reality uses reality-base64-pubkey / reality-hex-shortid

function quanxEmit(node) {
  const t = nodeType(node);
  const host = hostOf(node);
  const port = portOf(node);
  const sni = sniOf(node);
  const scv = node["skip-cert-verify"] === true;
  const net = netOf(node);
  const ro = realityOf(node);
  const parts = [];
  const realityParams = () => {
    if (!ro) return;
    parts.push("reality-base64-pubkey=" + (ro["public-key"] || ""));
    if (ro["short-id"]) {
      parts.push("reality-hex-shortid=" + ro["short-id"]);
    }
  };
  // Shared vmess/vless transport mapping (sample.conf): ws -> obfs=
  // ws|wss, plain TLS -> obfs=over-tls; obfs-host carries the SNI /
  // WS host. gRPC has no QuanX form.
  const obfsParams = (withTls) => {
    if (net === "grpc") return false;
    if (net === "ws") {
      parts.push("obfs=" + (withTls ? "wss" : "ws"));
      const h = wsHostOf(node) || sni;
      if (h) parts.push("obfs-host=" + h);
      if (wsPathOf(node)) parts.push("obfs-uri=" + wsPathOf(node));
    } else if (withTls) {
      parts.push("obfs=over-tls");
      if (sni) parts.push("obfs-host=" + sni);
    }
    return true;
  };
  if (t === "ss" || t === "shadowsocks") {
    parts.push(`shadowsocks=${host}:${port}`,
      "method=" + (node.cipher || "aes-256-gcm"),
      "password=" + (node.password || ""));
    const pl = String(node.plugin || "");
    const o = node["plugin-opts"] || {};
    if (pl === "obfs") {
      parts.push("obfs=" + (o.mode || "http"));
      if (o.host) parts.push("obfs-host=" + o.host);
    } else if (pl === "v2ray-plugin") {
      parts.push("obfs=" + (o.tls ? "wss" : "ws"));
      if (o.host) parts.push("obfs-host=" + o.host);
      if (o.path) parts.push("obfs-uri=" + o.path);
    } else if (pl) {
      return null;
    }
  } else if (t === "ssr") {
    parts.push(`shadowsocks=${host}:${port}`,
      "method=" + (node.cipher || "aes-256-cfb"),
      "password=" + (node.password || ""),
      "ssr-protocol=" + (node.protocol || "origin"));
    if (node["protocol-param"]) {
      parts.push("ssr-protocol-param=" + node["protocol-param"]);
    }
    parts.push("obfs=" + (node.obfs || "plain"));
    if (node["obfs-param"]) parts.push("obfs-host=" + node["obfs-param"]);
  } else if (t === "vmess") {
    const method = !node.cipher || node.cipher === "auto"
      ? "chacha20-ietf-poly1305" : node.cipher;
    parts.push(`vmess=${host}:${port}`, "method=" + method,
      "password=" + (node.uuid || ""));
    if (intOr(node.alterId, 0) !== 0) parts.push("aead=false");
    if (!obfsParams(!!node.tls || !!ro)) return null;
    realityParams();
    if (scv) parts.push("tls-verification=false");
  } else if (t === "vless") {
    parts.push(`vless=${host}:${port}`, "method=none",
      "password=" + (node.uuid || ""));
    if (!obfsParams(!!node.tls || !!ro)) return null;
    realityParams();
    if (node.flow) parts.push("vless-flow=" + node.flow);
    if (scv) parts.push("tls-verification=false");
  } else if (t === "trojan") {
    parts.push(`trojan=${host}:${port}`,
      "password=" + (node.password || ""));
    if (net === "ws") {
      // sample.conf: trojan over WS uses obfs=wss and must not also
      // carry over-tls / tls-host.
      parts.push("obfs=wss");
      const h = wsHostOf(node) || sni;
      if (h) parts.push("obfs-host=" + h);
      if (wsPathOf(node)) parts.push("obfs-uri=" + wsPathOf(node));
      realityParams();
    } else if (net === "tcp") {
      parts.push("over-tls=true");
      if (sni) parts.push("tls-host=" + sni);
      realityParams();
      if (scv) parts.push("tls-verification=false");
    } else {
      return null;
    }
  } else if (t === "anytls") {
    parts.push(`anytls=${host}:${port}`,
      "password=" + (node.password || ""), "over-tls=true");
    if (sni) parts.push("tls-host=" + sni);
    realityParams();
    if (scv) parts.push("tls-verification=false");
  } else if (t === "socks5") {
    parts.push(`socks5=${host}:${port}`);
    if (node.username) parts.push("username=" + node.username);
    if (node.password) parts.push("password=" + node.password);
    if (node.tls) {
      parts.push("over-tls=true");
      if (sni) parts.push("tls-host=" + sni);
      realityParams();
      if (scv) parts.push("tls-verification=false");
    }
  } else if (t === "http") {
    parts.push(`http=${host}:${port}`);
    if (node.username) parts.push("username=" + node.username);
    if (node.password) parts.push("password=" + node.password);
    if (node.tls) {
      parts.push("over-tls=true");
      if (sni) parts.push("tls-host=" + sni);
      realityParams();
      if (scv) parts.push("tls-verification=false");
    }
  } else {
    // hysteria2, tuic, snell, wireguard, ... — Quantumult X cannot
    // express them; skip.
    return null;
  }
  if (node.tfo === true) parts.push("fast-open=true");
  if (node.udp === true) parts.push("udp-relay=true");
  return parts.join(", ");
}


const TEXT_EMITTERS = { surge: surgeEmit, loon: loonEmit, quanx: quanxEmit };

function renderPairs(target, nodes, rename) {
  const emit = TEXT_EMITTERS[target];
  const out = [];
  for (const n of nodes) {
    const body = emit(n);
    if (body === null) continue;
    out.push({ name: txtName(rename ? rename(n.name) : n.name), body });
  }
  return out;
}


const PRIVATE_RULES = [
  ["10.0.0.0/8"], ["100.64.0.0/10"], ["127.0.0.0/8"],
  ["172.16.0.0/12"], ["192.168.0.0/16"],
];

function assembleSurge(entries, exits) {
  const lines = [
    "# Generated by subscription-chain-converter (native Surge renderer)",
    "[General]", "loglevel = notify", "", "[Proxy]", "DIRECT = direct",
  ];
  for (const p of entries || []) lines.push(`${p.name} = ${p.body}`);
  for (const p of exits) {
    lines.push(`${p.name} = ${p.body}` +
      (entries ? `, underlying-proxy=${ENTRY_AUTO}` : ""));
  }
  const en = (entries || []).map((p) => p.name);
  const xn = exits.map((p) => p.name);
  const all = [...en, ...xn];
  lines.push("", "[Proxy Group]");
  if (entries) {
    lines.push(`${ENTRY_AUTO} = url-test, ${en.join(", ")}, ` +
      `url=${TEST_URL}, interval=20, tolerance=50`);
    lines.push(`${EXIT_AUTO} = url-test, ${xn.join(", ")}, ` +
      `url=${TEST_URL}, interval=20, tolerance=100`);
  }
  lines.push("Proxy = select, " +
    (entries ? `${EXIT_AUTO}, ${ENTRY_AUTO}, ` : "") +
    `${AUTO_GROUP}, ${all.join(", ")}, DIRECT`);
  lines.push(`${AUTO_GROUP} = url-test, ${xn.join(", ")}, ` +
    `url=${TEST_URL}, interval=20, tolerance=100`);
  lines.push("", "[Rule]");
  for (const [cidr] of PRIVATE_RULES) {
    lines.push(`IP-CIDR,${cidr},DIRECT,no-resolve`);
  }
  lines.push("IP-CIDR6,::1/128,DIRECT,no-resolve",
    "GEOIP,CN,DIRECT", "FINAL,Proxy");
  return lines.join("\n") + "\n";
}

function assembleLoon(entries, exits) {
  const lines = [
    "# Generated by subscription-chain-converter (native Loon renderer)",
    "[Proxy]",
  ];
  for (const p of entries || []) lines.push(`${p.name} = ${p.body}`);
  for (const p of exits) lines.push(`${p.name} = ${p.body}`);
  const en = (entries || []).map((p) => p.name);
  const xn = exits.map((p) => p.name);
  const all = [...en, ...xn];
  if (entries) {
    // Loon's native chaining is a Chain policy (Loon 3.1+): the
    // hops are traversed in listed order, entry group first, exit
    // group second — the same shape as the clash dialer-proxy
    // layout, expressed with Loon's own mechanism.
    lines.push("", "[Proxy Chain]",
      `${CHAIN_GROUP} = ${ENTRY_AUTO},${EXIT_AUTO},udp=true`);
  }
  lines.push("", "[Proxy Group]");
  if (entries) {
    lines.push(`${ENTRY_AUTO} = url-test,${en.join(",")},` +
      `url=${TEST_URL},interval=20,tolerance=50`);
    lines.push(`${EXIT_AUTO} = url-test,${xn.join(",")},` +
      `url=${TEST_URL},interval=20,tolerance=100`);
  }
  lines.push("Proxy = select," +
    (entries ? `${CHAIN_GROUP},${EXIT_AUTO},${ENTRY_AUTO},` : "") +
    `${AUTO_GROUP},${all.join(",")},DIRECT`);
  lines.push(`${AUTO_GROUP} = url-test,${xn.join(",")},` +
    `url=${TEST_URL},interval=20,tolerance=100`);
  lines.push("", "[Rule]");
  for (const [cidr] of PRIVATE_RULES) {
    lines.push(`IP-CIDR,${cidr},DIRECT,no-resolve`);
  }
  lines.push("IP-CIDR6,::1/128,DIRECT,no-resolve",
    "GEOIP,CN,DIRECT", "FINAL,Proxy");
  return lines.join("\n") + "\n";
}

function assembleQuanx(entries, exits) {
  const lines = [
    "# Generated by subscription-chain-converter (native Quantumult X renderer)",
    "[general]", `server_check_url = ${TEST_URL}`, "", "[server_local]",
  ];
  for (const p of entries || []) lines.push(`${p.body}, tag=${p.name}`);
  for (const p of exits) {
    lines.push(`${p.body}` +
      (entries ? `, via-server=${ENTRY_AUTO}` : "") +
      `, tag=${p.name}`);
  }
  const en = (entries || []).map((p) => p.name);
  const xn = exits.map((p) => p.name);
  const all = [...en, ...xn];
  lines.push("", "[policy]");
  if (entries) {
    lines.push(`url-latency-benchmark=${ENTRY_AUTO}, ${en.join(", ")}, ` +
      "check-interval=20, tolerance=50");
    lines.push(`url-latency-benchmark=${EXIT_AUTO}, ${xn.join(", ")}, ` +
      "check-interval=20, tolerance=100");
  }
  lines.push("static=Proxy, " +
    (entries ? `${EXIT_AUTO}, ${ENTRY_AUTO}, ` : "") +
    `${AUTO_GROUP}, ${all.join(", ")}, direct`);
  lines.push(`url-latency-benchmark=${AUTO_GROUP}, ${xn.join(", ")}, ` +
    "check-interval=20, tolerance=100");
  lines.push("", "[filter_local]");
  for (const [cidr] of PRIVATE_RULES) {
    lines.push(`ip-cidr, ${cidr}, direct`);
  }
  lines.push("ip6-cidr, ::1/128, direct", "geoip, cn, direct",
    "final, Proxy");
  return lines.join("\n") + "\n";
}

const TEXT_ASSEMBLERS = {
  surge: assembleSurge, loon: assembleLoon, quanx: assembleQuanx,
};

const TEXT_FORMAT_NAMES = {
  surge: "Surge", loon: "Loon", quanx: "Quantumult X",
};

function buildTextPlain(target, nodes) {
  if (target === "v2ray") {
    const links = [];
    for (const n of nodes) {
      const link = nodeToShareLink(n);
      if (link) links.push(link);
    }
    if (!links.length) {
      throw new Error("没有可输出为分享链接的节点");
    }
    return [textToB64(links.join("\n") + "\n"),
      "text/plain; charset=utf-8"];
  }
  const pairs = renderPairs(target, nodes, null);
  if (!pairs.length) {
    throw new Error(`没有 ${TEXT_FORMAT_NAMES[target]} 可用的节点` +
      "（该客户端不支持所给协议）");
  }
  return [TEXT_ASSEMBLERS[target](null, pairs),
    "text/plain; charset=utf-8"];
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

function chainPool(nodes) {
  return nodes.filter((n) => {
    const t = String(n.type ?? "").toLowerCase();
    return t !== "direct" && t !== "reject";
  });
}


function nodeType(node) {
  const t = String(node.type || "").toLowerCase();
  return t === "hy2" ? "hysteria2" : t;
}


function b64UrlText(s) {
  return textToB64(s).replace(/\+/g, "-").replace(/\//g, "_")
    .replace(/=+$/, "");
}


function hostOf(node) {
  return String(node.server ?? "");
}

function urlHost(host) {
  return host.includes(":") && !host.startsWith("[")
    ? `[${host}]` : host;
}


function portOf(node) {
  return toPort(node.port, 443);
}

// ------------------------------------------------------------------ Surge
// Line style follows subconverter's proxyToSurge (", " separators,
// key=value params). Per Surge's own manual the Hysteria2 type
// keyword is "hysteria2" (subconverter's "hysteria" predates it).

function nonEmptyObj(v) {
  return isObj(v) && Object.keys(v).length > 0;
}

function toPort(v, dflt) {
  if (v === null || v === undefined || v === "" || v === 0) return dflt;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : dflt;
}

function ssPluginSip002(node) {
  const pl = String(node.plugin || "");
  const o = node["plugin-opts"] || {};
  if (pl === "obfs") {
    const parts = ["obfs-local", "obfs=" + (o.mode || "http")];
    if (o.host) parts.push("obfs-host=" + o.host);
    return parts.join(";");
  }
  if (pl === "v2ray-plugin") {
    const parts = ["v2ray-plugin", "mode=" + (o.mode || "websocket")];
    if (o.tls) parts.push("tls");
    if (o.host) parts.push("host=" + o.host);
    if (o.path) parts.push("path=" + o.path);
    return parts.join(";");
  }
  return "";
}

const _enc = new TextEncoder();
const _dec = new TextDecoder();

function isObj(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}


// ------------------------------------------------------------ driver
// Post-gather half of the CF edition's mergeTextChain: the caller
// (landing_server.py) performs the gather and passes the raw pools;
// filtering and rendering happen here exactly as there.
function textChainFromPools(target, entryPool, exitPool) {
  if (target === "v2ray") {
    const xnodes = chainPool(exitPool || []);
    if (!xnodes.length) throw new Error("没有可用节点");
    return buildTextPlain("v2ray", xnodes);
  }
  const enodes = chainPool(entryPool || []);
  if (!enodes.length) throw new Error("没有可用节点");
  const xnodes = chainPool(exitPool || []);
  if (!xnodes.length) throw new Error("没有可用节点");
  const entries = renderPairs(target, enodes,
    (name) => clashPrefixedName("入口-", name));
  const exits = renderPairs(target, xnodes,
    (name) => clashPrefixedName("出口-", name));
  if (!entries.length || !exits.length) {
    throw new Error(`没有 ${TEXT_FORMAT_NAMES[target]} 可用的` +
      "入口或出口节点（该客户端不支持所给协议）");
  }
  return [TEXT_ASSEMBLERS[target](entries, exits),
    "text/plain; charset=utf-8"];
}

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (d) => { input += d; });
process.stdin.on("end", () => {
  try {
    const req = JSON.parse(input);
    const [body] = textChainFromPools(
      req.target, req.entries, req.exits);
    process.stdout.write(body);
  } catch (e) {
    process.stderr.write(String((e && e.message) || e));
    process.exit(1);
  }
});
