#!/usr/bin/env python3
"""Landing page + chain-merge service for the private converter.

Serves on 127.0.0.1:18081 by default (env SUBPAGE_PORT), reached
publicly via a tunnel or reverse proxy:
  GET /        self-contained converter page (normal + chain modes)
  GET /chain   chained-proxy subscription generator:
               ?target=singbox|clash&entry=<items>&exit=<items>
               items = node URIs and/or subscription URLs joined by |

Node ingestion and config generation are done locally (the bundled
subconverter build cannot parse VLESS nodes from any source format).
Group/rule skeletons in templates/ were captured from subconverter
output, so generated configs keep the same shape as before.
  sing-box: exit outbounds get detour -> entry selector
  clash/mihomo: exit proxies get dialer-proxy -> entry group
"""
import base64
import copy
import json
import os
import secrets
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/126.0 Safari/537.36")
GROUP_TYPES = {"selector", "urltest"}
BUILTIN_TYPES = {"direct", "block", "dns"}
ENTRY_GROUP = "⛓ 入口选择"
SENTINEL = "\x00NODES\x00"
PAGE_PORT = int(os.environ.get("SUBPAGE_PORT", "18081"))
CONVERTER_BASE = os.environ.get(
    "SUBCONVERTER_URL", "http://127.0.0.1:18080").rstrip("/")
TPL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")


# ---------------------------------------------------------------- skeletons
def _load_skeletons():
    import yaml
    sb = json.load(open(os.path.join(TPL_DIR, "singbox.json")))
    for o in sb["outbounds"]:
        if o.get("outbounds"):
            o["outbounds"] = [SENTINEL if m == "SkeletonNode" else m
                              for m in o["outbounds"]]
    sb["outbounds"] = [o for o in sb["outbounds"] if o.get("tag") != "SkeletonNode"]
    cl = yaml.safe_load(open(os.path.join(TPL_DIR, "clash.yaml")))
    for g in cl.get("proxy-groups") or []:
        if g.get("proxies"):
            g["proxies"] = [SENTINEL if m == "SkeletonNode" else m
                            for m in g["proxies"]]
    cl["proxies"] = [p for p in cl.get("proxies") or []
                     if p.get("name") != "SkeletonNode"]
    return sb, cl


SB_SKEL, CL_SKEL = _load_skeletons()


# ------------------------------------------------------------- URI -> node
def _unq(s):
    return urllib.parse.unquote(s or "")


def _b64d(s):
    s = "".join(s.split())
    return base64.b64decode(s + "=" * (-len(s) % 4))


def _apply_transport(node, q):
    net = (q.get("type") or ["tcp"])[0].lower()
    node["network"] = net
    if net == "ws":
        ws = {}
        if q.get("path"):
            ws["path"] = q["path"][0]
        if q.get("host"):
            ws["headers"] = {"Host": q["host"][0]}
        if ws:
            node["ws-opts"] = ws
    elif net == "grpc":
        if q.get("serviceName"):
            node["grpc-opts"] = {"grpc-service-name": q["serviceName"][0]}


def _apply_tls_uri(node, q):
    sec = (q.get("security") or ["none"])[0].lower()
    if sec == "reality":
        node["tls"] = True
        ro = {}
        if q.get("pbk"):
            ro["public-key"] = q["pbk"][0]
        if q.get("sid"):
            ro["short-id"] = q["sid"][0]
        node["reality-opts"] = ro
    elif sec == "tls":
        node["tls"] = True
    sni = (q.get("sni") or q.get("peer") or [None])[0]
    if sni:
        node["servername"] = sni
    if q.get("fp"):
        node["client-fingerprint"] = q["fp"][0]
    if q.get("flow"):
        node["flow"] = q["flow"][0]
    if q.get("allowInsecure") and q["allowInsecure"][0] in ("1", "true"):
        node["skip-cert-verify"] = True


def parse_uri(line):
    line = line.strip()
    if "://" not in line:
        return None
    scheme, rest = line.split("://", 1)
    scheme = scheme.lower()
    try:
        if scheme == "vmess":
            doc = json.loads(_b64d(rest.split("#")[0]))
            node = {"name": doc.get("ps") or "vmess", "type": "vmess",
                    "server": doc.get("add"), "port": int(doc.get("port") or 443),
                    "uuid": doc.get("id"), "alterId": int(doc.get("aid") or 0),
                    "cipher": doc.get("scy") or "auto",
                    "network": (doc.get("net") or "tcp").lower()}
            if doc.get("tls") == "tls":
                node["tls"] = True
            if doc.get("sni"):
                node["servername"] = doc["sni"]
            if node["network"] == "ws":
                ws = {}
                if doc.get("path"):
                    ws["path"] = doc["path"]
                if doc.get("host"):
                    ws["headers"] = {"Host": doc["host"]}
                if ws:
                    node["ws-opts"] = ws
            elif node["network"] == "grpc" and doc.get("path"):
                node["grpc-opts"] = {"grpc-service-name": doc["path"]}
            return node
        u = urllib.parse.urlparse(line)
        host, port = u.hostname, u.port
        name = _unq(u.fragment) or scheme
        q = urllib.parse.parse_qs(u.query)
        if scheme == "vless":
            node = {"name": name, "type": "vless", "server": host,
                    "port": port or 443, "uuid": _unq(u.username or "")}
            _apply_tls_uri(node, q)
            _apply_transport(node, q)
            return node
        if scheme == "trojan":
            node = {"name": name, "type": "trojan", "server": host,
                    "port": port or 443, "password": _unq(u.username or ""),
                    "tls": True}
            _apply_tls_uri(node, q)
            _apply_transport(node, q)
            return node
        if scheme == "ss":
            if u.username and u.hostname:
                ui = u.username
                try:
                    dec = _b64d(_unq(ui)).decode()
                except Exception:
                    dec = _unq(ui)
                method, _, pwd = dec.partition(":")
                node = {"name": name, "type": "ss", "server": host,
                        "port": port or 8388, "cipher": method, "password": pwd}
            else:
                doc = _b64d(rest.split("#")[0]).decode()
                cred, _, addr = doc.rpartition("@")
                method, _, pwd = cred.partition(":")
                h, _, p = addr.rpartition(":")
                node = {"name": name, "type": "ss", "server": h,
                        "port": int(p or 8388), "cipher": method, "password": pwd}
            return node
        if scheme in ("hysteria2", "hy2"):
            node = {"name": name, "type": "hysteria2", "server": host,
                    "port": port or 443,
                    "password": _unq(u.username or "")}
            if q.get("sni"):
                node["sni"] = q["sni"][0]
            if q.get("obfs"):
                node["obfs"] = q["obfs"][0]
            if q.get("obfs-password"):
                node["obfs-password"] = q["obfs-password"][0]
            if q.get("insecure") and q["insecure"][0] in ("1", "true"):
                node["skip-cert-verify"] = True
            return node
        if scheme == "tuic":
            user = _unq(u.username or "")
            uuid, _, pwd = user.partition(":")
            node = {"name": name, "type": "tuic", "server": host,
                    "port": port or 443, "uuid": uuid, "password": pwd}
            if q.get("sni"):
                node["sni"] = q["sni"][0]
            if q.get("alpn"):
                node["alpn"] = [q["alpn"][0]]
            if q.get("congestion_control"):
                node["congestion-controller"] = q["congestion_control"][0]
            if q.get("udp_relay_mode"):
                node["udp-relay-mode"] = q["udp_relay_mode"][0]
            return node
        if scheme == "anytls":
            node = {"name": name, "type": "anytls", "server": host,
                    "port": port or 443, "password": _unq(u.username or ""),
                    "tls": True}
            if q.get("sni"):
                node["servername"] = q["sni"][0]
            return node
    except Exception:
        return None
    return None


# ------------------------------------------------- sing-box outbound -> node
def sb_to_node(o):
    t = o.get("type")
    node = {"name": o.get("tag"), "type": t, "server": o.get("server"),
            "port": o.get("server_port")}
    tls = o.get("tls") or {}
    if tls.get("enabled"):
        node["tls"] = True
        if tls.get("server_name"):
            node["servername"] = tls["server_name"]
        if tls.get("insecure"):
            node["skip-cert-verify"] = True
        if tls.get("utls", {}).get("fingerprint"):
            node["client-fingerprint"] = tls["utls"]["fingerprint"]
        if tls.get("reality", {}).get("enabled"):
            node["reality-opts"] = {
                "public-key": tls["reality"].get("public_key", ""),
                "short-id": tls["reality"].get("short_id", "")}
    tr = o.get("transport") or {}
    if tr.get("type") == "ws":
        node["network"] = "ws"
        ws = {}
        if tr.get("path"):
            ws["path"] = tr["path"]
        host = (tr.get("headers") or {}).get("Host")
        if host:
            ws["headers"] = {"Host": host}
        if ws:
            node["ws-opts"] = ws
    elif tr.get("type") == "grpc":
        node["network"] = "grpc"
        if tr.get("service_name"):
            node["grpc-opts"] = {"grpc-service-name": tr["service_name"]}
    if t in ("vless", "vmess", "tuic"):
        node["uuid"] = o.get("uuid")
    if t == "vless":
        if o.get("flow"):
            node["flow"] = o["flow"]
    if t == "vmess":
        node["alterId"] = o.get("alter_id") or 0
        node["cipher"] = o.get("security") or "auto"
    if t in ("trojan", "anytls"):
        node["password"] = o.get("password")
    if t == "shadowsocks":
        node["type"] = "ss"
        node["cipher"] = o.get("method")
        node["password"] = o.get("password")
    if t == "tuic":
        node["password"] = o.get("password")
        if o.get("congestion_control"):
            node["congestion-controller"] = o["congestion_control"]
        if o.get("udp_relay_mode"):
            node["udp-relay-mode"] = o["udp_relay_mode"]
    if t == "hysteria2":
        node["password"] = o.get("password") or o.get("auth")
        if o.get("obfs", {}).get("password"):
            node["obfs"] = o["obfs"].get("type") or "salamander"
            node["obfs-password"] = o["obfs"]["password"]
    return node


# ---------------------------------------------------------------- gathering
def _classify_text(text, depth=0):
    """Return a list of node dicts from raw subscription content."""
    text = text.strip()
    if not text:
        return []
    if text.startswith("{"):
        try:
            doc = json.loads(text)
            if isinstance(doc, dict) and doc.get("outbounds"):
                return [sb_to_node(o) for o in doc["outbounds"]
                        if o.get("type") not in GROUP_TYPES | BUILTIN_TYPES
                        and o.get("server")]
        except Exception:
            pass
    try:
        import yaml
        doc = yaml.safe_load(text)
        if isinstance(doc, dict) and doc.get("proxies"):
            return [p for p in doc["proxies"] if isinstance(p, dict)]
        if isinstance(doc, dict) and doc.get("proxy-providers") and depth < 2:
            # Full Mihomo configs often carry nodes only via providers:
            # resolve each provider URL and gather its nodes instead.
            nodes = []
            for pv in (doc["proxy-providers"] or {}).values():
                url = (pv or {}).get("url")
                if url:
                    nodes += _nodes_from_url(url, depth + 1)
            if nodes:
                return nodes
    except Exception:
        pass
    try:
        decoded = _b64d(text).decode("utf-8", "replace")
        if "://" in decoded or "proxies:" in decoded:
            inner = _classify_text(decoded, depth)
            if inner:
                return inner
    except Exception:
        pass
    return [n for n in (parse_uri(l) for l in text.splitlines()) if n]


def _fetch(url, ua):
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode("utf-8", "replace")


def _fetch_nodes(url):
    return _nodes_from_url(url, 0)


def _nodes_from_url(url, depth):
    # Aggregators serve different renditions per UA: a Mihomo client UA
    # gets the full Clash YAML (incl. ECH options); a browser UA gets a
    # reduced format. Try the client UA first, browser UA as fallback.
    for ua in ("clash-verge/2.2.3", "clash-verge/2.2.3",
               "sing-box/1.15.0", BROWSER_UA):
        try:
            found = _classify_text(_fetch(url, ua), depth)
            if found:
                return found
        except Exception:
            continue
    return []


def gather(items):
    nodes, seen = [], {}
    for item in items.split("|"):
        item = item.strip()
        if not item:
            continue
        if item.startswith(("http://", "https://")):
            found = _fetch_nodes(item)
        else:
            found = [n for n in [parse_uri(item)] if n]
        for n in found:
            if not n.get("server") or not n.get("type"):
                continue
            name = str(n.get("name") or n["type"])
            if name in seen:
                seen[name] += 1
                name = f"{name}-{seen[name]}"
                n = dict(n)
                n["name"] = name
            else:
                seen[name] = 1
            nodes.append(n)
    return nodes


# ------------------------------------------------------------- node -> emit
def _tls_sb(node):
    tls = {"enabled": True}
    sni = node.get("servername") or node.get("sni")
    if sni:
        tls["server_name"] = sni
    if node.get("skip-cert-verify"):
        tls["insecure"] = True
    if node.get("client-fingerprint"):
        tls["utls"] = {"enabled": True,
                       "fingerprint": node["client-fingerprint"]}
    ro = node.get("reality-opts") or {}
    if ro:
        tls["reality"] = {"enabled": True,
                          "public_key": ro.get("public-key", ""),
                          "short_id": ro.get("short-id", "")}
    eo = node.get("ech-opts") or {}
    if eo.get("enable") and eo.get("query-server-name"):
        tls["ech"] = {"enabled": True,
                      "query_server_name": eo["query-server-name"]}
    return tls


def _transport_sb(node):
    net = (node.get("network") or "tcp").lower()
    if net == "ws":
        ws = node.get("ws-opts") or {}
        tr = {"type": "ws", "path": ws.get("path") or "/"}
        host = (ws.get("headers") or {}).get("Host")
        if host:
            tr["headers"] = {"Host": host}
        return tr
    if net == "grpc":
        return {"type": "grpc",
                "service_name": (node.get("grpc-opts") or {}).get(
                    "grpc-service-name", "")}
    return None


def sb_emit(node):
    t = (node.get("type") or "").lower()
    ob = {"type": t, "tag": str(node.get("name") or t),
          "server": node.get("server"), "server_port": int(node.get("port") or 443),
          # sing-box 1.12 migration: replaces the legacy outbound DNS rule.
          "domain_resolver": "dns_resolver"}
    if t == "shadowsocks" or t == "ss":
        ob["type"] = "shadowsocks"
        ob["method"] = node.get("cipher") or "aes-256-gcm"
        ob["password"] = node.get("password") or ""
    elif t == "vless":
        ob["uuid"] = node.get("uuid") or ""
        if node.get("flow"):
            ob["flow"] = node["flow"]
        if node.get("tls") or node.get("reality-opts"):
            ob["tls"] = _tls_sb(node)
        tr = _transport_sb(node)
        if tr:
            ob["transport"] = tr
    elif t == "vmess":
        ob["uuid"] = node.get("uuid") or ""
        ob["alter_id"] = int(node.get("alterId") or 0)
        ob["security"] = node.get("cipher") or "auto"
        if node.get("tls") or node.get("reality-opts"):
            ob["tls"] = _tls_sb(node)
        tr = _transport_sb(node)
        if tr:
            ob["transport"] = tr
    elif t == "trojan":
        ob["password"] = node.get("password") or ""
        ob["tls"] = _tls_sb(node)
        tr = _transport_sb(node)
        if tr:
            ob["transport"] = tr
    elif t == "tuic":
        ob["uuid"] = node.get("uuid") or ""
        ob["password"] = node.get("password") or ""
        if node.get("congestion-controller"):
            ob["congestion_control"] = node["congestion-controller"]
        if node.get("udp-relay-mode"):
            ob["udp_relay_mode"] = node["udp-relay-mode"]
        tls = {"enabled": True}
        if node.get("sni"):
            tls["server_name"] = node["sni"]
        if node.get("alpn"):
            tls["alpn"] = node["alpn"]
        if node.get("skip-cert-verify"):
            tls["insecure"] = True
        ob["tls"] = tls
    elif t in ("hysteria2", "hy2"):
        ob["type"] = "hysteria2"
        ob["password"] = node.get("password") or ""
        if node.get("obfs"):
            ob["obfs"] = {"type": node["obfs"],
                          "password": node.get("obfs-password") or ""}
        tls = {"enabled": True}
        if node.get("sni"):
            tls["server_name"] = node["sni"]
        if node.get("skip-cert-verify"):
            tls["insecure"] = True
        ob["tls"] = tls
    elif t == "anytls":
        ob["password"] = node.get("password") or ""
        ob["tls"] = _tls_sb(node)
    else:
        raise ValueError(f"unsupported node type for sing-box: {t}")
    return ob


def clash_emit(node):
    p = {k: v for k, v in node.items() if v is not None}
    if (p.get("type") or "").lower() == "ss" and "cipher" not in p:
        p["cipher"] = "aes-256-gcm"
    return p


# ------------------------------------------------------------- full configs
def build_config(target, items):
    nodes = gather(items)
    if not nodes:
        raise ValueError("没有可用节点")
    if target == "singbox":
        cfg = copy.deepcopy(SB_SKEL)
        emitted = [sb_emit(n) for n in nodes]
        tags = [o["tag"] for o in emitted]
        out = [o for o in cfg["outbounds"] if o.get("type") in BUILTIN_TYPES]
        out += emitted
        for o in cfg["outbounds"]:
            if o.get("type") in GROUP_TYPES:
                g = dict(o)
                members = []
                for m in g.get("outbounds", []):
                    members += tags if m == SENTINEL else [m]
                g["outbounds"] = members
                out.append(g)
        cfg["outbounds"] = out
        return (json.dumps(cfg, ensure_ascii=False, indent=2),
                "application/json; charset=utf-8")
    import yaml
    cfg = copy.deepcopy(CL_SKEL)
    proxies = [clash_emit(n) for n in nodes]
    names = [str(p.get("name")) for p in proxies]
    groups = []
    for g in cfg.get("proxy-groups") or []:
        g = dict(g)
        members = []
        for m in g.get("proxies") or []:
            members += names if m == SENTINEL else [m]
        g["proxies"] = members
        groups.append(g)
    cfg["proxies"] = proxies
    cfg["proxy-groups"] = groups
    return (yaml.safe_dump(cfg, allow_unicode=True, sort_keys=False),
            "text/yaml; charset=utf-8")


STAGE = {"cur": "-"}


def sub_convert(target, items):
    """Kept name/signature from the subconverter era; conversion is local."""
    return build_config(target, items)[0]


# ------------------------------------------------------------------- merge
ENTRY_AUTO = "⛓ 入口优选"
EXIT_AUTO = "⛓ 出口优选"
PUBDNS_DOMAINS = [
    "dns.google", "cloudflare-dns.com", "dns.cloudflare.com",
    "one.one.one.one", "doh.pub", "dns.alidns.com", "dns.quad9.net",
    "quad9.net", "dns.adguard-dns.com", "dns.nextdns.io", "dns.sb",
    "dns.mullvad.net", "dns.opendns.com", "umbrella.com",
]
PUBDNS_IPS = [
    "1.1.1.1/32", "1.0.0.1/32", "8.8.8.8/32", "8.8.4.4/32",
    "9.9.9.9/32", "149.112.112.112/32", "208.67.222.222/32",
    "208.67.220.220/32", "223.5.5.5/32", "223.6.6.6/32",
    "119.29.29.29/32", "114.114.114.114/32", "180.76.76.76/32",
    "168.95.1.1/32", "101.102.103.104/32", "94.140.14.14/32",
    "2606:4700:4700::1111/128", "2606:4700:4700::1001/128",
    "2001:4860:4860::8888/128", "2001:4860:4860::8844/128",
    "2620:fe::fe/128", "2620:fe::9/128", "2400:3200::1/128",
    "2400:3200:baba::1/128",
]
OLD_AUTO = "♻️ 自动选择"
TEST_URL = "https://www.gstatic.com/generate_204"
CLASH_DNS = {
    "enable": True,
    "ipv6": False,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": ["*.lan", "*.local", "localhost.ptlogin2.qq.com"],
    "respect-rules": True,
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "proxy-server-nameserver": ["223.5.5.5", "119.29.29.29"],
    "nameserver": ["https://cloudflare-dns.com/dns-query#🔰 节点选择",
                   "https://dns.google/dns-query#🔰 节点选择"],
    "nameserver-policy": {
        "geosite:cn": ["https://dns.alidns.com/dns-query",
                       "https://doh.pub/dns-query"],
        "geosite:geolocation-!cn": ["https://cloudflare-dns.com/dns-query#🔰 节点选择",
                                    "https://dns.google/dns-query#🔰 节点选择"],
    },
}


# --- Bundled base configuration -------------------------------------------
# Values extracted verbatim from the bundled override script
# (mihomoScript.js) into clash-base.json (same directory). The script's
# default-proxy group is substituted with this converter's main selector
# at load time. If the file is missing, the converter falls back to the
# built-in CLASH_DNS and the simple STUN port rules above.
def _clashbase_load():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "clash-base.json")
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return None

    def sub(v):
        if isinstance(v, str):
            return v.replace("默认代理", "🔰 节点选择")
        if isinstance(v, list):
            return [sub(x) for x in v]
        if isinstance(v, dict):
            return {k: sub(x) for k, x in v.items()}
        return v

    return sub(data)


CLASHBASE = _clashbase_load()


def _nodes(cfg):
    return [o for o in cfg["outbounds"]
            if o.get("type") not in GROUP_TYPES | BUILTIN_TYPES]


# Overlay switches for the sing-box overlay script, fixed for this
# backend (in the app these come from the user's settings; the script
# defaults them all to on when no overlay object exists).
SB_OVERLAY = {
    "chinaDirect": True,
    "adsBlock": True,
    "webrtcProtect": True,
    "disableQuic": True,
    "excludeCnQuic": True,
    "disableIpv6": True,
    "dnsProtect": True,
    "strictRoute": True,
}


def _overlay_chain(enodes, xnodes):
    """Build the sing-box chain config with the bundled overlay script.

    The script (singbox-overlay.js, bundled with two marked backend
    adaptations) rebuilds groups, rules,
    rule-sets and DNS from the leaf nodes. It strips detour by design,
    so chaining is re-applied afterwards: exit outbounds (matched by
    server+port) get their detour back and the entry url-test group is
    appended. Any anomaly (script failure, an exit node lost) returns
    None and the caller falls back to the built-in merge.
    """
    import subprocess
    import tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "singbox-overlay.js")
    runner = os.path.join(here, "apply_overlay.js")
    if not (os.path.exists(script) and os.path.exists(runner)):
        return None
    node = next((c for c in NODE_CANDIDATES
                 if c == "node" or os.path.exists(c)), None)
    if node is None:
        return None
    base_out, entry_keys, exit_keys = [], set(), set()
    for o in enodes:
        o = dict(o)
        o["tag"] = "入口-" + o["tag"]
        entry_keys.add((o.get("server"), o.get("server_port")))
        base_out.append(o)
    for o in xnodes:
        o = dict(o)
        o["tag"] = "出口-" + o["tag"]
        exit_keys.add((o.get("server"), o.get("server_port")))
        base_out.append(o)
    tmp = tempfile.mkdtemp(prefix="sboverlay-")
    try:
        fin = os.path.join(tmp, "base.json")
        fov = os.path.join(tmp, "overlay.json")
        fout = os.path.join(tmp, "out.json")
        with open(fin, "w", encoding="utf-8") as f:
            json.dump({"outbounds": base_out}, f, ensure_ascii=False)
        with open(fov, "w", encoding="utf-8") as f:
            json.dump(SB_OVERLAY, f)
        r = subprocess.run([node, runner, script, fin, fov, fout],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            print("singbox overlay failed:", r.stderr.decode()[:300],
                  flush=True)
            return None
        with open(fout, encoding="utf-8") as f:
            out = json.load(f)
    except Exception as e:
        print("singbox overlay error:", e, flush=True)
        return None
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    entry_tags, exit_tags, exit_seen = [], [], 0
    for o in out.get("outbounds") or []:
        key = (o.get("server"), o.get("server_port"))
        if key in exit_keys:
            o["detour"] = ENTRY_AUTO
            exit_seen += 1
            exit_tags.append(o["tag"])
        elif key in entry_keys:
            entry_tags.append(o["tag"])
    if exit_seen < len(exit_keys) or not entry_tags:
        print("singbox overlay: chain re-apply incomplete", flush=True)
        return None
    out.setdefault("outbounds", []).append({
        "type": "urltest", "tag": ENTRY_AUTO, "outbounds": entry_tags,
        "url": TEST_URL, "interval": "1m", "tolerance": 100,
        "interrupt_exist_connections": False})
    for ib in out.get("inbounds") or []:
        for f in ("sniff", "sniff_override_destination", "sniff_timeout",
                  "domain_strategy"):
            ib.pop(f, None)
    route = out.setdefault("route", {})
    rrules = route.setdefault("rules", [])
    if not any(r.get("action") == "sniff" for r in rrules):
        rrules.insert(0, {"action": "sniff"})
    # BACKEND-ADAPTED (2026-10-25): same group restructure as the
    # clash chain path. The overlay script groups nodes by region,
    # mixing entries and exits, and its auto urltest can pick a
    # single-hop entry. Entries end up only in the entry auto group
    # (plus the manual group, untouched), exits get a dedicated
    # select group leading the main selector, and region groups are
    # removed: emptied ones retarget to the main selector, exit-only
    # ones to the exit group. Selector defaults, detours, DNS
    # detours and rule targets are kept pointing at live groups.
    _obs = out.get("outbounds") or []
    _route = out.get("route") or {}
    _main_tag = "默认代理" if any(
        o.get("tag") == "默认代理" for o in _obs) else \
        (_route.get("final") or "默认代理")
    _groups = {o.get("tag"): o for o in _obs
               if o.get("type") in ("selector", "urltest")}
    if _main_tag not in _groups or not exit_tags:
        print("overlay chain: main selector missing", flush=True)
        return None
    _entry_set = set(entry_tags)
    _exit_set = set(exit_tags)
    for _tag, _g in _groups.items():
        if _tag in (ENTRY_AUTO, "手动选择"):
            continue
        _mem = _g.get("outbounds")
        if isinstance(_mem, list):
            _g["outbounds"] = [m for m in _mem if m not in _entry_set]
    _deleted = set()
    while True:
        _empties = [_t for _t, _g in _groups.items()
                    if _t not in (_main_tag, ENTRY_AUTO)
                    and _t not in _deleted
                    and not (_g.get("outbounds") or [])]
        if not _empties:
            break
        _deleted.update(_empties)
        for _g in _groups.values():
            _mem = _g.get("outbounds")
            if isinstance(_mem, list):
                _g["outbounds"] = [m for m in _mem if m not in _deleted]
    _live = {t: g for t, g in _groups.items() if t not in _deleted}
    _leaf_set = {o.get("tag") for o in _obs
                 if o.get("type") not in ("selector", "urltest")}

    def _sb_leaves(_name, _seen=None):
        if _seen is None:
            _seen = set()
        if _name in _seen:
            return set()
        _seen.add(_name)
        _g = _live.get(_name)
        if _g is None:
            return set()
        _found = set()
        for _m in _g.get("outbounds") or []:
            if _m in _leaf_set:
                _found.add(_m)
            elif _m in _live:
                _found |= _sb_leaves(_m, _seen)
        return _found

    _keep = {_main_tag, ENTRY_AUTO, "手动选择", "自动选择",
             EXIT_AUTO}
    _region = set()
    for _t in list(_live):
        if _t in _keep:
            continue
        _lv = _sb_leaves(_t)
        if _lv and _lv <= _exit_set:
            _region.add(_t)
    _gone = _deleted | _region

    def _sb_retarget(_name):
        if _name in _region:
            return EXIT_AUTO
        if _name in _deleted:
            return _main_tag
        return _name

    _exit_group = {"type": "urltest", "tag": EXIT_AUTO,
                   "outbounds": list(exit_tags), "url": TEST_URL,
                   "interval": "1m", "tolerance": 100,
                   "interrupt_exist_connections": False}
    for _t, _g in _live.items():
        if _t in _region:
            continue
        _mem = _g.get("outbounds")
        if isinstance(_mem, list):
            _new_mem = []
            for _m in _mem:
                if _m in _region:
                    _tgt = EXIT_AUTO
                elif _m in _deleted or _m == _t:
                    continue
                else:
                    _tgt = _m
                if _tgt not in _new_mem:
                    _new_mem.append(_tgt)
            _g["outbounds"] = _new_mem
    for _t, _g in _live.items():
        if _t in _region:
            continue
        _d = _g.get("default")
        _mem = _g.get("outbounds") or []
        if _d is not None and _d not in _mem:
            if _d in _region and EXIT_AUTO in _mem:
                _g["default"] = EXIT_AUTO
            elif _mem:
                _g["default"] = _mem[0]
            else:
                _g.pop("default", None)
    for _r in _route.get("rules") or []:
        if _r.get("outbound") in _gone:
            _r["outbound"] = _sb_retarget(_r.get("outbound"))
    for _srv in (out.get("dns") or {}).get("servers") or []:
        if _srv.get("detour") in _gone:
            _srv["detour"] = _sb_retarget(_srv.get("detour"))
    _final_obs = [_exit_group]
    if ENTRY_AUTO in _live:
        _final_obs.append(_live[ENTRY_AUTO])
    for _o in _obs:
        if _o.get("tag") in _gone or _o.get("tag") == ENTRY_AUTO:
            continue
        if _o.get("detour") in _gone:
            _o["detour"] = _sb_retarget(_o.get("detour"))
        _final_obs.append(_o)
    _main_g = _live.get(_main_tag) or {}
    _mem = [m for m in (_main_g.get("outbounds") or [])
            if m not in (EXIT_AUTO, ENTRY_AUTO)]
    _main_g["outbounds"] = [EXIT_AUTO, ENTRY_AUTO] + _mem
    out["outbounds"] = _final_obs
    return json.dumps(out, ensure_ascii=False, indent=2), \
        "application/json; charset=utf-8"


def _ech_query_names(cfg):
    """ECH query names that need a live DNS HTTPS fetch at dial time:
    outbounds/endpoints whose tls.ech has no inline config list. Mirrors
    the ECH query-route scan a client applies to configs it builds."""
    names = []
    for key in ("outbounds", "endpoints"):
        for o in cfg.get(key) or []:
            if not isinstance(o, dict):
                continue
            tls = o.get("tls") or {}
            ech = tls.get("ech") or {}
            if not isinstance(ech, dict) or not ech:
                continue
            if ech.get("enabled") is False:
                continue
            q = str(ech.get("query_server_name") or
                    ech.get("query-server-name") or "").strip()
            if not q and not ech.get("config"):
                q = str(tls.get("server_name") or "").strip()
            if q and q not in names:
                names.append(q)
    return names


_ECH_CFG_CACHE = {}


def _fetch_ech_config(name):
    """Fetch the live ECHConfigList for a query name via AliDNS DoH
    (JSON API), server-side where the network is clean. The HTTPS
    record's TTL is about a minute, so a phone-side fetch lands on
    nearly every fresh chained connection; inlining the config at
    generation time removes that round trip from the dial path.
    Returns the base64 config string, or None on any failure."""
    if name in _ECH_CFG_CACHE:
        return _ECH_CFG_CACHE[name]
    result = None
    try:
        url = ("https://dns.alidns.com/resolve?name=" +
               urllib.parse.quote(name) + "&type=HTTPS")
        req = urllib.request.Request(url, headers={
            "Accept": "application/dns-json", "User-Agent": BROWSER_UA})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
        for ans in data.get("Answer") or []:
            text = str(ans.get("data") or "")
            if 'ech="' in text:
                result = text.split('ech="', 1)[1].split('"', 1)[0]
                if result:
                    break
                result = None
    except Exception:
        result = None
    _ECH_CFG_CACHE[name] = result
    return result


def _ensure_ech_route(cfg):
    """ECH self-sufficiency for generated full configs (2026-10-26).

    Airport entry nodes carry ECH whose config list is fetched with a
    DNS HTTPS query at dial time, but the generated DNS rules reject
    HTTPS/SVCB queries wholesale, so every chained dial died with
    "fetch ECH config list: REFUSED" on the phone. Some clients apply
    this same fix to configs they build themselves (a dedicated AliDNS
    DoH server detoured via a plain direct outbound, plus a prepended
    domain rule for the ECH names) but deliberately leave full sing-box
    files alone, so the generated file must carry the routing itself. On top of the route, the current ECHConfigList
    is inlined into each ECH outbound at generation time (the record
    TTL is ~56s, so runtime fetching repeats constantly and adds a
    DoH round trip to most fresh chained connections); the route
    stays as the fallback if an inlined config ever goes stale."""
    names = _ech_query_names(cfg)
    if not names:
        return cfg
    for key in ("outbounds", "endpoints"):
        for o in cfg.get(key) or []:
            if not isinstance(o, dict):
                continue
            ech = (o.get("tls") or {}).get("ech") or {}
            if not isinstance(ech, dict) or not ech:
                continue
            if ech.get("enabled") is False or ech.get("config"):
                continue
            q = str(ech.get("query_server_name") or
                    ech.get("query-server-name") or "").strip()
            if not q:
                continue
            fetched = _fetch_ech_config(q)
            if fetched:
                # sing-box wants the ECHConfigList PEM-armored
                # ("invalid ECH configs pem" otherwise); the DNS
                # record carries it as bare base64.
                wrapped = "\n".join(
                    fetched[i:i + 64] for i in range(0, len(fetched), 64))
                ech["config"] = ["-----BEGIN ECH CONFIGS-----\n" + wrapped +
                                  "\n-----END ECH CONFIGS-----"]
    outs = cfg.setdefault("outbounds", [])
    bypass = None
    for o in outs:
        if isinstance(o, dict) and o.get("type") == "direct" and o.get("tag"):
            if str(o["tag"]).lower() == "direct":
                bypass = o
                break
            if bypass is None:
                bypass = o
    if bypass is None:
        bypass = {"type": "direct", "tag": "direct", "connect_timeout": "8s"}
        outs.append(bypass)
    elif not any(k in bypass for k in ("connect_timeout", "domain_resolver",
                                      "override_address", "override_port",
                                      "proxy_protocol")):
        # An empty direct outbound is not a valid detour target.
        bypass["connect_timeout"] = "8s"
    dns = cfg.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    tag = None
    for s in servers:
        if isinstance(s, dict) and str(s.get("tag", "")).startswith("ech-"):
            tag = s["tag"]
            s["detour"] = bypass["tag"]
            break
    if tag is None:
        tag = "ech-dns"
        if not any(isinstance(s, dict) and s.get("tag") == tag
                   for s in servers):
            servers.append({
                "type": "https", "tag": "ech-dns", "server": "223.5.5.5",
                "server_port": 443, "path": "/dns-query",
                "tls": {"enabled": True, "server_name": "dns.alidns.com"},
                "detour": bypass["tag"],
            })
    rules = dns.setdefault("rules", [])
    covered = set()
    for r in rules:
        if isinstance(r, dict) and r.get("server") == tag:
            d = r.get("domain")
            if isinstance(d, str):
                covered.add(d.lower())
            elif isinstance(d, list):
                covered.update(str(x).lower() for x in d)
    missing = [n for n in names if n.lower() not in covered]
    if missing:
        rules.insert(0, {"domain": missing, "action": "route",
                         "server": tag})
    return cfg


def _ech_fix_body(body):
    try:
        cfg = json.loads(body)
    except Exception:
        return body
    if _ech_query_names(cfg):
        _ensure_ech_route(cfg)
        return json.dumps(cfg, ensure_ascii=False, indent=2)
    return body


# ------------------------------------------------------- own rule system
# Since 2026-10-27 the chain configs are assembled from backend-owned
# skeletons (skeleton_clash.json / skeleton_singbox.json in this
# directory, harvested from the last script-built outputs and frozen):
# groups, rules, DNS and sniffer match what the bundled override / overlay
# scripts produced, but every rule file is an official source
# (MetaCubeX meta-rules-dat for mihomo, SagerNet sing-geosite /
# sing-geoip for sing-box) served from our own mirror under /rules/
# and refreshed daily by refresh_rules.py. The scripts stay on disk
# as an automatic fallback if a skeleton is missing or a build
# fails, so rollback needs no action.
_SKELETON_CACHE = {}
_MANIFEST_CACHE = None
_RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "rules_files")
_MEMBER_TOKENS = ("@ENTRIES@", "@EXITS@", "@ALL@")


def _skeleton(name):
    if name not in _SKELETON_CACHE:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            name)
        with open(path, encoding="utf-8") as f:
            _SKELETON_CACHE[name] = json.load(f)
    return copy.deepcopy(_SKELETON_CACHE[name])


def _manifest_dsts():
    global _MANIFEST_CACHE
    if _MANIFEST_CACHE is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "rules_manifest.json")
        with open(path, encoding="utf-8") as f:
            _MANIFEST_CACHE = {e["dst"] for e in json.load(f)}
    return _MANIFEST_CACHE


def _fill_members(mem, entry_names, exit_names):
    if (isinstance(mem, list) and len(mem) == 1
            and mem[0] in _MEMBER_TOKENS):
        if mem[0] == "@ENTRIES@":
            return list(entry_names)
        if mem[0] == "@EXITS@":
            return list(exit_names)
        return list(entry_names) + list(exit_names)
    return mem


def _clash_prefixed_name(prefix, name):
    """Prefix a clash node name the way the override script's name
    normalization leaves it: a leading flag emoji stays first and the
    prefix becomes the second word ("🇺🇸 出口- 美国 ...")."""
    name = name or ""
    if (len(name) >= 2
            and all("\U0001F1E6" <= ch <= "\U0001F1FF"
                    for ch in name[:2])):
        return name[:2] + " " + prefix + name[2:]
    return prefix + name


def _sb_leaf_fix(o):
    """Per-node normalization the sing-box overlay script applies:
    domain_resolver is repointed at the script's CN DNS (any legacy
    domain_strategy is folded into it and dropped), TCP keep-alive
    defaults are set on non-endpoint outbounds, and a stray name
    field differing from the tag is removed. The overlay options
    this backend fixes (SB_OVERLAY) leave the resolver strategy
    empty, matching the script's behavior for those options."""
    st = str(o.get("domain_strategy") or "")
    cur = o.get("domain_resolver")
    if isinstance(cur, dict):
        cur["server"] = "dns-cn"
        if st and not cur.get("strategy"):
            cur["strategy"] = st
    elif cur or st:
        o["domain_resolver"] = ({"server": "dns-cn", "strategy": st}
                                if st else "dns-cn")
    o.pop("domain_strategy", None)
    if o.get("type") != "wireguard":
        o["tcp_keep_alive"] = "60s"
        if not o.get("tcp_keep_alive_interval"):
            o["tcp_keep_alive_interval"] = "60s"
    if o.get("name") and o.get("name") != o.get("tag"):
        del o["name"]
    return o


def _own_clash_chain(eprox, xprox):
    try:
        import yaml
        sk = _skeleton("skeleton_clash.json")
        entries, exits = [], []
        for p in eprox:
            p = dict(p)
            p["name"] = _clash_prefixed_name("入口-", p["name"])
            entries.append(p)
        for p in xprox:
            p = dict(p)
            p["name"] = _clash_prefixed_name("出口-", p["name"])
            p["dialer-proxy"] = ENTRY_AUTO
            exits.append(p)
        en = [p["name"] for p in entries]
        xn = [p["name"] for p in exits]
        specials = [x for x in sk.get("proxies") or []
                    if x != "@NODES@"]
        sk["proxies"] = entries + exits + specials
        for g in sk.get("proxy-groups") or []:
            g["proxies"] = _fill_members(g.get("proxies"), en, xn)
        return (yaml.safe_dump(sk, allow_unicode=True, sort_keys=False),
                "text/yaml; charset=utf-8")
    except Exception as e:
        print("own clash chain failed:", e, flush=True)
        return None


def _own_singbox_chain(enodes, xnodes):
    try:
        sk = _skeleton("skeleton_singbox.json")
        entries, exits = [], []
        for o in enodes:
            o = _sb_leaf_fix(dict(o))
            o.pop("detour", None)
            o["tag"] = "入口-" + o["tag"]
            entries.append(o)
        for o in xnodes:
            o = _sb_leaf_fix(dict(o))
            o["tag"] = "出口-" + o["tag"]
            o["detour"] = ENTRY_AUTO
            exits.append(o)
        en = [o["tag"] for o in entries]
        xn = [o["tag"] for o in exits]
        out = []
        for o in sk.get("outbounds") or []:
            if o.get("type") == "@nodes@":
                out.extend(entries)
                out.extend(exits)
                continue
            if "outbounds" in o:
                o["outbounds"] = _fill_members(o.get("outbounds"),
                                               en, xn)
            out.append(o)
        sk["outbounds"] = out
        return (json.dumps(sk, ensure_ascii=False, indent=2),
                "application/json; charset=utf-8")
    except Exception as e:
        print("own singbox chain failed:", e, flush=True)
        return None


def merge_singbox(entry_items, exit_items):
    STAGE["cur"] = "entry-convert"
    ecfg = json.loads(sub_convert("singbox", entry_items))
    STAGE["cur"] = "exit-convert"
    xcfg = json.loads(sub_convert("singbox", exit_items))
    STAGE["cur"] = "merge"
    enodes, xnodes = _nodes(ecfg), _nodes(xcfg)
    if not enodes or not xnodes:
        raise ValueError("入口或出口没有可用节点")
    built = _own_singbox_chain(enodes, xnodes)
    if built is not None:
        print("chain target=singbox path=own", flush=True)
        return _ech_fix_body(built[0]), built[1]
    scripted = _overlay_chain(enodes, xnodes)
    if scripted is not None:
        print("chain target=singbox path=scripted", flush=True)
        return _ech_fix_body(scripted[0]), scripted[1]
    emap = {o["tag"]: "入口-" + o["tag"] for o in enodes}
    xmap = {o["tag"]: "出口-" + o["tag"] for o in xnodes}
    out = [o for o in xcfg["outbounds"] if o.get("type") in BUILTIN_TYPES]
    for o in xnodes:
        o = dict(o)
        o["tag"] = xmap[o["tag"]]
        o["detour"] = ENTRY_AUTO
        out.append(o)
    for o in enodes:
        o = dict(o)
        o["tag"] = emap[o["tag"]]
        out.append(o)
    for o in xcfg["outbounds"]:
        if o.get("type") in GROUP_TYPES and o.get("tag") != OLD_AUTO:
            g = dict(o)
            members = [xmap.get(m, m) for m in g.get("outbounds", [])]
            g["outbounds"] = [m for m in members if m != OLD_AUTO]
            out.append(g)
    for g in out:
        if g.get("type") in GROUP_TYPES and g.get("tag") in ("🔰 节点选择", "GLOBAL"):
            rest = [m for m in g["outbounds"] if m != EXIT_AUTO]
            g["outbounds"] = [EXIT_AUTO] + rest
    # Chain failover tuning (2026-10-29): detection interval
    # tightened 3m -> 1m (a dead node used to stay selected for
    # minutes — field report: selected exit showed Timeout while
    # healthy exits sat unused). Tolerance stays 100: two-hop
    # latency jitter is large, and a tight tolerance makes
    # url-test flap between near-equal exits (client-side logs,
    # AngelaMihomo chain fix, same day).
    urltest = {"url": TEST_URL, "interval": "1m", "tolerance": 100}
    out.append({"type": "urltest", "tag": ENTRY_AUTO,
                "outbounds": [emap[o["tag"]] for o in enodes],
                **{**urltest, "interval": "1m"}})
    out.append({"type": "urltest", "tag": EXIT_AUTO,
                "outbounds": [xmap[o["tag"]] for o in xnodes], **urltest})
    xcfg["outbounds"] = out
    # Leak prevention: overseas DNS is dialed through the chain selector,
    # never straight out; CN DNS keeps its DIRECT detour from the skeleton.
    for srv in (xcfg.get("dns") or {}).get("servers") or []:
        if srv.get("tag") == "dns_proxy":
            srv["detour"] = "🔰 节点选择"
    # Leak prevention + direct-routing pack (inserted right after the
    # leading sniff/hijack action rules):
    #  - WebRTC: STUN/TURN ports and stun domains are rejected outright.
    #  - LAN IPs/domains, public-DNS IPs/domains and CN domains go DIRECT.
    #  - Ad/tracker rule-set is rejected at the route level too (DNS
    #    already answers those domains with NOERROR).
    route = xcfg.get("route") or {}
    rsets = route.setdefault("rule_set", [])
    if not any(rs.get("tag") == "geosite-cn" for rs in rsets):
        rsets.append({"type": "remote", "tag": "geosite-cn",
                      "format": "binary",
                      "url": "__PUBLIC_ORIGIN__/rules/singbox/geosite-cn.srs",
                      "http_client": "http-direct"})
    direct = "🎯 全球直连"
    extra = [
        {"domain_keyword": ["stun"], "outbound": "REJECT"},
        {"network": ["udp"], "port": [3478, 19302, 5349],
         "outbound": "REJECT"},
        {"ip_is_private": True, "outbound": direct},
        {"domain_suffix": ["lan", "local", "internal", "home.arpa"],
         "outbound": direct},
        {"port": [53], "outbound": "REJECT"},
        {"domain_suffix": PUBDNS_DOMAINS, "outbound": direct},
        {"ip_cidr": PUBDNS_IPS, "outbound": direct},
        {"rule_set": ["geosite-cn"], "outbound": direct},
    ]
    tags = {rs.get("tag") for rs in rsets}
    if "geosite-category-ads-all" in tags:
        extra.append({"rule_set": ["geosite-category-ads-all"],
                      "outbound": "REJECT"})
    rules = route.get("rules") or []
    idx = 0
    while idx < len(rules) and "action" in rules[idx]:
        idx += 1
    route["rules"] = rules[:idx] + extra + rules[idx:]
    # CN domains resolve through the CN resolver explicitly.
    drules = (xcfg.get("dns") or {}).get("rules")
    if drules is not None and not any(
            r.get("rule_set") == ["geosite-cn"] for r in drules):
        drules.insert(0, {"rule_set": ["geosite-cn"], "server": "dns_direct"})
    print("chain target=singbox path=fallback", flush=True)
    return json.dumps(_ensure_ech_route(xcfg), ensure_ascii=False,
                      indent=2), "application/json; charset=utf-8"


_HERE = os.path.dirname(os.path.abspath(__file__))
NODE_CANDIDATES = [
    os.path.join(_HERE, "tools", "node", "bin", "node"),
    "node",
]
if os.environ.get("NODE_BIN"):
    NODE_CANDIDATES.insert(0, os.environ["NODE_BIN"])


def _clashbase_chain(eprox, xprox):
    """Build the clash chain config with the bundled override rule system.

    The merged proxies (entry-prefixed / exit-prefixed) are fed to the
    script's main(); the script rebuilds groups, rules, providers, DNS,
    hosts and sniffer. It strips dialer-proxy while normalizing proxies,
    so chaining is re-applied afterwards: exit proxies (identified by
    server+port) get dialer-proxy back, and the entry url-test group is
    appended. Any failure returns None and the caller falls back to the
    built-in merge.
    """
    import subprocess
    import tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    script = os.path.join(here, "mihomoScript.js")
    runner = os.path.join(here, "apply_clashbase.js")
    if not (os.path.exists(script) and os.path.exists(runner)):
        return None
    base_proxies = []
    entry_keys, exit_keys = set(), set()
    for p in eprox:
        p = dict(p)
        p["name"] = "入口-" + p["name"]
        entry_keys.add((p.get("server"), p.get("port")))
        base_proxies.append(p)
    for p in xprox:
        p = dict(p)
        p["name"] = "出口-" + p["name"]
        exit_keys.add((p.get("server"), p.get("port")))
        base_proxies.append(p)
    node = next((c for c in NODE_CANDIDATES
                 if c == "node" or os.path.exists(c)), None)
    if node is None:
        return None
    tmp = tempfile.mkdtemp(prefix="clashbase-")
    try:
        fin = os.path.join(tmp, "base.json")
        fout = os.path.join(tmp, "out.json")
        with open(fin, "w", encoding="utf-8") as f:
            json.dump({"proxies": base_proxies}, f, ensure_ascii=False)
        r = subprocess.run([node, runner, script, fin, fout],
                           capture_output=True, timeout=60)
        if r.returncode != 0:
            print("clash base run failed:", r.stderr.decode()[:300],
                  flush=True)
            return None
        with open(fout, encoding="utf-8") as f:
            out = json.load(f)
    except Exception as e:
        print("clash base chain error:", e, flush=True)
        return None
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    entry_names, exit_names, exit_seen = [], [], 0
    for p in out.get("proxies") or []:
        key = (p.get("server"), p.get("port"))
        if key in exit_keys:
            p["dialer-proxy"] = ENTRY_AUTO
            exit_seen += 1
            exit_names.append(p["name"])
        elif key in entry_keys:
            entry_names.append(p["name"])
    if not entry_names or exit_seen == 0:
        print("clash base chain: entry/exit re-apply failed", flush=True)
        return None
    groups = out.setdefault("proxy-groups", [])
    groups.append({"name": ENTRY_AUTO, "type": "url-test",
                    "url": TEST_URL, "interval": 60, "tolerance": 100, "lazy": False, "timeout": 5000, "max-failed-times": 3,
                    "proxies": entry_names})
    # BACKEND-ADAPTED (2026-10-25): the base DNS baseline bootstraps
    # node-hostname resolution over DoT (tls://223.5.5.5, TCP 853).
    # Bettbox core logs from 2026-10-25 showed 275 cancelled 853 dials
    # in a single night (carrier interference with TCP 853), stalling
    # chain connection setup. Use the same AliDNS over DoH/443 instead.
    _dns = out.get("dns") or {}
    for _key in ("default-nameserver", "proxy-server-nameserver"):
        _lst = _dns.get(_key) or []
        _dns[_key] = [
            "https://223.5.5.5/dns-query#DIRECT"
            if isinstance(_x, str) and _x.startswith("tls://223.5.5.5")
            else _x
            for _x in _lst
        ]
    # BACKEND-ADAPTED (2026-10-25): the override script groups proxies by region,
    # so entry and exit nodes land in the same region group, and its
    # url-test / load-balance groups can silently pick a single-hop
    # entry. Restructure for the chain: entries live only in the
    # entry auto group (plus the manual group, left untouched), exits
    # get a dedicated select group, and both dedicated groups lead
    # the main selector. Region groups keep exits only; groups left
    # empty are removed and rule targets pointing at them are
    # retargeted to the main selector.
    _main_name = "默认代理"
    _groups = out.get("proxy-groups") or []
    _by_name = {g.get("name"): g for g in _groups}
    if _main_name not in _by_name or not exit_names:
        print("clash base chain: main selector missing", flush=True)
        return None
    _entry_set = set(entry_names)
    for _g in _groups:
        if _g.get("name") in (ENTRY_AUTO, "手动选择"):
            continue
        _mem = _g.get("proxies")
        if isinstance(_mem, list):
            _g["proxies"] = [m for m in _mem if m not in _entry_set]
    _deleted = set()
    while True:
        _empties = [g for g in _groups
                    if g.get("name") not in (_main_name, ENTRY_AUTO)
                    and not (g.get("proxies") or [])
                    and not g.get("use")]
        if not _empties:
            break
        for _g in _empties:
            _deleted.add(_g.get("name"))
            _groups.remove(_g)
        for _g in _groups:
            _mem = _g.get("proxies")
            if isinstance(_mem, list):
                _g["proxies"] = [m for m in _mem if m not in _deleted]
    if _deleted:
        def _retarget(_rule):
            if not isinstance(_rule, str):
                return _rule
            _p = _rule.split(",")
            if _p[0] == "MATCH":
                _i = 1
            elif _p[0] in ("AND", "OR", "NOT"):
                _i = len(_p) - 1
            elif len(_p) > 2:
                _i = 2
            else:
                return _rule
            if 0 <= _i < len(_p) and _p[_i].strip() in _deleted:
                _p[_i] = _main_name
                return ",".join(_p)
            return _rule
        out["rules"] = [_retarget(r) for r in out.get("rules") or []]
    _groups.insert(0, {"name": EXIT_AUTO, "type": "url-test",
                       "url": TEST_URL, "interval": 60,
                       "tolerance": 100,
                       "lazy": False,
                       "timeout": 5000,
                       "max-failed-times": 3, "proxies": list(exit_names)})
    _entry_group = _by_name.get(ENTRY_AUTO)
    if _entry_group is not None and _entry_group in _groups:
        _groups.remove(_entry_group)
        _groups.insert(1, _entry_group)
    _main = _by_name[_main_name]
    _mem = [m for m in (_main.get("proxies") or [])
            if m not in (EXIT_AUTO, ENTRY_AUTO)]
    _main["proxies"] = [EXIT_AUTO, ENTRY_AUTO] + _mem
    out["proxy-groups"] = _groups
    # BACKEND-ADAPTED (2026-10-25): region groups whose reachable leaf
    # nodes are all exits duplicate the exit select group (the user
    # flagged the standalone US group as redundant). Delete them;
    # references from other groups and rule targets are rewritten to
    # the exit select group, which is what a region means for a chain
    # (the exit decides the apparent region).
    _proxy_set = {p.get("name") for p in out.get("proxies") or []}
    _gmap = {g.get("name"): g for g in _groups}

    def _leaves(_name, _seen=None):
        if _seen is None:
            _seen = set()
        if _name in _seen:
            return set()
        _seen.add(_name)
        _g = _gmap.get(_name)
        if _g is None:
            return set()
        _found = set()
        for _m in _g.get("proxies") or []:
            if _m in _proxy_set:
                _found.add(_m)
            elif _m in _gmap:
                _found |= _leaves(_m, _seen)
        return _found

    _keep = {_main_name, ENTRY_AUTO, "手动选择", "自动选择",
             "负载均衡", "故障转移", EXIT_AUTO}
    _region = set()
    for _g in list(_groups):
        _nm = _g.get("name")
        if _nm in _keep:
            continue
        _lv = _leaves(_nm)
        if _lv and _lv <= set(exit_names):
            _region.add(_nm)
    if _region:
        _groups = [g for g in _groups if g.get("name") not in _region]
        for _g in _groups:
            _mem = _g.get("proxies")
            if isinstance(_mem, list):
                _new_mem = []
                for _m in _mem:
                    _t = EXIT_AUTO if _m in _region else _m
                    if _t not in _new_mem:
                        _new_mem.append(_t)
                _g["proxies"] = _new_mem

        def _retarget_exit(_rule):
            if not isinstance(_rule, str):
                return _rule
            _p = _rule.split(",")
            if _p[0] == "MATCH":
                _i = 1
            elif _p[0] in ("AND", "OR", "NOT"):
                _i = len(_p) - 1
            elif len(_p) > 2:
                _i = 2
            else:
                return _rule
            if 0 <= _i < len(_p) and _p[_i].strip() in _region:
                _p[_i] = EXIT_AUTO
                return ",".join(_p)
            return _rule
        out["rules"] = [_retarget_exit(r) for r in out.get("rules") or []]
        out["proxy-groups"] = _groups
    import yaml
    return (yaml.safe_dump(out, allow_unicode=True, sort_keys=False),
            "text/yaml; charset=utf-8")


def merge_clash(entry_items, exit_items):
    import yaml
    STAGE["cur"] = "entry-convert"
    ey = yaml.safe_load(sub_convert("clash", entry_items))
    STAGE["cur"] = "exit-convert"
    xy = yaml.safe_load(sub_convert("clash", exit_items))
    STAGE["cur"] = "merge"
    if not isinstance(ey, dict) or not isinstance(xy, dict):
        raise ValueError("转换失败")
    eprox, xprox = ey.get("proxies") or [], xy.get("proxies") or []
    if not eprox or not xprox:
        raise ValueError("入口或出口没有可用节点")
    built = _own_clash_chain(eprox, xprox)
    if built is not None:
        print("chain target=clash path=own", flush=True)
        return built
    scripted = _clashbase_chain(eprox, xprox)
    if scripted is not None:
        print("chain target=clash path=scripted", flush=True)
        return scripted
    emap = {p["name"]: "入口-" + p["name"] for p in eprox}
    xmap = {p["name"]: "出口-" + p["name"] for p in xprox}
    newprox = []
    for p in eprox:
        p = dict(p)
        p["name"] = emap[p["name"]]
        newprox.append(p)
    for p in xprox:
        p = dict(p)
        p["name"] = xmap[p["name"]]
        p["dialer-proxy"] = ENTRY_AUTO
        newprox.append(p)
    groups = []
    for g in xy.get("proxy-groups") or []:
        if g.get("name") == OLD_AUTO:
            continue
        g = dict(g)
        members = [xmap.get(m, m) for m in g.get("proxies") or []]
        g["proxies"] = [m for m in members if m != OLD_AUTO]
        groups.append(g)
    if groups:
        rest = [m for m in groups[0]["proxies"] if m != EXIT_AUTO]
        groups[0]["proxies"] = [EXIT_AUTO] + rest
    # Chain failover tuning (2026-10-29): 60s interval and lazy
    # off so dead nodes are found within a minute, but tolerance
    # stays 100ms and per-node timeout 5000ms — two-hop checks
    # jitter too much for tighter switching (client-side logs,
    # AngelaMihomo chain fix, same day). Forced recheck after
    # 3 failures.
    urltest = {"type": "url-test", "url": TEST_URL, "interval": 60,
               "tolerance": 100,
               "lazy": False,
               "timeout": 5000,
               "max-failed-times": 3}
    groups.append({"name": ENTRY_AUTO,
                   "proxies": [emap[p["name"]] for p in eprox],
                   **{**urltest, "interval": 60}})
    groups.append({"name": EXIT_AUTO,
                   "proxies": [xmap[p["name"]] for p in xprox], **urltest})
    # Leak prevention + direct-routing pack, prepended (first match wins):
    # WebRTC STUN rejected; LAN, public-DNS and CN endpoints go DIRECT
    # (CN rules also exist in the skeleton; these take priority).
    pack = []
    if CLASHBASE:
        pack += CLASHBASE["block_webrtc"] + CLASHBASE["block_quic"]
    else:
        pack += [
            "DOMAIN-KEYWORD,stun,REJECT",
            "DST-PORT,3478,REJECT",
            "DST-PORT,19302,REJECT",
        ]
    pack += [
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "DOMAIN-SUFFIX,lan,DIRECT",
        "DOMAIN-SUFFIX,local,DIRECT",
        "DOMAIN-SUFFIX,home.arpa,DIRECT",
    ]
    pack.append("DST-PORT,53,REJECT")
    pack += [f"DOMAIN-SUFFIX,{d},DIRECT" for d in PUBDNS_DOMAINS]
    pack += [f"IP-CIDR,{c},DIRECT,no-resolve" for c in PUBDNS_IPS]
    xy["rules"] = pack + list(xy.get("rules") or [])
    xy["proxies"] = newprox
    xy["proxy-groups"] = groups
    # The skeleton ships no DNS section; add a leak-proof one (fake-ip,
    # rules-following resolution, CN domains to CN resolvers).
    if CLASHBASE:
        xy["dns"] = CLASHBASE["dns"]
        xy["hosts"] = CLASHBASE["hosts"]
        xy["sniffer"] = CLASHBASE["sniffer"]
        providers = dict(xy.get("rule-providers") or {})
        providers.update(CLASHBASE["providers"])
        xy["rule-providers"] = providers
    else:
        xy["dns"] = CLASH_DNS
    return (yaml.safe_dump(xy, allow_unicode=True, sort_keys=False),
            "text/yaml; charset=utf-8")


# ---------------------------------------------------------------- short links
# Generated subscription URLs used to embed the original entry/exit
# subscription URLs (tokens included) in plaintext. A short link keeps
# only an opaque code in the URL; the mapping lives server-side in
# links.json next to this file (mode 0600).
LINKS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "links.json")
_LINKS_LOCK = threading.Lock()
_LINK_ALPHABET = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _load_links():
    try:
        with open(LINKS_PATH, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_links(links):
    tmp = LINKS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(links, f, ensure_ascii=False)
    os.replace(tmp, LINKS_PATH)
    try:
        os.chmod(LINKS_PATH, 0o600)
    except Exception:
        pass


def _same_payload(a, b):
    return (isinstance(a, dict) and isinstance(b, dict)
            and a.get("kind") == b.get("kind")
            and a.get("entry") == b.get("entry")
            and a.get("exit") == b.get("exit")
            and a.get("url") == b.get("url"))


_CODE_CHARS = ("abcdefghijklmnopqrstuvwxyz"
               "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _valid_code(code):
    # User-chosen codes accept the full ASCII letter/digit set (the
    # random generator's alphabet is narrower on purpose, dropping
    # look-alike characters, but users will type 0/1/i/l/o).
    return (3 <= len(code) <= 32
            and all(ch in _CODE_CHARS for ch in code))


def _store_link(record, want_code=None):
    """Store a link record and return its code. With want_code, the
    caller-chosen code is used: returns it when free or already bound
    to the same payload, and None when taken by a different payload.
    Without want_code, an existing code for the same payload is
    reused (the target format is NOT part of a link's identity; the
    /m/ vs /s/ path letter picks it at fetch time), else a random
    code is generated."""
    with _LINKS_LOCK:
        links = _load_links()
        if want_code:
            rec = links.get(want_code)
            if rec is not None:
                return want_code if _same_payload(rec, record) else None
            links[want_code] = record
            _save_links(links)
            return want_code
        for code, rec in links.items():
            if _same_payload(rec, record):
                return code
        while True:
            code = "".join(secrets.choice(_LINK_ALPHABET)
                           for _ in range(10))
            if code not in links:
                break
        links[code] = record
        _save_links(links)
        return code


def _get_link(code):
    with _LINKS_LOCK:
        return _load_links().get(code)


# --------------------------------------------------------------------- page
PAGE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>订阅转换</title>
<style>
body{font-family:system-ui,sans-serif;background:#111;color:#eee;margin:0;padding:24px}
.wrap{max-width:560px;margin:0 auto}
h1{font-size:20px}
.tabs{display:flex;gap:8px;margin-bottom:8px}
.tabs button{flex:1;padding:10px;border:1px solid #444;border-radius:8px;background:#1c1c1e;color:#bbb;font-size:15px}
.tabs button.on{background:#0a84ff;color:#fff;border-color:#0a84ff}
label{display:block;margin:16px 0 6px;color:#bbb;font-size:14px}
select,textarea,input{width:100%;padding:10px;border-radius:8px;border:1px solid #444;background:#1c1c1e;color:#eee;box-sizing:border-box}
textarea{resize:vertical;font-family:inherit}
button.go{margin-top:18px;width:100%;padding:12px;border:0;border-radius:8px;background:#0a84ff;color:#fff;font-size:16px}
.out{margin-top:18px;word-break:break-all;background:#1c1c1e;border:1px solid #333;border-radius:8px;padding:12px;display:none}
.row{display:flex;gap:10px;margin-top:10px}
.row button{flex:1;padding:10px;border:0;border-radius:8px;background:#333;color:#eee}
.hide{display:none}
</style>
</head>
<body>
<div class="wrap">
<h1>订阅转换</h1>
<div class="tabs">
<button id="tabN" class="on" onclick="mode('n')">普通转换</button>
<button id="tabC" onclick="mode('c')">链式代理</button>
</div>

<div id="secN">
<label>节点 / 订阅（每行一个，可任意混填）</label>
<textarea id="u" rows="6" placeholder="ss://...&#10;trojan://...&#10;https://订阅地址"></textarea>
<label>目标格式</label>
<select id="t">
<option value="clash">Clash / Mihomo</option>
<option value="singbox">sing-box</option>
<option value="v2ray">V2Ray</option>
<option value="surge">Surge</option>
<option value="loon">Loon</option>
<option value="quanx">Quantumult X</option>
</select>
<label>自定义后缀（可选，不填则随机）</label>
<input id="codeN" placeholder="如 home，只用字母、数字、-、_">
<button class="go" onclick="genN()">生成转换链接</button>
<div class="out" id="outN"><div id="linkN"></div>
<div class="row"><button onclick="openL('N')">打开链接</button><button onclick="copyL('N')">复制链接</button></div></div>
</div>

<div id="secC" class="hide">
<label>入口（每行一个，可混填节点与订阅）</label>
<textarea id="ein" rows="4" placeholder="链的第一站，如日本入口节点或入口订阅"></textarea>
<label>出口（每行一个，可混填节点与订阅）</label>
<textarea id="eout" rows="4" placeholder="链的第二站，如美国出口节点或出口订阅"></textarea>
<label>目标格式</label>
<select id="tc">
<option value="singbox">sing-box</option>
<option value="clash">Mihomo / Clash</option>
</select>
<label>自定义后缀（可选，不填则随机）</label>
<input id="codeC" placeholder="如 chain，只用字母、数字、-、_">
<button class="go" onclick="genC()">生成链式订阅链接</button>
<div class="out" id="outC"><div id="linkC"></div>
<div class="row"><button onclick="openL('C')">打开链接</button><button onclick="copyL('C')">复制链接</button></div></div>
<p style="color:#777;font-size:13px">生成的链接可直接当订阅地址填进客户端，每次更新都会重新按入口到出口串好。短链里的字母代表格式：/m/ 是 Mihomo、/s/ 是 sing-box，同一个码改字母就能切换格式，不用重新生成。</p>
</div>

<p style="color:#777;font-size:13px">后端运行在你自己的 VPS 上，订阅链接不经过任何第三方。</p>
</div>
<script>
var cur={N:"",C:""};
function mode(m){
  document.getElementById("secN").className = m=="n" ? "" : "hide";
  document.getElementById("secC").className = m=="c" ? "" : "hide";
  document.getElementById("tabN").className = m=="n" ? "on" : "";
  document.getElementById("tabC").className = m=="c" ? "on" : "";
}
function items(id){
  return document.getElementById(id).value.split(/\n+/).map(function(s){return s.trim()}).filter(function(s){return s.length>0});
}
function show(k){
  document.getElementById("link"+k).textContent=cur[k];
  document.getElementById("out"+k).style.display="block";
}
function shorten(body,cb){
  fetch("/shorten",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})
    .then(function(r){return r.text().then(function(t){cb(r.ok?t:null,r.ok?null:t)})})
    .catch(function(){cb(null,null)});
}
function genN(){
  var it=items("u"); if(!it.length){alert("先粘贴节点或订阅链接");return}
  var tg=document.getElementById("t").value;
  var cd=document.getElementById("codeN").value.trim();
  var body={target:tg,url:it.join("|")}; if(cd)body.code=cd;
  shorten(body,function(u,err){
    if(!u){
      if(cd){alert(err||"生成失败");return}
      var base=(tg=="clash"||tg=="singbox")?"/conv":"/sub";u=location.origin+base+"?target="+tg+"&url="+encodeURIComponent(it.join("|"));
    }
    cur.N=u;show("N");
  });
}
function genC(){
  var a=items("ein"), b=items("eout");
  if(!a.length||!b.length){alert("入口和出口都要填");return}
  var tg=document.getElementById("tc").value;
  var cd=document.getElementById("codeC").value.trim();
  var body={target:tg,entry:a.join("|"),exit:b.join("|")}; if(cd)body.code=cd;
  shorten(body,function(u,err){
    if(!u){
      if(cd){alert(err||"生成失败");return}
      u=location.origin+"/chain?target="+tg+"&entry="+encodeURIComponent(a.join("|"))+"&exit="+encodeURIComponent(b.join("|"));
    }
    cur.C=u;show("C");
  });
}
function openL(k){if(cur[k])location.href=cur[k]}
function copyL(k){if(cur[k])navigator.clipboard.writeText(cur[k])}
</script>
</body>
</html>
""".encode("utf-8")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/plain; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # Browser-based converter frontends call this backend cross-origin.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/shorten":
            try:
                n = int(self.headers.get("Content-Length") or 0)
                data = (json.loads(self.rfile.read(n).decode("utf-8"))
                        if n > 0 else {})
                if not isinstance(data, dict):
                    raise ValueError("bad body")
            except Exception:
                return self._send(400, "bad request")
            target = str(data.get("target") or "")
            entry = str(data.get("entry") or "")
            exit_ = str(data.get("exit") or "")
            items = str(data.get("url") or "")
            want = str(data.get("code") or "").strip()
            if want and not _valid_code(want):
                return self._send(
                    400, "自定义后缀只能用字母、数字、-、_，长度 3 到 32")
            if entry or exit_:
                if (target not in ("singbox", "clash")
                        or not entry or not exit_):
                    return self._send(400, "bad request")
                record = {"kind": "chain", "target": target,
                          "entry": entry, "exit": exit_}
            elif items and target:
                record = {"kind": "conv", "target": target, "url": items}
            else:
                return self._send(400, "bad request")
            code = _store_link(record, want or None)
            if code is None:
                return self._send(409, "这个后缀已被占用，换一个试试")
            host = self.headers.get("Host", "")
            p = {"clash": "m", "singbox": "s"}.get(target)
            if p:
                return self._send(200, f"https://{host}/{p}/{code}")
            return self._send(200, f"https://{host}/c/{code}")
        return self._send(404, "not found")

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path.startswith("/rules/"):
            rel = urllib.parse.unquote(u.path[len("/rules/"):])
            try:
                allowed = _manifest_dsts()
            except Exception:
                allowed = set()
            if rel not in allowed:
                return self._send(404, "not found")
            try:
                with open(os.path.join(_RULES_DIR, rel), "rb") as f:
                    data = f.read()
            except Exception:
                return self._send(404, "not found")
            return self._send(200, data, "application/octet-stream")
        _fmt = {"c": None, "m": "clash", "s": "singbox"}
        if (len(u.path) > 3 and u.path[0] == "/" and u.path[2] == "/"
                and u.path[1] in _fmt):
            code = u.path[3:].strip("/")
            rec = _get_link(code) if code else None
            if not rec:
                return self._send(404, "link not found")
            # The path letter picks the output format (m = Mihomo /
            # clash, s = sing-box); /c/ falls back to the format the
            # link was created with.
            want = _fmt[u.path[1]] or rec.get("target") or ""
            if rec.get("kind") == "chain":
                STAGE["cur"] = "start"
                try:
                    body, ctype = (
                        merge_singbox(rec["entry"], rec["exit"])
                        if want == "singbox"
                        else merge_clash(rec["entry"], rec["exit"]))
                except Exception as e:
                    import sys
                    print(f"chain error via short link "
                          f"stage={STAGE['cur']} err={e!r}",
                          file=sys.stderr, flush=True)
                    return self._send(
                        502, f"chain generate failed at {STAGE['cur']}: {e}")
                return self._send(200, body, ctype)
            target = want
            items = rec.get("url") or ""
            if target in ("singbox", "clash") and items:
                try:
                    body, ctype = build_config(target, items)
                except Exception as e:
                    return self._send(502, f"convert failed: {e}")
                return self._send(200, body, ctype)
            try:
                q = urllib.parse.urlencode({"target": target, "url": items})
                req = urllib.request.Request(
                    CONVERTER_BASE + "/sub?" + q,
                    headers={"User-Agent": BROWSER_UA})
                with urllib.request.urlopen(req, timeout=60) as r:
                    return self._send(r.status, r.read(),
                                      r.headers.get("Content-Type",
                                                    "text/plain"))
            except urllib.error.HTTPError as e:
                return self._send(e.code, e.read())
            except Exception as e:
                return self._send(502, f"backend proxy failed: {e}")
        if u.path == "/version":
            try:
                req = urllib.request.Request(CONVERTER_BASE + "/version")
                with urllib.request.urlopen(req, timeout=10) as r:
                    return self._send(200, r.read())
            except Exception:
                return self._send(200, "subconverter v0.9.0 backend")
        if u.path == "/sub":
            qs = urllib.parse.parse_qs(u.query)
            target = (qs.get("target") or [""])[0]
            items = (qs.get("url") or [""])[0]
            if target in ("singbox", "clash") and items:
                try:
                    body, ctype = build_config(target, items)
                except Exception as e:
                    return self._send(502, f"convert failed: {e}")
                return self._send(200, body, ctype)
            try:
                req = urllib.request.Request(
                    CONVERTER_BASE + self.path,
                    headers={"User-Agent": self.headers.get(
                        "User-Agent", BROWSER_UA)})
                with urllib.request.urlopen(req, timeout=60) as r:
                    return self._send(r.status, r.read(),
                                      r.headers.get("Content-Type",
                                                    "text/plain"))
            except urllib.error.HTTPError as e:
                return self._send(e.code, e.read())
            except Exception as e:
                return self._send(502, f"backend proxy failed: {e}")
        if u.path == "/conv":
            qs = urllib.parse.parse_qs(u.query)
            target = (qs.get("target") or [""])[0]
            items = (qs.get("url") or [""])[0]
            if target not in ("singbox", "clash") or not items:
                return self._send(400, "bad request")
            try:
                body, ctype = build_config(target, items)
            except Exception as e:
                import sys
                print(f"conv error target={target} err={e!r}",
                      file=sys.stderr, flush=True)
                return self._send(502, f"convert failed: {e}")
            return self._send(200, body, ctype)
        if u.path == "/chain":
            qs = urllib.parse.parse_qs(u.query)
            target = (qs.get("target") or [""])[0]
            entry = (qs.get("entry") or [""])[0]
            exit_ = (qs.get("exit") or [""])[0]
            if target not in ("singbox", "clash") or not entry or not exit_:
                return self._send(400, "bad request: need target=singbox|clash, entry, exit")
            STAGE["cur"] = "start"
            try:
                body, ctype = (merge_singbox(entry, exit_) if target == "singbox"
                               else merge_clash(entry, exit_))
            except Exception as e:
                import sys
                print(f"chain error target={target} stage={STAGE['cur']} err={e!r}",
                      file=sys.stderr, flush=True)
                return self._send(502, f"chain generate failed at {STAGE['cur']}: {e}")
            return self._send(200, body, ctype)
        return self._send(404, "not found")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PAGE_PORT), H).serve_forever()
