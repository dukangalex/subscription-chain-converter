#!/usr/bin/env bash
# One-click installer for the self-hosted subscription converter
# (page service + chain builder + subconverter + self-hosted rule mirror).
#
# Usage:
#   cp config.env.example config.env   # edit DOMAIN at least
#   sudo bash install.sh
#
# Re-running is safe: the previous install is moved to a timestamped
# backup, while links.json (short-link map) and rules_files/ (mirror)
# are carried over. Set NO_SYSTEMD=1 to lay files down and run a
# self-test without touching systemd (containers / CI / evaluation).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$HERE/config.env" ]; then
  # shellcheck disable=SC1091
  set -a; . "$HERE/config.env"; set +a
fi

DOMAIN="${DOMAIN:-sub.example.com}"
ORIGIN="https://${DOMAIN}"
INSTALL_DIR="${INSTALL_DIR:-/opt/subconv}"
PAGE_PORT="${PAGE_PORT:-18081}"
CONV_PORT="${CONV_PORT:-18080}"
SUBCONVERTER_VERSION="${SUBCONVERTER_VERSION:-v0.9.0}"
NODE_VERSION="${NODE_VERSION:-v22.14.0}"
NO_SYSTEMD="${NO_SYSTEMD:-0}"

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

retry_dl() { # url dest
  local i
  for i in 1 2 3; do
    curl -fsSL --connect-timeout 15 -o "$2" "$1" && return 0
    log "download failed (attempt $i): $1"
    sleep 2
  done
  return 1
}

wait_http() { # url needle tries
  local i
  for i in $(seq 1 "${3:-30}"); do
    if curl -fsS -m 5 "$1" 2>/dev/null | grep -q "$2"; then return 0; fi
    sleep 1
  done
  return 1
}

# ------------------------------------------------------------ preflight
[ "$NO_SYSTEMD" = "1" ] || [ "$(id -u)" = "0" ] \
  || die "run as root (or set NO_SYSTEMD=1)"
command -v python3 >/dev/null || die "python3 not found"
command -v curl >/dev/null || die "curl not found"
command -v tar >/dev/null || die "tar not found"
if ! python3 -c "import yaml" 2>/dev/null; then
  log "installing PyYAML (required by the page service)"
  python3 -m pip install --quiet pyyaml 2>/dev/null \
    || (command -v apt-get >/dev/null && apt-get install -y python3-yaml >/dev/null) \
    || die "could not install PyYAML"
  python3 -c "import yaml" 2>/dev/null || die "PyYAML still unavailable"
fi
case "$(uname -m)" in
  x86_64)  NODE_ARCH="x64";     SUB_ARCH="linux64" ;;
  aarch64) NODE_ARCH="arm64";   SUB_ARCH="linuxarm" ;;
  *) die "unsupported arch: $(uname -m)" ;;
esac
log "domain=$DOMAIN install_dir=$INSTALL_DIR page_port=$PAGE_PORT conv_port=$CONV_PORT"

# ------------------------------------------------------------ lay files
if [ -d "$INSTALL_DIR" ]; then
  BAK="${INSTALL_DIR}.bak-$(date +%Y%m%d%H%M%S)"
  log "existing install -> backup $BAK"
  mv "$INSTALL_DIR" "$BAK"
  mkdir -p "$INSTALL_DIR"
  for keep in links.json rules_status.json; do
    [ -f "$BAK/$keep" ] && cp -a "$BAK/$keep" "$INSTALL_DIR/$keep"
  done
  [ -d "$BAK/rules_files" ] && cp -a "$BAK/rules_files" "$INSTALL_DIR/rules_files"
fi
mkdir -p "$INSTALL_DIR"
cp -a "$HERE/app/." "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/rules_files"
log "application files laid down"

# Point every self-hosted rule URL at the operator's own origin.
grep -rl "__PUBLIC_ORIGIN__" "$INSTALL_DIR" --include='*.py' --include='*.json' \
  | while read -r f; do
      sed -i "s|__PUBLIC_ORIGIN__|${ORIGIN}|g" "$f"
    done
log "rule origin set to $ORIGIN"

# ------------------------------------------------------- subconverter
SUBDIR="$INSTALL_DIR/subconverter"
mkdir -p "$SUBDIR"
SUB_URL="https://github.com/tindy2013/subconverter/releases/download/${SUBCONVERTER_VERSION}/subconverter_${SUB_ARCH}.tar.gz"
if retry_dl "$SUB_URL" /tmp/subconverter.tar.gz; then
  tar -xzf /tmp/subconverter.tar.gz -C /tmp
  cp -a /tmp/subconverter/. "$SUBDIR/"
  rm -rf /tmp/subconverter /tmp/subconverter.tar.gz
  if [ -f "$SUBDIR/pref.ini" ]; then
    sed -i -E "s/^listen[[:space:]]*=.*/listen=127.0.0.1/" "$SUBDIR/pref.ini"
    grep -q "^listen" "$SUBDIR/pref.ini" || printf 'listen=127.0.0.1\n' >> "$SUBDIR/pref.ini"
    sed -i -E "s/^port[[:space:]]*=.*/port=${CONV_PORT}/" "$SUBDIR/pref.ini"
    grep -q "^port" "$SUBDIR/pref.ini" || printf 'port=%s\n' "$CONV_PORT" >> "$SUBDIR/pref.ini"
  fi
  log "subconverter $SUBCONVERTER_VERSION installed (127.0.0.1:$CONV_PORT)"
else
  log "WARNING: subconverter download failed; /sub passthrough for other"
  log "         formats will be unavailable until it is installed manually."
fi

# ------------------------------------------------------------ node.js
# Only the legacy script fallback path needs node; the primary builder
# is pure Python. Best effort.
if command -v node >/dev/null; then
  log "node found: $(node --version)"
elif retry_dl "https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.gz" /tmp/node.tar.gz; then
  mkdir -p "$INSTALL_DIR/tools"
  tar -xzf /tmp/node.tar.gz -C /tmp
  rm -rf "$INSTALL_DIR/tools/node"
  mv "/tmp/node-${NODE_VERSION}-linux-${NODE_ARCH}" "$INSTALL_DIR/tools/node"
  rm -f /tmp/node.tar.gz
  log "node $NODE_VERSION installed under $INSTALL_DIR/tools/node"
else
  log "WARNING: node unavailable; script fallback path disabled (primary path unaffected)"
fi

# ------------------------------------------------------------- systemd
if [ "$NO_SYSTEMD" != "1" ]; then
  cat > /etc/systemd/system/subconverter.service <<EOF
[Unit]
Description=Subconverter backend (loopback only)
After=network-online.target

[Service]
Type=simple
ExecStart=$SUBDIR/subconverter
WorkingDirectory=$SUBDIR
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/subpage.service <<EOF
[Unit]
Description=Subscription converter page service
After=network-online.target subconverter.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/landing_server.py
WorkingDirectory=$INSTALL_DIR
Environment=SUBPAGE_PORT=$PAGE_PORT
Environment=SUBCONVERTER_URL=http://127.0.0.1:$CONV_PORT
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  cat > /etc/systemd/system/rules-refresh.service <<EOF
[Unit]
Description=Refresh self-hosted rule mirror from official sources
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $INSTALL_DIR/refresh_rules.py
WorkingDirectory=$INSTALL_DIR
EOF
  cat > /etc/systemd/system/rules-refresh.timer <<EOF
[Unit]
Description=Daily rule mirror refresh

[Timer]
OnCalendar=*-*-* 04:35:00
RandomizedDelaySec=900
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  [ -x "$SUBDIR/subconverter" ] && systemctl enable --now subconverter.service >/dev/null
  log "filling the rule mirror (first run downloads ~100 files)"
  systemctl start rules-refresh.service || log "WARNING: first rules refresh failed; check rules_status.json later"
  systemctl enable --now subpage.service >/dev/null
  systemctl enable --now rules-refresh.timer >/dev/null
  log "systemd services enabled"
else
  log "NO_SYSTEMD=1: refreshing the rule mirror directly"
  (cd "$INSTALL_DIR" && python3 refresh_rules.py) \
    || log "WARNING: rules refresh failed; rerun refresh_rules.py later"
fi

# ----------------------------------------------------------- self-test
TMP_PIDS=""
cleanup() {
  # shellcheck disable=SC2086
  [ -n "$TMP_PIDS" ] && kill $TMP_PIDS 2>/dev/null || true
}
if [ "$NO_SYSTEMD" = "1" ]; then
  for p in "$PAGE_PORT" "$CONV_PORT"; do
    if curl -fsS -m 2 "http://127.0.0.1:$p/" >/dev/null 2>&1; then
      die "port $p is already serving HTTP; refusing to self-test against a foreign process"
    fi
  done
  if [ -x "$SUBDIR/subconverter" ]; then
    (cd "$SUBDIR" && exec ./subconverter >/tmp/subconv-test-sub.log 2>&1) &
    TMP_PIDS="$TMP_PIDS $!"
  fi
  (cd "$INSTALL_DIR" && exec env SUBPAGE_PORT="$PAGE_PORT" \
     SUBCONVERTER_URL="http://127.0.0.1:$CONV_PORT" \
     python3 landing_server.py >/tmp/subconv-test-page.log 2>&1) &
  TMP_PIDS="$TMP_PIDS $!"
  trap cleanup EXIT
  sleep 2
fi

BASE="http://127.0.0.1:$PAGE_PORT"
wait_http "$BASE/version" "." 30 || die "self-test failed: /version not responding"
wait_http "$BASE/" "chain" 10 || die "self-test failed: home page not responding"
RULE_CODE="$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$BASE/rules/clash/private.mrs")"
[ "$RULE_CODE" = "200" ] || die "self-test failed: rule mirror not serving"

DUMMY_ENTRY="vless://00000000-0000-0000-0000-000000000000@entry.example.com:443?security=none#entry-node"
DUMMY_EXIT="vless://11111111-1111-1111-1111-111111111111@exit.example.com:443?security=none#exit-node"
SHORT_URL="$(curl -fsS -m 15 -X POST "$BASE/shorten" -H 'Content-Type: application/json' \
  -d "{\"target\":\"singbox\",\"entry\":\"$DUMMY_ENTRY\",\"exit\":\"$DUMMY_EXIT\"}")" \
  || die "self-test failed: /shorten did not return a short link"
CODE="${SHORT_URL##*/}"
[ -n "$CODE" ] && [ "$CODE" != "$SHORT_URL" ] \
  || die "self-test failed: could not parse short code from: $SHORT_URL"
curl -fsS -m 30 "$BASE/s/$CODE" | grep -q "detour" \
  || die "self-test failed: generated sing-box config has no chain detour"
log "self-test passed: /version, /, /rules mirror, chain generation via short link /s/$CODE"
cleanup
trap - EXIT

# -------------------------------------------------------------- summary
cat <<EOF

Done. The converter is installed in $INSTALL_DIR.

Public exposure is one step and stays under your control: route your
domain's paths to 127.0.0.1:$PAGE_PORT. For a Cloudflare Tunnel
(config.yml ingress), add BEFORE the catch-all rule:

  - hostname: $DOMAIN
    path: ^/$
    service: http://127.0.0.1:$PAGE_PORT
  - hostname: $DOMAIN
    path: ^/(chain|conv|sub|version|shorten)$
    service: http://127.0.0.1:$PAGE_PORT
  - hostname: $DOMAIN
    path: ^/(c|m|s)/
    service: http://127.0.0.1:$PAGE_PORT
  - hostname: $DOMAIN
    path: ^/rules/
    service: http://127.0.0.1:$PAGE_PORT

Then open https://$DOMAIN/ and generate your first short link.
Logs: journalctl -u subpage.service -f   (generation paths only, no URLs)
Rule mirror status: $INSTALL_DIR/rules_status.json
EOF
