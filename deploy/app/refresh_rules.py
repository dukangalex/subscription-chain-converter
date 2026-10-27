#!/usr/bin/env python3
"""Refresh the self-hosted rule mirror from the official sources.

The generated clash / sing-box configs reference rule files under our
own domain (see the skeletons); this script keeps the local mirror in
sync with the official upstreams:

  - mihomo rules and geodata: MetaCubeX/meta-rules-dat (official)
  - sing-box rule-sets: SagerNet/sing-geosite + SagerNet/sing-geoip

Every file is downloaded to a temp path, validated, and atomically
replaced; a failed download keeps the previous copy. A status file
(rules_status.json, next to this script) records the outcome. Run by
the rules-refresh systemd timer (daily); safe to run by hand.
"""
import datetime
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "rules_manifest.json")
OUT_DIR = os.path.join(HERE, "rules_files")
STATUS = os.path.join(HERE, "rules_status.json")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def _valid(dst, data):
    if len(data) < 64:
        return False
    if dst.endswith(".svg"):
        head = data[:2048]
        return b"<svg" in head or head.lstrip().startswith(b"<?xml")
    # Binary rule files must not be an HTML error page in disguise.
    return not data.lstrip().startswith(b"<")


def main():
    with open(MANIFEST, encoding="utf-8") as f:
        manifest = json.load(f)
    ok, failed = 0, []
    for entry in manifest:
        dst, src = entry["dst"], entry["src"]
        path = os.path.join(OUT_DIR, dst)
        try:
            req = urllib.request.Request(src, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            if not _valid(dst, data):
                raise ValueError("validation failed")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
            ok += 1
        except Exception as e:
            failed.append(dst)
            print(f"FAIL {dst}: {e}", flush=True)
    status = {
        "updated_at": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "ok": ok,
        "failed": failed,
    }
    with open(STATUS, "w", encoding="utf-8") as f:
        json.dump(status, f, ensure_ascii=False, indent=1)
    print(f"rules refresh: {ok} ok, {len(failed)} failed", flush=True)
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
