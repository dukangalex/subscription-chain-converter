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
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "rules_manifest.json")
OUT_DIR = os.path.join(HERE, "rules_files")
STATUS = os.path.join(HERE, "rules_status.json")
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")


def _declared_behaviors():
    """dst -> set of behaviors the skeleton's rule-providers declare
    for the file behind their URLs (clash .mrs files only)."""
    try:
        with open(os.path.join(HERE, "skeleton_clash.json"),
                  encoding="utf-8") as f:
            sk = json.load(f)
    except Exception:
        return {}
    out = {}
    for p in (sk.get("rule-providers") or {}).values():
        if not isinstance(p, dict):
            continue
        beh = p.get("behavior")
        if beh not in ("domain", "ipcidr"):
            continue
        m = re.search(r"/rules/(clash/[^/?#]+)$", str(p.get("url") or ""))
        if m:
            out.setdefault(m.group(1), set()).add(beh)
    return out


def _mrs_behavior(data):
    """Embedded behavior of a .mrs payload: a zstd stream whose
    decompressed head is 'MRS', a version byte, then a behavior byte
    (0 = domain, 1 = ipcidr). None when undecodable."""
    try:
        import io

        import zstandard
    except ImportError:
        return None
    try:
        reader = zstandard.ZstdDecompressor().stream_reader(
            io.BytesIO(data))
        head = reader.read(16)
    except Exception:
        return None
    if len(head) >= 5 and head[:3] == b"MRS":
        return {0: "domain", 1: "ipcidr"}.get(head[4])
    return None


DECLARED = None  # lazily filled by main()


def _valid(dst, data, src=""):
    if len(data) < 64:
        return False
    if dst.endswith(".svg"):
        head = data[:2048]
        return b"<svg" in head or head.lstrip().startswith(b"<?xml")
    # Binary rule files must not be an HTML error page in disguise.
    if data.lstrip().startswith(b"<"):
        return False
    # A clash .mrs whose class (or embedded behavior marker) disagrees
    # with the skeleton's declared behavior makes the core reject the
    # provider with "invalid behavior" (T206): never publish it.
    if dst.startswith("clash/") and dst.endswith(".mrs") and DECLARED:
        declared = DECLARED.get(dst)
        if declared:
            cls = ("domain" if "/geosite/" in src
                   else "ipcidr" if "/geoip/" in src else None)
            if cls is None or cls not in declared:
                return False
            embedded = _mrs_behavior(data)
            if embedded is not None and embedded not in declared:
                return False
    return True


def main():
    global DECLARED
    DECLARED = _declared_behaviors()
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
            if not _valid(dst, data, src):
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
