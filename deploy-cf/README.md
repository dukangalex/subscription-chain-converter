# Cloudflare Workers Variant — Subscription Converter with Chain Proxy

The same subscription converter as the VPS version (see the spec in
the repository root README), ported to a single Cloudflare Worker.
Short links and the rule mirror live in one KV namespace instead of
files on a server; a Cron Trigger replaces the systemd timer. The
port targets the Python service's **primary (own-skeleton) builders**,
and its generated chain configs were verified deep-equal (parsed
JSON/YAML) against the Python builders' outputs for the same inputs.

## Architecture mapping

| VPS version | This variant |
|---|---|
| subpage Python service (`landing_server.py`) | `src/worker.js` (Worker fetch handler) |
| `links.json` (mode 0600) | KV keys `link:<code>` + `idx:<sha256>` content index |
| `rules_files/` mirror directory | KV keys `rule:<dst>` |
| `rules_status.json` | KV key `meta:rules_status` |
| `refresh_rules.py` + systemd timer (daily 04:35) | Cron Trigger `35 20 * * *` UTC (= 04:35 CST) + `POST /admin/refresh` |
| skeleton files with the origin baked in at install | same skeletons bundled verbatim; `__PUBLIC_ORIGIN__` is replaced per request with the request's own origin |
| bundled subconverter (for `/sub` passthrough) | optional external one via `EXTERNAL_SUBCONVERTER_URL` |
| tunnel / reverse proxy for exposure | the Worker itself (workers.dev or a custom domain) |

Endpoints are identical to the VPS version: `GET /`, `/chain`,
`/conv`, `/sub`, `/version`, `POST /shorten`, `GET /c|m|s/<code>`,
`GET /rules/<path>` — plus `POST /admin/refresh`, which requires
`Authorization: Bearer <REFRESH_TOKEN>` (a Worker secret).

## Free-tier feasibility

KV free tier: 1 GB storage, 100k reads/day, 1k writes/day. One full
rule refresh writes ~104 keys (103 files + status), so the daily
cron uses about a tenth of the daily write budget. The largest
single value, `clash/geoip.dat` at about 16.5 MB, fits under the
25 MB KV value limit, and the whole mirror is well under 1 GB.

One caveat: the Workers **free plan allows 50 subrequests per
invocation**, while a full refresh fetches 103 files. On the free
plan a single refresh run therefore fills the mirror incrementally —
entries that fail keep their previous copy and later runs (cron or
manual) top them up. For a guaranteed one-shot refresh, the Workers
Paid plan raises the subrequest limit. Everything else (generation,
short links, rule serving) fits comfortably in the free tier.

## One-click deploy

Prerequisites: a Cloudflare account, Node.js 18+, and a wrangler
login (`npx wrangler login`).

```bash
bash deploy.sh                # or: bash deploy.sh sub.example.com
```

The script installs dependencies, creates the KV namespace and
writes its id into `wrangler.toml`, generates a `REFRESH_TOKEN`
(`openssl rand -hex 24`) and stores it as a Worker secret, deploys,
fills the rule mirror via `POST /admin/refresh`, and smoke-tests
the deployment (shorten → sing-box chain config containing
`detour`, plus one mirrored rule file). It prints the token at the
end — save it; rerunning generates a new one.

## Manual deploy

```bash
npm install
npx wrangler kv namespace create KV            # note the id
npx wrangler kv namespace create KV --preview  # note the preview id
# put both ids into wrangler.toml (replacing the placeholders)
npx wrangler secret put REFRESH_TOKEN          # paste a random token
npx wrangler deploy
curl -X POST https://<your-worker-domain>/admin/refresh \
  -H "Authorization: Bearer <REFRESH_TOKEN>"
```

## Differences and limits vs the VPS version

- **Own-builder only.** The Python service's fallbacks — the Node
  script path (the bundled mihomo / sing-box overlay scripts) and the
  templates-based merge — do not exist here. If the own builder
  cannot build, the request fails with 502 instead of degrading.
- **`/sub` for other formats needs an external subconverter.**
  clash/singbox targets are built locally everywhere (including
  `/sub`), but v2ray/surge/loon/quanx targets are proxied to
  `EXTERNAL_SUBCONVERTER_URL` when set, and return 501 otherwise.
- **Plain `/conv` conversions** are assembled from the same own
  skeleton with the entry tier removed (entry group dropped, nodes
  form the exit/manual tiers, leaf normalization applied so
  `domain_resolver` matches the skeleton DNS). The VPS builds these
  from its captured subconverter templates instead, so the exact
  shape differs while groups/rules/DNS come from the same frozen
  definitions.
- **`/version`** returns `subscription-converter cf-worker` instead
  of proxying a local subconverter.
- **YAML formatting** comes from js-yaml rather than PyYAML; line
  folding/quoting can differ cosmetically. Parsed content was
  verified identical for chain outputs.
- **KV is eventually consistent**: a freshly created short link is
  normally readable immediately, but propagation can lag briefly in
  some regions.
- **ECH handling is unchanged**: ECHConfigList is fetched from
  AliDNS DoH at generation time and inlined (PEM label
  `ECH CONFIGS`), with the `ech-dns` route as fallback — verified
  byte-for-byte equal to the Python output for an ECH-carrying
  entry.

## Data flow

Short-link records — including the original subscription URLs with
their tokens — are stored only in **your own** Cloudflare KV
namespace. Generation runs on Cloudflare's edge; subscription
sources, official rule files and ECH lookups are fetched from
Cloudflare egress IPs. Clients pull configs and rule files from
your Worker domain. Nothing is sent to any third-party converter,
and request URLs are not written to any log by the Worker.

## Files

```
package.json          name, js-yaml + wrangler pins, scripts
wrangler.toml         worker config (KV binding, cron, vars)
deploy.sh             one-click deploy + smoke test
src/worker.js         the Worker (page, ingestion, builders, KV, HTTP)
src/skeleton_clash.json    bundled verbatim from the VPS backend
src/skeleton_singbox.json  bundled verbatim
src/rules_manifest.json    bundled verbatim (103 official sources)
test/smoke.mjs        stubbed-KV/fetch test harness: node test/smoke.mjs
```
