# URL-sourced sets: lazy loading and midnight refresh

`geosite:`/`geoip:` sets do not have to be placed on disk by hand — the resolver
downloads them when they are first needed and refreshes them once a day.

> Русская версия: [geo-fetch.md](geo-fetch.md)

---

## Sources: geo.sources

Sets are downloaded from **named sources** declared in the `geo:` section. The
flat `geosite_url`/`geoip_url` keys are gone.

```yaml
geo:
  cache_dir: /var/cache/smartdns
  proxy: socks5://127.0.0.1:10808      # optional; see "Download proxy"
  sources:
    - name: hagezi                     # referenced as geosite@hagezi:pro
      geosite:
        - https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/{name}.txt
        - https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/wildcard/{name}.txt
    - name: rf                         # referenced as geosite@rf:… and set: rf@…
      geosite:
        - https://raw.githubusercontent.com/runetfreedom/russia-blocked-geosite/release/{name}.txt
      geoip:
        - https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/{name}.txt
```

**Set references.**

| Reference | Set comes from |
|---|---|
| `geosite:pro` (route), `set: pro` | the **first** source declaring that kind |
| `geosite@hagezi:pro`, `set: rf@ru-blocked` | exactly the named source |

Source order in `sources:` is the default-search order; name collisions are
resolved by the namespace. Local directories `geosite_dir`/`geoip_dir` act as
the `dir` pseudo-source for non-namespaced references when no URL source
declares that kind.

**The mode is chosen by whether the URL contains `{name}`.**

1. **Single `.dat`** (URL without `{name}`) — the file is downloaded whole
   (e.g. `geosite.dat` ≈ 70 MB), cached as
   `<cache_dir>/<kind>/<source>.dat`; only the categories referenced by rules
   are kept in memory. Set names are case-insensitive.
2. **Per-name** (`{name}` in the URL) — text lists, one file per set. Cache:
   `<cache_dir>/<kind>/<source>/<name>.txt`.

The file format is detected from the content, not the extension.

**Several URLs per kind = mirrors:** the first one is used; on a network error
or HTTP failure the next one is tried. Mixing `{name}` templates with plain
files in one list is not allowed (split into separate sources).

**YAML gotcha:** URLs containing `{name}` inside a flow list (`[ … ]`) must be
quoted, or written as a block list — curly braces break the parser.

`-check` prints sources, modes and mirror counts; a reference to an unknown
source is a config error, not a silent no-op rule.

---

## Download proxy

Downloads go out directly and do not read system proxy settings. If the source
is unreachable directly (GitHub is flaky from some networks), route downloads
through a proxy with a single key:

```yaml
proxy: socks5://127.0.0.1:10808      # SOCKS5
proxy: socks5h://user:pass@host:1080 # SOCKS5 with credentials
proxy: http://127.0.0.1:10801        # HTTP CONNECT; https:// works too
proxy: env                           # = yes: HTTP_PROXY/HTTPS_PROXY from the environment
```

Schemes: `http://`, `https://`, `socks5://`, `socks5h://` — equivalent here,
the target hostname is always passed to the proxy instead of being resolved
locally. Credentials go straight into the URL. A typo in the scheme
(`sock5://`) is a config error, not a silent fallback: `-check` reports it.

The proxy applies to **geo downloads only**. DoT/DoH/UDP upstreams keep going
out directly. If the proxy is down, the download fails with the usual retry,
and cached sets keep working.

---

## Behaviour

1. **Lazy.** A set is fetched the first time a rule references it (at startup
   only sets mentioned in `routes` / `answer_geoip` are scheduled).
2. **Never blocks DNS.** The transfer runs in a goroutine. Until the set is
   there, the rule simply does not match and the query follows the catch-all
   `"*"`. Subsequent queries see the set.
3. **Disk cache.** Written atomically (tmp + rename). If the file is already
   cached it is applied immediately (works offline) and the fresh version is
   fetched right after. Stale `*.tmp` files older than an hour are removed on
   first use.
4. **A set appearing flushes the DNS cache.** Otherwise a domain answered via
   the catch-all `"*"` while the set was downloading would stay cached for its
   whole TTL.
5. **Timeouts match the file size:** 15 s to connect, up to 10 minutes for the
   body. 404/403/410 responses are remembered until restart; after a network
   failure retries pause for a minute so queries do not hammer the source.
6. **`include:` is expanded** (per-name mode). v2fly lists are trees of
   `include:`; attributes (`name @ads`) are stripped — we cannot filter by
   attribute, so the entry is taken whole. The parent set is rebuilt when an
   included set arrives.
7. **Refresh at 00:00** local time: a single `.dat` is re-downloaded whole and
   the referenced categories are re-parsed; in per-name mode only already-loaded
   sets are re-downloaded.

---

## Not implemented

- no bulk loading of every category — only those referenced by rules;
- attributes (`@ads`, `@cn`) are not filtered;
- `regexp:` entries from the databases are skipped and counted (visible in `-check`);
- IPv6 ranges from `geoip.dat` are skipped (counted in `-check`): `geoip:` rules
  are IPv4-only today;
- refresh overwrites files, no version history.

---

## Diagnostics

```
гео-наборы: лениво по URL, кэш /tmp/smartdns
  домены: https://…/geosite.dat (единый .dat)
  адреса: https://…/geoip.dat (единый .dat)
  обновление: ежедневно в 00:00
```

Log:

```
гео: geosite.dat — применено категорий: 1 из 1 запрошенных
гео: geoip — загрузка не удалась: HTTP 404 …
гео: полночь — обновляю загруженные наборы
гео: geosite.dat — обновлён
```

A rule "not firing" right after start is expected: the set is still downloading
(70 MB over a slow link takes minutes). Confirm it landed: `ls -lh <geo_cache_dir>/`.
