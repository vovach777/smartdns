# URL-sourced sets: lazy loading and midnight refresh

`geosite:`/`geoip:` sets do not have to be placed on disk by hand — the resolver
downloads them when they are first needed and refreshes them once a day.

> Русская версия: [geo-fetch.md](geo-fetch.md)

---

## Sources: two modes

The mode is chosen by whether the URL contains `{name}`.

**1. Single `.dat` (default)** — v2ray format, Russian databases from
[runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat);
the `release` branch always carries the latest version.

```yaml
geosite_url: https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geosite.dat
geoip_url:   https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/geoip.dat
```

The file is downloaded whole (geosite.dat ≈ 70 MB, geoip.dat ≈ 18 MB) and cached
as `<geo_cache_dir>/geosite.dat` / `geoip.dat`; `geo_cache_dir` defaults to
`/tmp/smartdns`, so after a reboot the databases are simply downloaded again. Only the categories referenced by
rules are kept in memory: the file is parsed in a single pass and the other
1000+ categories are dropped.

Category names inside the database are uppercase (`CATEGORY-ADS-ALL`, `RU`);
rule names are case-insensitive: both `geosite:category-ads-all` and `geosite:RU`
work.

**2. Per-name (`{name}` in the URL)** — v2fly/ipdeny text lists, one file per
set:

```yaml
geosite_url: https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/{name}
geoip_url:   https://www.ipdeny.com/ipblocks/data/aggregated/{name}-aggregated.zone
```

`{name}` is the set name from the rule (`geosite:category-ads-all` →
`category-ads-all`). Cache: `<geo_cache_dir>/geosite/<name>.txt` and
`<geo_cache_dir>/geoip/<name>.txt`.

---

## Behaviour

1. **Lazy.** A set is fetched the first time a rule references it (at startup
   only sets mentioned in `routes` / `answer_geoip` are scheduled).
2. **Never blocks DNS.** The transfer runs in a goroutine. Until the set is
   there, the rule simply does not match and the query follows the catch-all
   `"*"`. Subsequent queries see the set.
3. **Disk cache.** Written atomically (tmp + rename). With a cache present it
   works offline.
4. **Timeouts match the file size:** 15 s to connect, up to 10 minutes for the
   body. 404/403/410 responses are remembered until restart; network failures
   are not — the next reference retries.
5. **`include:` is expanded** (per-name mode). v2fly lists are trees of
   `include:`; attributes (`name @ads`) are stripped — we cannot filter by
   attribute, so the entry is taken whole. The parent set is rebuilt when an
   included set arrives.
6. **Refresh at 00:00** local time: a single `.dat` is re-downloaded whole and
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
