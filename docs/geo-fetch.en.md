# URL-sourced sets: lazy loading and midnight refresh

`geosite:`/`geoip:` sets do not have to be placed on disk by hand — the resolver
downloads them when they are first needed and refreshes them once a day.

> Русская версия: [geo-fetch.md](geo-fetch.md)

---

## Config

```yaml
geo_cache_dir: /var/cache/smartdns      # where to keep files (default)
geosite_url: https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/{name}
geoip_url:   https://www.ipdeny.com/ipblocks/data/aggregated/{name}-aggregated.zone
```

`{name}` is the set name from the rule (`geosite:category-ads-all` →
`category-ads-all`). Both defaults are built in; override only to change the
source (mirror, local server, another branch).

---

## Behaviour

1. **Lazy.** A set is fetched the first time a rule references it (at startup
   only sets mentioned in `routes` / `answer_geoip` are scheduled).
2. **Never blocks DNS.** The transfer runs in a goroutine. Until the set is
   there, the rule simply does not match and the query follows the catch-all
   `"*"`. Subsequent queries see the set.
3. **Disk cache.** `<geo_cache_dir>/geosite/<name>.txt` and
   `<geo_cache_dir>/geoip/<name>.txt`, written atomically (tmp + rename). With a
   cache present it works offline.
4. **`include:` is expanded.** v2fly lists are trees of `include:`; attributes
   (`name @ads`) are stripped — we cannot filter by attribute, so the entry is
   taken whole. The parent set is rebuilt when an included set arrives.
5. **Refresh at 00:00** local time: only already-loaded sets are re-downloaded,
   then the config is re-read.

---

## Not implemented

- no bulk download of every set in the repository — only referenced ones;
- v2fly attributes (`@ads`, `@cn`) are not filtered;
- `regexp:`/`keyword:` lines from lists are skipped and counted (visible in `-check`);
- refresh overwrites files, no version history;
- 404s and other failures are remembered until restart, so the same name is not
  hammered every second.

---

## Diagnostics

```
гео-наборы: лениво по URL, кэш /var/cache/smartdns
  домены: https://…/{name}
  адреса: https://…/{name}-aggregated.zone
  обновление: ежедневно в 00:00
```

Log:

```
гео: geosite:category-ads-all загружен по URL и применён
гео: geosite:zhihu — загрузка не удалась: HTTP 404 …
гео: полночь — обновляю загруженные наборы
```

A rule "not firing" right after start is expected: the set is still downloading.
Confirm it landed: `ls <geo_cache_dir>/geosite/`.
