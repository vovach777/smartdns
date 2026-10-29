# geoip: filtering answers by address sets

In this resolver `geoip:` is **not** a routing rule. A route is chosen by name
before the query; an address only appears in the answer. So here it is an
**answer filter**: it looks at the addresses in the answer and can rewrite the
result (`nxdomain` / `refused` / empty `noerror`).

The key property: the filter never asks anything again. The answer is filtered
once and cached in that form, so there is nothing to loop on and no second
upstream query.

> Русская версия: [geoip.md](geoip.md)

---

## Quick start

```yaml
geoip_dir: /etc/smartdns/geoip

answer_geoip:
  - set: blocked          # file /etc/smartdns/geoip/blocked.txt
    action: nxdomain      # nxdomain | refused | noerror
```

`blocked.txt`:

```
# one prefix or address per line
203.0.113.0/24
198.51.100.7
# IPv6 lines are skipped and counted separately
2001:db8::/32
```

An answer containing an address from the set is rewritten:

| action | what the client sees |
|---|---|
| `nxdomain` | `NXDOMAIN`, records dropped |
| `refused` | `REFUSED`, records dropped |
| `noerror` (or empty) | empty `NOERROR` — "no such record", without NXDOMAIN |

---

## Why a filter and not a route

Three possible places for an address-based decision:

| where | feasible? | outcome |
|---|---|---|
| by name (geosite) | yes | pick the chain before the query — current behaviour |
| by answer address, switching chain | **dangerous** | would need to resolve again → loop, repeated queries, unstable cache |
| by answer address, rewriting the answer | **yes** | one query, deterministic result, the cache already holds the filtered answer |

We do the third. Hence the guarantee: **one query — one answer**, no retries.

Verified on a live build:

```
1st query github.com  → ГЕО ... отфильтровано → NXDOMAIN   (went to the upstream)
2nd query github.com  → КЭШ              → NXDOMAIN   (upstream not asked)
```

---

## Set format

| line | meaning |
|---|---|
| `10.0.0.0/8` | CIDR |
| `203.0.113.7` | a single address |
| `# …` | comment |
| IPv6 (`2001:db8::/32`) | **skipped**, the counter is visible in `-check` |

Overlapping and adjacent ranges are merged at load time; lookups are a binary
search over sorted ranges — around a hundred nanoseconds per address.

Garbage on a line is a load error with path and line number.

---

## Verification

```bash
smartdns -check -config smartdns.yaml
```

```
geoip: 1 наборов из /etc/smartdns/geoip
  blocked              /tmp/gip/geoip/blocked.txt               1 префиксов
  фильтр ответа: geoip:blocked -> nxdomain
```

(Russian output: "1 set(s) from …", "prefixes", "answer filter: geoip:blocked
-> nxdomain".)

---

## Reloading

Same watcher as `hosts_files` and `geosite`: every 5 seconds mtime/size of the
files in `geoip_dir` are compared; on change the config is re-read and the cache
is flushed. `SIGHUP` does the same manually.

Note: after a cache flush the first answers go to the upstream again — expected,
the filter is applied to them anew.

---

## Limits

- IPv4 only;
- the filter does not affect routing: "go to another chain if the address is
  wrong" is deliberately not implemented;
- no automatic download of lists;
- `answer_geoip` works on `A` records (`AAAA` is stripped by the separate
  `ipv6: false` rule when enabled).

---

## References

- implementation: `geoip.go` (`parseIPSet`, `ipSet.match`, `applyAnswerGeoip`);
- config: `config.go` (`GeoipDir`, `AnswerGeoip`);
- tests: `geoip_test.go`.
