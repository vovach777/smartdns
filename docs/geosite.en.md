# geosite: ready-made domain lists in routing

`geosite:` is a route rule that points at a **set of domains** in a file rather
than a single name. The sets come from public repositories
(Loyalsoldier/v2ray-rules-dat, v2fly, sing-box) as plain text lists — one file
per category.

> Русская версия: [geosite.md](geosite.md)

---

## Quick start

```yaml
geosite_dir: /etc/smartdns/geosite     # directory with <name>.txt files

routes:
  - match: ["geosite:category-ads-all"]
    chain: [blocked]                    # first match wins
  - match: ["geosite:cn"]
    chain: [local]
  - match: ["*"]
    chain: [upstream]
```

Files:

```
/etc/smartdns/geosite/cn.txt
/etc/smartdns/geosite/category-ads-all.txt
```

Set name = file name without `.txt`, so `geosite:cn` → `cn.txt`.

---

## List format

```
# comment
domain:example.com          # example.com and every subdomain
full:only.example.org       # exactly this name, no subdomains
plain.net                   # same as domain:plain.net
```

| line | meaning |
|---|---|
| `#` | comment to end of line |
| `full:name` | exact match only |
| `domain:name` | the name and any subdomain (on a dot boundary) |
| bare `name` | same as `domain:name` |
| blank lines | ignored |

Deliberately **not supported**:

| directive | why not |
|---|---|
| `regexp:` | unpredictable cost per query; the whole point of the matcher is hundreds of nanoseconds |
| `keyword:` | same, plus false positives |
| `include:` | sets compose at the `routes` level anyway |

A `regexp:` line is a **load error** with path and line number, not a silent
skip — a rule that "sometimes does not fire" is far more expensive to debug.

---

## Where to get the lists

Categories live next to the binary databases in the same repositories, as text:

| source | path in the repo |
|---|---|
| Loyalsoldier/v2ray-rules-dat | `geosite/<category>.txt` (and `geoip/` for addresses) |
| v2fly/domain-list-community | `data/<category>` (same format) |
| sing-box / SagerNet | `geosite.db` (binary) — not usable here, take the text lists |

Put only the categories you need into `geosite_dir`; the whole repository is not
required. Updating means overwriting files — the resolver picks them up itself.

Licences and update cadence are the source's business: this is external data,
the resolver only reads it.

---

## How matching works

The name is lower-cased, a trailing dot is stripped, and **suffixes on dot
boundaries** are checked:

```
query: a.b.example.com
checked: a.b.example.com → b.example.com → example.com → com
```

- `domain:example.com` matches `a.b.example.com`, but **not** `badexample.com`;
- `full:example.com` matches `example.com` only;
- `routes` order matters: the first matching rule wins, so put `geosite:` rules
  above the catch-all `"*"`.

Cost: sorted suffix slice + binary search. Measured on a 300 000-entry set —
**123 ns per query**, ~13 MB heap:

```
BenchmarkDomainSetMatch-24   19280059   123.3 ns/op
```

For scale: a cache hit is a few microseconds, an upstream query 1–50 ms. The
matcher disappears in that noise.

---

## Reloading without a restart

| trigger | behaviour |
|---|---|
| automatic | every 5 s the mtime/size of files in `geosite_dir` are compared; on change the config is re-read and the cache flushed |
| `SIGHUP` | the same, immediately |
| restart | only when the YAML changes (e.g. a new `geosite:` rule) |

After a YAML edit: `systemctl reload smartdns`.

---

## Verification and troubleshooting

```bash
smartdns -check -config smartdns.yaml
```

```
geosite: 1 наборов из /etc/smartdns/geosite
  cn                             /etc/smartdns/geosite/cn.txt    41233 записей

цепочки (первое совпадение выигрывает):
  geosite:cn                     -> local
  *                              -> upstream
```

(The binary prints these lines in Russian: "1 set(s) from …", "entries",
"chains (first match wins)".)

A name did not match — check in order:

1. does `-check` list the set? If not, the file is not in `geosite_dir` or not `.txt`;
2. `domain:` versus `full:` — only `domain:` matches subdomains;
3. is the `geosite:` rule **above** the catch-all `"*"`? Otherwise it is never reached;
4. dot boundary: `domain:example.com` does not catch `badexample.com`;
5. the log shows a parse error — the set was rejected as a whole and the previous
   config keeps serving.

---

## Not implemented (on purpose)

- **`geoip:`** (address sets, CIDR) — a separate task: it must match the
  *answer*, not the queried name, which is a different decision path;
- **automatic download** of lists — a resolver should not fetch its own rules
  from the internet;
- **`regexp:`** — see above.

---

## References

- implementation: `geosite.go` (`parseDomainSet`, `domainSet.match`, `watchGeosite`);
- config: `config.go` (`GeositeDir`, `geosite:` handling in `routeFor`);
- tests and benchmark: `geosite_test.go`.
