# Hosts-file records

The resolver can answer from files in the `/etc/hosts` format — the same files
the system itself reads. This is useful when one record has to work on several
machines and copying it into every `/etc/hosts` is not acceptable.

The classic case: a name exists in `/etc/hosts` on a build host but **never
reaches a container** — Docker generates a separate `/etc/hosts` for every
container. If the resolver reads the same file and answers over the network,
the record becomes shared and is maintained with a single `append`.

> Русская версия: [hosts.md](hosts.md)

---

## Quick start

```yaml
hosts_files:
  - /etc/hosts          # a regular file
  - /etc/hosts.d        # a directory: every file inside, sorted by name
```

No restart is needed: file changes are picked up in about 5 seconds (see
[Reloading](#reloading)).

Check how the config was understood:

```bash
smartdns -check -config smartdns.yaml
```

```
hosts_files: 1 из конфига, 3 из файлов
  /etc/hosts                             3 записей, перекрыто 1
```

(The messages are Russian in the binary; they read "1 from the config, 3 from
files … entries, 1 shadowed".)

---

## File format

An ordinary `/etc/hosts`:

```
# comment
172.17.0.77   serv_das.po.perco.ru  serv-das
10.0.0.7      my.local.test
::1           v6.local.test
```

Parsing rules:

| Element | Meaning |
|---|---|
| `#` | starts a comment, to end of line |
| blank lines | ignored |
| first field | IPv4 or IPv6 address (`net.ParseIP`) |
| remaining fields | names; each one gets that address, aliases work |
| trailing dot | stripped (`my.local.` → `my.local`) |
| letter case | lower-cased — DNS is case-insensitive |
| garbage in the first field | **hard error with path and line number**, the file is not applied partially |

Example error:

```
smartdns: /etc/hosts.d/lab:3: не адрес: "10.0.0."
```

This is deliberate: a silently skipped hosts line is a name that "sometimes does
not resolve", and that diagnosis costs far more than a loud failure at startup.

---

## Precedence and merging

```
hosts:            (YAML)   ← highest priority
  ↓
hosts_files: [file1, file2, dir/…]
  ↓
first occurrence of a name wins
```

- an entry in the `hosts:` section **always** shadows a file entry: a local
  override must not depend on what somebody appended to `/etc/hosts`;
- inside and across files the rule is "first wins", exactly as in a classic
  `/etc/hosts`;
- shadowed entries are not lost silently: `-check` reports `перекрыто N`
  ("shadowed N"), and the startup log states how many entries came from the
  config and how many from files.

Example: config has `keep.example: 10.9.9.9`, a file has
`keep.example 10.1.1.1` → the answer is `10.9.9.9`, and the file entry is
counted as shadowed.

---

## Reloading

| Trigger | When it fires |
|---|---|
| automatic | every **5 seconds** `mtime` and `size` of each file are compared; on mismatch the config is re-read and the cache is flushed |
| manual | `SIGHUP` (`systemctl reload smartdns`) — the same, immediately |
| restart | only needed when the YAML itself changes |

Things worth knowing about the automatic path:

- the **whole config** is re-read, not just hosts; the cache is flushed, so the
  next query goes to an upstream;
- the file list is rebuilt: a new file appearing in a watched directory is
  picked up;
- if the new state contains a parse error, the reload is rejected, the reason is
  logged, and the previous state keeps serving;
- removing a file from the list (a YAML edit) needs `SIGHUP` or a restart.

---

## Directories

A directory is read **non-recursively**: every regular file inside, in
alphabetical order. Subdirectories are ignored. This is convenient for
deployment: a service drops its own file into `/etc/hosts.d/50-service` without
touching a shared one.

Order is alphabetical, so `10-…` shadows `20-…` (first wins).

---

## What files cannot do

`hosts:` in YAML is more capable; a file only provides "address → name":

| Feature | `hosts:` (YAML) | hosts file |
|---|---|---|
| IPv4 / IPv6 | yes | yes |
| several addresses, comma-separated | yes | no (one per line) |
| `"*.domain"` (suffix match) | yes | **no** |
| `nxdomain` / `refused` (blocking) | yes | **no** |
| CNAME (value is a domain) | yes | **no** |

Need blocking or a pattern? Use `hosts:`. Files are for plain address-name
pairs.

---

## Verification and troubleshooting

```bash
# how the config was understood (starts nothing)
smartdns -check -config smartdns.yaml

# what actually answers
dig @127.0.0.1 serv_das.po.perco.ru A +short
dig @127.0.0.1 my.local.test A +short
dig @127.0.0.1 v6.local.test AAAA +short
```

A name does not resolve — check in this order:

1. does `-check` list the file at all? If not, wrong key or wrong path;
2. does the file show `перекрыто N` (shadowed)? Then the name was defined
   earlier — in the YAML or in a file that comes first;
3. can the service user read the file? (`644` plus directory access; under a
   systemd unit with `User=` this is not necessarily `root`);
4. does the name match exactly? (case does not matter, a hyphen versus an
   underscore does);
5. `SIGHUP` did not help and the log shows a parse error — the file was rejected
   as a whole.

---

## Example: a name for containerised builds

Goal: `serv_das.po.perco.ru` must resolve both on the host and inside
containers that have no `/etc/hosts` of their own.

```yaml
# smartdns.yaml on the build host
listen: 172.17.0.133:53
servers:
  resolved: 127.0.0.53:53
routes:
  - match: ["*"]
    chain: [resolved]
hosts_files:
  - /etc/hosts        # already holds 172.17.0.77 serv_das.po.perco.ru
```

```yaml
# docker/compose.yml — the container asks this resolver
services:
  sdk:
    dns: ["172.17.0.133"]
```

From then on any edit of the host's `/etc/hosts` is visible inside the
container within ~5 seconds — no `extra_hosts`, no container restart, no DNS
zone change.

---

## References

- implementation: `hosts_files.go` (`loadHostsFiles`, `watchHostsFiles`);
- config keys: `config.go` (`HostsFiles`), known-key list — `knownTopKeys`;
- answering: `resolve.go` (`hostValue`, `hostAnswer`).
