# TODO

Findings from a review of this repo, originally written 2026-09-01 and revised
the same day after verifying every item against the tree, against a real
`docker build`, and against the seven live production nodes.

Ordered by priority. **Items 2 and 3 are order-dependent — read the note on
item 3 before starting item 2.**

## Context you need

This service is the TLS/DoH/DoT front-end for the public Bancuh DNS resolvers.
It runs as a supervisor process (`src/main.rs`) that spawns three children:

- `dnsdist` — the actual DNS proxy, configured by `dnsdist.conf`
- `certbot` — obtains/renews the Let's Encrypt cert (`src/tasks/certbot.rs`)
- `dnstap` — writes query logs to `logs.yaml`, consumed by `src/logs/`

It is deployed from the `adblock-dns-server` repo
(`EXAMPLES/default/docker-compose.yml`), where it runs with
**`network_mode: host`** and `privileged: true`, in front of `bancuh-dns` which
listens on `127.0.0.1:1153`. Seven production nodes run this.

Bear in mind while working: this container terminates TLS and holds the Let's
Encrypt private keys, and if it stops, all seven nodes stop answering DNS.

### Deployment path — how a merge to master reaches production

Worth understanding before pushing anything:

1. `.github/workflows/build-docker-image.yml` fires on push to `master` and
   publishes `type=raw,value=latest`.
2. The production compose references `image: ragibkl/dnsdist-acme` — **untagged,
   therefore `:latest`**.
3. `start.sh` runs `docker compose pull` before `up -d`.

So a merge to master does not deploy, but it *arms* the change: the next run of
`deploy.sh` for any reason — including shipping an unrelated `bancuh-dns`
change — ships it to all seven nodes at once, bundled with whatever you thought
you were deploying. Note `bancuh-dns` is pinned to `:2` while `dnsdist-acme` is
unpinned, so this repo is the floating one. `:latest` is also the image the
README hands to the public.

Note the workflow's `on:` triggers are only `push` to `master` and
`pull_request` targeting `master` — **pushing a branch builds nothing**. To get
a canary image you must open a PR against master, which publishes
`ragibkl/dnsdist-acme:pr-<N>` via `type=ref,event=pr` and does *not* publish
`:latest`, since that tag is gated on `github.ref == refs/heads/master`. Pin one
node's compose to the `pr-<N>` tag and run `./start.sh` there.

### Production state as measured 2026-09-01 (~2h window)

| node | dropped | forwarded | drop rate | restarts | cert expires | mem |
|---|---|---|---|---|---|---|
| sg-dns1 | 8,896 | 136,569 | 6.12% | 0 | Oct 14 | 73 MB |
| sg-dns2 | 582 | 20,819 | 2.72% | 0 | Nov 13 | 51 MB |
| fr-dns1 | 609 | 13,928 | 4.19% | 0 | Nov 17 | 40 MB |
| fr-dns2 | 419 | 18,490 | 2.22% | 0 | Nov 17 | 41 MB |
| jp-dns1 | 20,298 | 213,603 | 8.68% | 0 | Nov 17 | — |
| jp-dns2 | 0 | 691 | 0% | 0 | Nov 17 | — |
| us-dns1 | 25 | 6,821 | 0.37% | 0 | Oct 28 | — |
| **total** | **30,829** | **410,921** | **6.98%** | | | |

Read from the dnsdist console (`showRules()`, `showServers()`, `topClients()`).
Useful consequences:

- Memory is 40–73 MB of 992 MB. Concerns about rate-limit state tables or logs
  memory are not currently justified by the numbers.
- `restarts=0` fleet-wide and every cert is healthy, so items 2 and 3 have never
  fired in anger. That is luck holding, not the design being sound.
- TCP/53 answers on all seven nodes (verified by `dig +tcp`).
- Two hosts (`jp-*`, `us-*`, `fr-*`) have no `bash` — use `sh` for remote
  scripts. Container names differ too: `default_dnsdist_1` on `sg-*`,
  `default-dnsdist-1` elsewhere. Detect with
  `docker ps --filter ancestor=ragibkl/dnsdist-acme --format '{{.Names}}'`.

---

## 0. Rate limit — DONE, on branch `rate-limit-tune`, not yet merged

**Where:** `dnsdist.conf:41`.

`MaxQPSIPRule(10, 32, 48)` omitted the 4th parameter, `burst`, which **defaults
to `qps`**. So sustained *and* burst allowance were both 10. DNS is bursty — one
page load with third-party domains fires 20–50 lookups in well under a second —
so the bucket empties before the page finishes loading. The running rule printed
its own parameters as `QPS over 10 burst 10`, confirming this on production.

Measured impact: **~7% of all queries dropped fleet-wide**, 8.68% on jp-dns1.

`DropAction` also makes it worse than it needs to be: a drop sends nothing, so
the client waits out its full timeout (1–5s) and then *retries* — more load, and
the user experiences a stall. `TCAction` truncates instead, and the client
retries over TCP transparently.

The rule was doing double duty — abuse control *and* the only amplification
mitigation for an open resolver (`setACL` on line 13). Simply raising the
ceiling would have traded that away. The committed split does not: truncated
responses are query-sized (amplification factor ~1) and a spoofed source cannot
complete a TCP handshake, so reflection protection is *better* than before,
while real users get 5–10× more headroom.

**Before merging — the one open question.** `topClients` shows the drops are
concentrated, not spread: one source is 31.6% of jp-dns1's traffic and a second
is 13.6% (~45% between them); sg-dns1 has one at 24.3%. These are
indistinguishable at this level from abuse, a downstream forwarder, or a large
CGNAT egress. That splits the change by risk:

- **Drop → TCAction is safe to ship.** It helps legitimate clients regardless of
  who the heavy talkers are and gives an abuser nothing.
- **10 → 50 qps is the part needing a canary**, because it is precisely what
  lets those heavy sources through. If they are abuse, it raises their ceiling
  5×.

Canary on **jp-dns1** — worst offender at 8.68%, so the effect shows fastest.
jp-dns2 is useless for this (no traffic). Watch `showRules()` match counts, TCP
connection count, and RSS.

Note `dnsdist.conf` sets none of `setMaxTCPClientThreads`,
`setMaxTCPConnectionsPerClient` or `setMaxTCPQueuedConnections`, so they sit at
defaults. Shifting UDP traffic onto TCP is the one plausible way this degrades
service, and is what the canary is watching for.

## 1. Stale base image and unpinned build dependencies — DONE, on branch `bump-alpine-dnsdist`, not yet merged

**Where:** `Dockerfile:2`, `:23`, `:29` — all three stages were `alpine:3.19`.

Alpine 3.19 shipped Dec 2023 with security support to **2025-11-01**, so roughly
ten months unpatched — not two years, as an earlier draft of this file claimed.
The running image contained **dnsdist 1.8.2-r1, certbot 2.7.4, gcompat
1.1.0-r4**. PowerDNS secpoll reports 1.8.2 on every production node as
`Security Update Recommended: Unsupported release (EOL)`.

### Choosing the target: 3.23, not 3.22

Both packaged versions carry **mandatory** advisories, but they are not
equivalent:

| base | dnsdist | certbot | outstanding advisory |
|---|---|---|---|
| 3.19 (was) | 1.8.2 | 2.7.4 | EOL, not tracked at all |
| 3.22 | 1.9.11 | 4.0.0 | 2026-02 **and** 2026-09 |
| 3.23 (chosen) | 2.0.4 | 5.1.0 | 2026-09 only |

- Advisory **2026-02** affects 1.9.0–1.9.11 and 2.0.0–2.0.2, fixed in 1.9.12 /
  2.0.3. It includes **CVE-2026-24029, a DoH ACL bypass at CVSS 6.5**, which
  applies directly — these nodes serve DoH.
- Advisory **2026-09** affects up to 1.9.14 / 2.0.6, fixed in 1.9.15 / 2.0.7.
  Its seven CVEs cover the web server (not enabled here), DoH3/DoQ (not used —
  this config uses HTTP/2 `addDOHLocal`), IXFR, ECS insertion and
  `SetMacAddrAction`, none of which this config uses.

So 2.0.4 is strictly better than 1.9.11, and an earlier draft's advice to prefer
3.22 as "conservative" was wrong. Neither is fully clean — reaching 2.0.7 means
building dnsdist from source or leaving Alpine. **Follow-up: watch for a 2.0.7
package.** The applicability judgement above is about this config and is not
quoted from the advisories; re-check it before relying on it.

### The bump would have silently broken cert reloads

**dnsdist 2.0 rejects a console key passed as `-k`.** Verified against a running
instance of each version:

| dnsdist | `-k <key>` | `-C <config>` |
|---|---|---|
| 1.8.2 | works | works |
| 1.9.11 | works | works |
| 2.0.4 | **fails** | works |

`src/tasks/dnsdist.rs` used `-k`. Combined with item 4 — the exit status is
never checked — this would have failed **silently**: `reloading certs for
dnsdist server. DONE` logged every hour while nothing reloaded, until DoT/DoH
began serving an expired certificate weeks later with nothing in the logs.

It now uses `-C dnsdist.conf`, which works on all three versions, so it is safe
to ship before or after the base bump. It also keeps the key off the command
line, which is part of item 2. Note the client evaluates the *whole* config, so
it needs the same `PORT`/`BACKEND`/`TLS_ENABLED` env vars as `spawn_dnsdist`;
without them it still connects but logs a spurious
`Error creating new server with address`.

### The Rust side, which was the forced part

`Cargo.toml:10` had `aws-lc-rs = { version = "*", features = ["bindgen"] }` — a
wildcard on a cryptography crate. Worse, the locked `aws-lc-sys 0.20.1` **only
built inside the EOL image**: on a current toolchain it fails under CMake 4.x
(`Compatibility with CMake < 3.5 has been removed`) and then, forced past that,
under GCC 15 (`-Werror=discarded-qualifiers`). A newer Alpine brings exactly
that newer CMake and GCC, so the base bump and the crypto pin were necessarily
one change.

Now `aws-lc-rs = "1.18"` (resolving 1.18.0 / aws-lc-sys 0.44.0) with the
`bindgen` feature dropped, since recent aws-lc-sys ships pregenerated musl
bindings. That also removed:

- `apk add clang clang-dev` — alpine 3.23 has no plain `clang` package anyway,
  only `clang16`/`clang18`, so this would have broken the build regardless
- `RUN cargo install --force --locked bindgen-cli` — the slowest step in the
  image build, and the second unpinned dependency

Image shrinks 160 MB → 126 MB. `.tool-versions` moves to `rust 1.91.1`.

**Verified:** `docker build` passes; `dnsdist --check-config` passes; the dnstap
Go stage builds on go 1.25.10; and `reloadAllCertificates()` was exercised end
to end against 2.0.4 with TLS enabled and real certificates.

## 2. dnsdist control-socket key is committed to a public repo

**Where:** `dnsdist.conf:33-34`, and the same literal again in
`src/tasks/dnsdist.rs:28-29`.

```lua
controlSocket('127.0.0.1')
setKey('miQjUydO7fwUmSDS0hT+2pHC1VqT8vOjfexOyvHKcNA=')
```

**Why it matters:** `controlSocket('127.0.0.1')` looks contained, but the
container runs with `network_mode: host`, so that is the *host's* loopback, not
a private network namespace. Any process on the droplet — or any other
host-networked container — can connect to it, and the key guarding it is
published on GitHub (`github.com/ragibkl/dnsdist-acme`, present since the
`rough skeleton` commit).

The dnsdist control socket is a Lua console. That is arbitrary code execution
inside the process that terminates TLS and holds the private keys: an attacker
could rewrite answers, dump traffic, or change the ACL.

Passing the key as `-k <key>` on the command line (`src/tasks/dnsdist.rs:28`)
additionally exposes it via `ps` to any user on the host.

**Suggested fix:** generate a fresh key at container start
(`openssl rand -base64 32`), hand it to dnsdist's config and to the reload path
through the environment rather than a literal, and keep it out of the repo. Note
that dnsdist reads `dnsdist.conf` as Lua, so `os.getenv` is available there —
the config already uses it for `PORT`, `BACKEND` and `TLS_ENABLED`. Consider
also setting `setConsoleACL` explicitly rather than relying on its default.

Prefer a mechanism that keeps the key off the command line entirely if dnsdist
supports it in the version pinned here; otherwise argv exposure is a smaller
problem than the committed literal, and fixing the literal alone is worthwhile.

The current key must be treated as permanently compromised — rotate it, do not
reuse it.

## 3. A renewal error takes the whole front-end down

**Do this before item 4, or in the same change. See the note at the end.**

**Where:** `src/main.rs:122`, `:133`, `:141` — the three error arms inside the
certbot auto-update task.

Each does `cloned_token.cancel(); return;`. That token cancels the whole
`TaskTracker`, so the supervisor exits and takes **dnsdist with it**. With
`restart: always` in the compose file, a transient certbot problem becomes a
restart loop of the service that answers all production DNS.

A failed *renewal* is not a reason to stop serving. The existing certificate is
still on disk and still valid — often for weeks. Log, keep serving, retry next
cycle.

This is the same bug that was fixed in the sibling `bancuh-dns` repo in PR #4.
Mirror the shape at `bancuh-dns/src/main.rs:200-207`:

```rust
if let Err(err) = cloned_engine.run_update().await {
    tracing::warn!("... ERROR: {err}. Keeping existing db, will retry next interval.");
}
```

Note the other `cancel()` calls in `main.rs` (the ones covering dnsdist and
dnstap exiting) are *correct* — if a supervised child dies the process should
come down so Docker restarts it. Only the certbot renewal arms should change.

## 4. certbot failures are silent, and can lead to unnoticed cert expiry

**Where:** `src/tasks/certbot.rs:29-31`.

```rust
.output()
.await
.unwrap();
```

Two problems in three lines:

- `.unwrap()` panics if certbot cannot be spawned at all.
- The returned `Output.status` is **never checked**, so a certbot that runs and
  fails is treated as success.

**Why it matters:** on failure (LE rate limit, port 80 blocked, DNS not
resolving, expired account) the code carries straight on to copy
`/etc/letsencrypt/live/<domain>/{fullchain,privkey}.pem` — which on a renewal
still holds the **previous** certificate. It copies the stale cert, reloads it
into dnsdist, and logs `certbot renewing certs. DONE`.

**The same bug exists in the reload path**, and was missed in the first draft.
`src/tasks/dnsdist.rs:32-35` captures `.status()`, logs it, and returns
`Ok(())` regardless:

```rust
let res = Command::new("dnsdist")...status().await?;
tracing::info!("dnsdist reload status: {res}");
Ok(())
```

So a failed console reload logs `reloading certs for dnsdist server. DONE` while
dnsdist keeps serving the **old certificate** until the container restarts. This
is more likely to bite than the certbot one, and it is coupled to item 2 —
rotate the key, get it slightly wrong, and this is exactly how you fail to
notice.

Branch `bump-alpine-dnsdist` changes *how* that command is invoked (`-C`
instead of `-k`, forced by dnsdist 2.0) but deliberately does **not** add the
status check, because doing so would newly trigger the `cancel()` at
`main.rs:141` — the same ordering hazard described below. The reload path is
still silent on failure.

**A status check alone is NOT sufficient for the reload path.** Measured on
the jp-dns2 canary running 2.0.4, the failing invocation still exits 0:

| invocation | exit code | output |
|---|---|---|
| `-C dnsdist.conf` (new) | 0 | clean, reload happened |
| `-k <key>` (old) | **0** | `The currently configured console key is not valid` |

The dnsdist console client reports success on the exit code even when it
refused to run the command. So `status.success()` would have sailed straight
past the 2.0 breakage. The reload path needs its output captured and inspected
(use `.output()` and treat any stderr/stdout content as failure), or the reload
needs verifying out-of-band — e.g. re-reading the cert dnsdist actually serves
on :853 and asserting its expiry moved.

**Suggested fix:** for certbot, check `status.success()` and log the captured
stderr. For the dnsdist reload, capture and inspect the output rather than
trusting the exit code. Return `Err` in both cases so the caller can react —
but see the ordering warning below before wiring that up. Consider also asserting the
copied cert's expiry actually moved, since "certbot succeeded" and "we now have
a fresher cert" are not the same claim.

**⚠ Ordering — this is why item 3 comes first.** Today `certbot.run()` only ever
returns `Err` from the *file copy*, so the arm at `main.rs:122` almost never
fires. Fix this item alone and you convert "silently serves a stale cert" into
"cancel the token → supervisor exits → dnsdist dies → restart loop" on all seven
nodes, on the first hour certbot has a bad day. Item 3 must land first, or in
the same change.

## 5. `logs.yaml` read-then-truncate drops log entries

**Where:** `src/tasks/dnstap.rs:53-56`.

```rust
let content = tokio::fs::read_to_string("./logs.yaml").await.unwrap_or_default();
let _ = tokio::fs::write("./logs.yaml", "").await;
```

`dnstap` appends to this file continuously while the consumer reads it once a
second (`src/logs/mod.rs`, `ingest_logs_from_file`). Anything dnstap writes
between the read and the truncate is silently lost — a steady trickle of dropped
entries under load, worse the busier the node.

It also reads the entire file into memory on every tick, and the read can land
mid-document, so the trailing partial record is both dropped *and* logged at
info by `extract_query_logs` (`src/logs/query_log.rs:86`) — which adds log volume
under exactly the conditions where log retention is already tight.

**Suggested fix:** rotate rather than truncate (rename and let dnstap reopen), or
read the dnstap stream directly instead of going via a file. If the file
approach is kept, track a byte offset and read only what is new.

---

## Lower priority

- **`/logs` shows DNS query history to anyone sharing your public IP.**
  `src/handler.rs:57`, `:70` key purely on the source IP of the HTTP request.
  Behind NAT or CGNAT — where a mobile carrier may put thousands of subscribers
  on one address — any of them can read the others' query history. Port 8080 is
  plain HTTP, so it is cleartext on the wire too. This is the product feature
  working as designed, and may be an accepted tradeoff, but it deserves an
  explicit decision the way the open-resolver item below got one.

- **`dnsdist.conf:13`** — `setACL({ '0.0.0.0/0', '::/0' })` makes this an open
  resolver. That is intentional for a public service, but on UDP/53 it is usable
  for amplification, with the QPS rule as the only mitigation. Worth a
  deliberate decision, and possibly response-rate limiting.

- **`html/.well-known` looks vestigial.** `src/main.rs:58` serves it on 8080 and
  8443, but certbot runs `--standalone` (`src/tasks/certbot.rs:20`), which binds
  its own listener on port 80 and never consults a webroot. Either this is dead
  code to delete, or someone intended `--webroot`. Confirm which before
  "fixing" the wrong half.

- **`dnsdist.conf:24-25`** — `doTCP` and `tcpFastOpenSize` are silently ignored
  by `addDOHLocal`, on 1.8.2 today and on every version tested. They were
  written expecting an effect and have never had one.

- **`src/logs/usage_stats.rs:17-32`** — `merge_logs` clones the map under one
  lock, mutates the clone, then overwrites under a second lock, so a concurrent
  writer's update would be lost. There is exactly one writer today, so it is
  benign — but it is a lost-update pattern on a `Clone` + `Arc` type that looks
  safe to call from anywhere, and it copies the whole map every second. Its
  guard is also still named `active_ips_one_day` while the cutoff is 10 minutes.

- **`src/logs/query_log.rs:31`** — `parse_query_time` uses `unwrap_or_default()`,
  yielding the Unix epoch on a parse failure. That is older than the 10-minute
  cutoff, so `remove_expired_logs` deletes such entries immediately: a dnstap
  timestamp format change would make `/logs` silently go empty with nothing in
  the logs to explain it.

- **`src/logs/query_logs.rs`** — `QueryLogs` has no per-IP cap, so a single noisy
  source is bounded only by the 10-minute expiry. `bancuh-dns` caps at
  `MAX_PER_IP = 1000` (`bancuh-dns/src/query_log.rs:11`). Commit `bece86a`
  ("reduce logs and ip stats memory") suggests this has been hit once, though
  current RSS (40–73 MB of 992 MB) shows no present pressure.

- **`src/handler.rs:84`** — `render_template(...).unwrap()` panics inside a
  request handler. The template is `include_str!`-ed and static so the risk is
  low, but a panic here is avoidable. The registry is also rebuilt and the
  template re-parsed on every request (`:74`); a `LazyLock` registry would do.
  Escaping is fine — `{{ }}` escapes, so no XSS.

- **`src/handler.rs:45`** — `ip.replace("::ffff:", "")` strips the IPv4-mapped
  IPv6 prefix by substring replacement. It is guarded by `starts_with` and a
  canonical `Display` cannot contain the prefix twice, so this is cosmetic
  rather than a bug. `strip_prefix` is the correct operation; the sibling
  `bancuh-dns` repo does it that way (`src/admin.rs:29`). `to_canonical()` is
  cleaner still.

- **`src/handler.rs:55`, `:68`** — every `/logs` request logs at info. Minor, but
  the sibling repo has just had to cut per-query logging because container log
  retention had dropped to ten minutes; the same pressure applies here.

- **`src/logs/query_logs.rs:41-46`** — `get_logs_for_ip` trips
  `clippy::manual_unwrap_or_default`, the only clippy warning in the tree once
  the toolchain builds again. Clippy's own suggestion:
  `self.logs_store.lock().unwrap().get(ip).cloned().unwrap_or_default()`.
  Left alone on the bump branch as out of scope for a version bump.

- **`src/main.rs:27`** — typo in the doc comment: "custom l istener port".

- **Operational, not in this repo: jp-dns2 receives almost no traffic.** jp-dns1
  served 213,603 queries in the measurement window; jp-dns2 served 691, a 300:1
  split. sg is 6.5:1. jp-dns2 answers correctly over both UDP and TCP, so the
  node is healthy — it simply is not being asked. If jp-dns1 fails, the standby
  is one nothing is configured to use. Worth investigating in
  `adblock-dns-server`.

- **README drift** — says the image is "only available for Docker architecture
  linux-x86_64" and that Raspberry Pi support is future work, but CI already
  builds `linux/amd64,linux/arm64,linux/386,linux/arm/v7`. `Dockerfile:46`'s
  `EXPOSE` also omits 443 and 853, the DoH/DoT ports.

---

## Verifying changes

There are no integration tests in this repo (there are two unit tests in
`src/logs/query_log.rs`), and the container needs a real domain plus ports
80/443/853 to exercise the certbot and TLS paths, so most of this cannot be
verified locally end to end.

**On master, `cargo build --release` and `cargo clippy --all-targets` do not
work on a current host** — they fail inside `aws-lc-sys 0.20.1` before reaching
any code in this repo. See item 1. An earlier draft of this file recommended
them without qualification.

**On branch `bump-alpine-dnsdist` they work again.** Verified under alpine 3.23
(rust 1.91.1): `cargo test` passes both unit tests, and `cargo clippy
--all-targets` reports a single warning. Note the clippy package on Alpine is
`rust-clippy`, not `clippy`, and `apk add` is atomic — a wrong package name
aborts the whole install and leaves you without cargo:

```sh
docker run --rm -v "$PWD:/w" -w /w alpine:3.23 sh -c \
  'apk add --quiet rust cargo build-base cmake perl rust-clippy; cargo test --release'
```

What also works:

- **`docker build .`** — passes today (exit 0), and catches the base image and
  dependency problems that are most of item 1.
- **dnsdist config syntax**, against any version, without deploying:
  ```sh
  docker run --rm -v "$PWD/dnsdist.conf:/w/dnsdist.conf:ro" -w /w alpine:3.23 sh -c \
    'apk add dnsdist >/dev/null 2>&1;
     PORT=53 BACKEND=127.0.0.1:1153 TLS_ENABLED=true \
     dnsdist --check-config --config dnsdist.conf'
  ```
- **Reading live state** from a node, given the control-socket key:
  ```sh
  CID=$(docker ps --filter ancestor=ragibkl/dnsdist-acme --format '{{.Names}}' | head -1)
  docker exec $CID dnsdist -c 127.0.0.1 -k "$KEY" -e 'showRules()'
  ```
  `showRules()` gives per-rule match counts, `showServers()` totals and latency,
  `topClients(n)` the heaviest sources. Capture a baseline *before* changing a
  rule; you cannot get it afterwards.

For anything touching certbot, use Let's Encrypt's **staging** directory rather
than production — failed validations against production count against a
per-domain rate limit, and this service's renewal loop retries hourly.

Do not deploy to the production nodes without the owner's say-so. They are
listed in `adblock-dns-server/scripts/deploy.sh`, and that script deploys to
**all seven at once**; a canary is a `git pull && ./start.sh` on a single host,
or better, pinning one node to a branch tag (see "Deployment path" above).

**Node-specific cautions:**

- **sg-dns2 serves the maintainer's own laptop.** Do not disrupt it.
- **jp-dns2 is the safe canary for anything image-level** — it is healthy but
  carries almost no traffic. For the same reason it is *useless* for validating
  rate-limit changes; use jp-dns1 for those.
