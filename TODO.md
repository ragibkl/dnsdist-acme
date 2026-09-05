# TODO

Findings from a review of this repo, originally written 2026-09-01 and revised
since against the tree, against a real `docker build`, and against the seven
live production nodes.

Everything originally filed as items 0-4 is merged and rolled out; those are
kept at the end as **Done**, for the reasoning rather than the status. What
remains is triaged below. References here are checked against the tree when
they are touched -- several items in earlier revisions described code that no
longer existed.

## Context you need

This service is the TLS/DoH/DoT front-end for the public Bancuh DNS resolvers.
It runs as a supervisor process (`src/main.rs`). dnsdist is now its only child;
ACME and dnstap are handled in-process:

- `dnsdist` — the actual DNS proxy, configured by `dnsdist.conf`
- ACME — the Let's Encrypt cert is obtained and renewed **in-process** by
  `rustls-acme` (`src/tasks/acme.rs`), not by a child process. See item 3
- dnstap — query logs arrive from dnsdist over a unix socket and are parsed
  in-process (`src/logs/framestream.rs`, `src/logs/dnstap_proto.rs`). No child
  process, no file. See item 4

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

## Open items

Triaged 2026-09-05. Nothing here is urgent; the fleet is healthy and uniform.

### Worth doing next

- **`src/logs/query_logs.rs` has no per-IP cap.** A single noisy source is
  bounded only by the 10-minute expiry. `bancuh-dns` caps at `MAX_PER_IP = 1000`
  (`bancuh-dns/src/query_log.rs:11`). Commit `bece86a` ("reduce logs and ip
  stats memory") suggests this has been hit at least once. Current RSS (40-73 MB
  of 992 MB) shows no present pressure, so this is insurance, not a fire.

- **`serde_yaml` is a dead dependency.** It is declared in `Cargo.toml:24` and
  used **nowhere in `src/`** -- the YAML ingestion path it served was deleted
  with the dnstap rewrite. Earlier revisions of this file called it a risky swap
  because it "parses dnstap output on the ingestion path"; that is no longer
  true. It is now a one-line deletion, which also retires an archived,
  unmaintained crate (`0.9.34+deprecated`). Verify with `grep -rn serde_yaml src/`
  before removing.

- **`src/handler.rs:84`** -- `render_template(...).unwrap()` panics inside a
  request handler. The template is `include_str!`-ed and static so the risk is
  low, but a panic here is avoidable. The registry is also rebuilt and the
  template re-parsed on every request (`:74`); a `LazyLock` registry would fix
  both. Escaping is fine -- `{{ }}` escapes, so no XSS.

### Cheap and low risk

- **`html/.well-known` is vestigial.** `src/main.rs:87` serves it via `ServeDir`
  on 8080 and 8443, but the ACME challenge has its own listener on port 80
  (`src/tasks/acme.rs`). It was already unused under certbot's `--standalone`.
  Delete the directory and the route.

- **`dnsdist.conf:29-30`** -- `addTLSLocal` does not pass `reusePort`, while the
  DNS and DoH listeners do. Harmless today, and the one-line prerequisite for
  the overlap restart in B+ below: without it a replacement dnsdist cannot bind
  :853 alongside the outgoing one, so DoT would gap.

- **`dnsdist.conf:25-26`** -- `doTCP` and `tcpFastOpenSize` are silently ignored
  by `addDOHLocal`, on 2.0.4 and every version tested. Written expecting an
  effect they have never had.

- **`src/logs/usage_stats.rs:25`** -- the guard is named `active_ips_one_day`
  while the cutoff is 10 minutes. Misleading when reading the expiry logic.

- **`src/handler.rs:45`** -- `ip.replace("::ffff:", "")` strips the IPv4-mapped
  prefix by substring replacement. Guarded by `starts_with`, and a canonical
  `Display` cannot contain the prefix twice, so cosmetic rather than a bug.
  `strip_prefix` is the correct operation; `to_canonical()` is cleaner still.
  `bancuh-dns` does it that way (`src/admin.rs:29`).

- **`src/main.rs:30`** -- typo in the doc comment: "custom l istener port".

- **`Dockerfile:39`** -- `EXPOSE` omits 443 and 853, the DoH/DoT ports. Purely
  documentary, but wrong. (The rest of the old "README drift" item is resolved:
  the README now lists all four published architectures and describes the
  socket-based dnstap correctly.)

### Needs a decision, not just work

- **Remove the dnsdist console entirely (options B / B+).** Item 2 shipped
  option A -- a key generated per process start -- which closed the actual
  vulnerability. B deletes the console and restarts dnsdist to pick up a
  renewed certificate; B+ overlaps the restart via `reusePort` so no query is
  dropped. Both cost `showServers()`, `topClients()` and `showRules()`, which
  are the tools used to measure every change in this file. Measured restart
  downtime for plain B: 353 ms, 374 ms, 42 ms across three runs, roughly six
  times a year per node. **Recommendation: leave it.** A already removed the
  published secret; B/B+ trade real diagnostics for a console that is now
  key-guarded and loopback-only. Full analysis in item 2 under Done.

- **`src/handler.rs:55`, `:68`** -- every `/logs` request logs at info. Minor
  here, but the sibling repo has already had to cut per-query logging because
  container log retention had fallen to ten minutes. Same pressure applies.

### Not this repo

- **jp-dns2 receives almost no traffic.** jp-dns1 served 213,603 queries in the
  measurement window; jp-dns2 served 691, a 300:1 split. sg is 6.5:1. jp-dns2
  answers correctly over UDP, DoT and DoH, so the node is healthy -- it simply
  is not being asked. If jp-dns1 fails, the standby is one nothing is configured
  to use. Worth investigating in `adblock-dns-server`.

## Decided and accepted

Recorded so they are not re-filed as findings. Both are the product working as
designed, confirmed by the maintainer 2026-09-05.

- **`/logs` shows query history to anyone sharing your public IP.**
  `src/handler.rs:57` and `:70` key purely on the source IP of the HTTP request,
  so behind NAT or CGNAT -- where a carrier may put thousands of subscribers on
  one address -- any of them can read the others' query history. Port 8080 is
  plain HTTP, so it is cleartext on the wire too. **Intentional.** It is what
  makes the page useful without accounts.

- **`dnsdist.conf:14`** -- `setACL({ '0.0.0.0/0', '::/0' })` makes this an open
  resolver, usable for amplification on UDP/53. **Intentional**: it is a public
  adblock DNS service and must stay open. Mitigation therefore has to come from
  rate limiting rather than the ACL -- see item 0 under Done, which truncates
  over UDP rather than dropping, so a spoofed source cannot complete the
  handshake and a truncated response carries no amplification gain. Live
  `showRules()` on jp-dns1 confirms it working: 97 truncations, 0 drops.


## Verifying changes

**`tests/e2e/run.sh`** is the end-to-end ACME suite, run against a local
[Pebble](https://github.com/letsencrypt/pebble). Sixteen assertions covering
first issuance, restart with a warm cache, re-issuance, and the console/cert
reload path — each certificate check reading the certificate **dnsdist actually
serves on :853**, not the file on disk. Those are
different claims and only the second matters to a client. Takes about 90
seconds.

It is the only check that catches a broken challenge route. The axum
path-parameter syntax (`{token}` on 0.8, `:token` on 0.7) compiles either way
with no warning and fails only at runtime; getting it wrong means the
certificate never issues, dnsdist never starts, and the node is fully down. That
bug was introduced and caught twice during this work.

`cargo build --release`, `cargo test` and `cargo clippy` all work since the
toolchain bump. Note the clippy package on Alpine is `rust-clippy`, not
`clippy`, and `apk add` is atomic — a wrong package name aborts the whole
install and leaves you without cargo:

```sh
docker run --rm -v "$PWD:/w" -w /w alpine:3.23 sh -c \
  'apk add --quiet rust cargo build-base cmake perl rust-clippy; cargo test --release'
```

What also works:

- **`docker build .`** — passes, and catches base image and dependency problems.
- **dnsdist config syntax**, against any version, without deploying:
  ```sh
  docker run --rm -v "$PWD/dnsdist.conf:/w/dnsdist.conf:ro" -w /w alpine:3.23 sh -c \
    'apk add dnsdist >/dev/null 2>&1;
     PORT=53 BACKEND=127.0.0.1:1153 TLS_ENABLED=true \
     dnsdist --check-config --config dnsdist.conf'
  ```
- **Reading live state** from a node:
  ```sh
  scripts/console.sh jp-dns1 'showRules()'
  ```
  The key is generated per process start, so there is no constant to paste; the
  script reads it back from the running dnsdist. Do not use `-k <key>` — dnsdist
  2.0 rejects it, and the console client exits 0 either way, so a failure looks
  like success.
  `showRules()` gives per-rule match counts, `showServers()` totals and latency,
  `topClients(n)` the heaviest sources. Capture a baseline *before* changing a
  rule; you cannot get it afterwards.

For anything touching ACME, use Pebble (`tests/e2e/`) rather than Let's
Encrypt. Failed validations against production count against a per-domain weekly
rate limit on a live service, and there is no way to undo one.

Do not deploy to the production nodes without the owner's say-so. They are
listed in `adblock-dns-server/scripts/deploy.sh`, and that script deploys to
**all seven at once**; a canary is a `git pull && ./start.sh` on a single host,
or better, pinning one node to a branch tag (see "Deployment path" above).

**Node-specific cautions:**

- **sg-dns2 serves the maintainer's own laptop.** Do not disrupt it.
- **jp-dns2 is the safe canary for anything image-level** — it is healthy but
  carries almost no traffic. For the same reason it is *useless* for validating
  rate-limit changes; use jp-dns1 for those.


---

## Done

Merged and rolled out to all seven nodes. Kept for the reasoning, which is
the part that is hard to reconstruct.

### 0. Rate limit

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

### 1. Stale base image and unpinned build dependencies

**Where:** `Dockerfile:2`, `:23`, `:29` — all three stages were `alpine:3.19`.

Alpine 3.19 shipped Dec 2023 with security support to **2025-11-01**, so roughly
ten months unpatched — not two years, as an earlier draft of this file claimed.
The running image contained **dnsdist 1.8.2-r1, certbot 2.7.4, gcompat
1.1.0-r4**. PowerDNS secpoll reports 1.8.2 on every production node as
`Security Update Recommended: Unsupported release (EOL)`.

#### Choosing the target: 3.23, not 3.22

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

#### The bump would have silently broken cert reloads

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

#### The Rust side, which was the forced part

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

### 2. console key generated at start instead of committed

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

**Already fixed:** the key used to be passed as `-k <key>`, exposing it via `ps`
to any user on the host. The version bump replaced that with `-C dnsdist.conf`
(`src/tasks/dnsdist.rs:42`), because dnsdist 2.0 no longer accepts `-k` at all.
The argv exposure is gone; **the committed literal is not**, and that is the
remaining problem.

**Scope, established by inspection.** Worth knowing before choosing a fix:

- `controlSocket()` is **TCP-only** in dnsdist 2.0.4 — there is no unix-socket
  form, so the console cannot be moved behind filesystem permissions.
- The default console ACL is `127.0.0.0/8` + `::1/128`, which under
  `network_mode: host` is the *host's* loopback. Without a key, any local user
  can connect.
- `reloadAllCertificates()` is called from exactly one place
  (`src/tasks/dnsdist.rs:47`) and runs roughly **six times a year per node**.
  Cert rotation is the console's only use in this codebase.
- dnsdist 2.0.4 has no file-watch or signal-based cert reload, so removing the
  console means restarting dnsdist to pick up a new cert.

**Option A — keep the console, generate the key at start.** `openssl rand
-base64 32` at container start, passed through the environment; `dnsdist.conf`
already reads env via `os.getenv` (it does so for `PORT`, `BACKEND`,
`TLS_ENABLED`). Add an explicit `setConsoleACL` rather than relying on the
default. Keeps `showRules()`, `showServers()` and `topClients()` — which were
used repeatedly during this review to measure drop rates and identify the
client responsible for 53% of sg-dns1's traffic.

**Option B — delete the console, restart dnsdist on a new cert.** Removes the
attack surface entirely rather than guarding it. Costs the diagnostics above,
and requires `main.rs` to distinguish a deliberate restart from a crash (a
dnsdist exit currently cancels the token).

Restart downtime was **measured**, not estimated — SIGTERM to answering again,
three runs in a container with the real image and config: **353 ms, 374 ms,
42 ms**. The spread suggests it depends on port-rebind timing rather than being
reliably sub-100ms. Note this understates client impact: a UDP query sent during
the gap gets no answer at all, so that client waits out *its own* timeout
(typically 1-5s) before retrying. At jp-dns1's ~86 qps a 400 ms gap touches
roughly 34 queries.

**Option B+ — overlap instead of gapping.** The DNS and DoH listeners already
set `reusePort=true`, so a new dnsdist can bind the same ports before the old
one exits: start it, wait until it answers, then SIGTERM the old. No unanswered
queries. Two prerequisites: `addTLSLocal` does *not* currently pass `reusePort`,
so DoT on :853 would still gap (one-line config change); and both processes
briefly connect to the dnstap socket, which works only because the listener in
item 4 accepts connections repeatedly and handles each independently. The
console port conflict that would normally block this disappears precisely
because B removes the console.

**Status: A shipped**, all seven nodes on one image digest, each with its own
key. `scripts/console.sh <node> '<lua>'` reads the key back from the running
dnsdist, so the console stays as reachable as the literal made it.

B/B+ remain available later — nothing in A blocks
them, and the restart machinery they need is untouched by this change.

**What A turned up.** The console path was exercised by nothing: the reload is
gated on dnsdist already running, and every e2e scenario restarts the container,
so `publish()` always took the "dnsdist not started yet" branch. Adding a test
for it immediately found that **dnsdist's console client exits 0 even when it
refuses to connect.** `run_dnsdist_reload_cert` only checked the exit status, so
a wrong key would have been reported as a successful reload.

There are two distinct rejection messages, both exiting 0, sharing no common
substring — "the currently configured console key is not valid" when the client
has no key, and "likely indicating a key mismatch" when it has the wrong one.
Only the second was found, by a deliberate wrong-key negative control; matching
the first alone would have looked correct and caught nothing.

That bug predates this change and applied to the committed key too. It is the
reason the reload is now checked on output rather than status.

The old key must still be treated as permanently compromised. It is out of the
tree but remains in git history.

### 3. certbot replaced with in-process ACME

This supersedes what were previously items 3 and 4: a renewal error taking the
whole front-end down, and certbot failures being swallowed. Both are gone,
because certbot is gone.

**What was wrong.** `CertbotTask::run` called `.output().await.unwrap()` and
never looked at the returned status. certbot could fail — rate limit, port 80
busy, DNS not resolving — and the code would carry on and copy
`/etc/letsencrypt/live/<domain>/*.pem`, which on a renewal still held the
**previous** certificate. It copied the stale cert, reloaded it, and logged
`DONE`. Renewal would quietly stop and the first symptom, weeks later, would be
DoT and DoH failing for every user at once.

Separately, each of the three error arms in the hourly loop called
`cloned_token.cancel()`, which cancels the whole `TaskTracker` and takes dnsdist
with it. With `restart: always`, a transient renewal problem became a restart
loop of the service answering all production DNS. The first bug masked the
second: because certbot failures were swallowed, the cancel arm almost never
fired. Fixing either alone would have been worse than fixing neither.

**What replaced it.** [`rustls-acme`](https://crates.io/crates/rustls-acme),
in-process, mirroring `bancuh-dns/src/tls.rs`:

- Renewal is **event-driven** at ~2/3 of certificate lifetime, not an hourly
  poll that was a no-op ~1,400 times per certificate
- Individual ACME errors are logged and retried; only the stream *ending* is
  fatal. A failed renewal no longer takes the fleet down
- The Rust HTTPS server takes the ACME resolver directly, so its file-reload
  path is gone entirely — there is no longer a reload to forget to check
- certbot and its Python runtime are out of the image: 126MB → 61MB

dnsdist is a separate process reading PEM files, so it still needs the
credential written out and an explicit reload. That is what
`DnsdistCertCache` does.

**The trap, for anyone touching that cache.** rustls-acme calls `store_cert`
only for a *newly issued* certificate — `process_cert(.., cached: true)` returns
before reaching it. A cache that writes dnsdist's files only in `store_cert`
works on first issuance and on renewal, and silently fails on every restart that
reuses a cached certificate, which is most restarts. Hence both `load_cert` and
`store_cert` publish. `tests/e2e/run.sh` case 2 guards this.

**Testing.** `tests/e2e/run.sh` runs the whole thing against
[Pebble](https://github.com/letsencrypt/pebble), Let's Encrypt's own test CA:
issue, restart with a warm cache, and re-issue, asserting each time on the
certificate **dnsdist actually serves on :853** rather than on the file. Real
Let's Encrypt cannot be used for this — failed validations count against a
per-domain weekly rate limit on a live service.

Note Pebble validates HTTP-01 on port 5002 by default; `tests/e2e/pebble-config.json`
moves it to 80, which is where the service serves challenges because that is the
only port Let's Encrypt uses.

**Still open here:** nothing in the code, but this has not been deployed. Unlike
every other change in this file, it talks to real Let's Encrypt, so a failed
validation burns rate limit against a live domain. Canary on jp-dns2 (idle, most
runway) and confirm a real issuance before touching the rest.

### 4. dnstap read over a socket instead of a file

**What was wrong.** `dnstap` ran as a child appending YAML to `logs.yaml`, which
the supervisor read and truncated once a second:

```rust
let content = tokio::fs::read_to_string("./logs.yaml").await.unwrap_or_default();
let _ = tokio::fs::write("./logs.yaml", "").await;
```

Two separate operations, so anything dnstap appended in the gap was destroyed
unread — silently, with nothing counting it. A read landing mid-document also
produced an unparseable fragment, which was dropped and logged.

That second one was measurable, and measured: **834 lost entries on sg-dns1 in
roughly two hours, about 6.6% of ingest ticks.** The failures were bursty rather
than steady, which is what a race looks like. The first loss leaves no trace at
all, so 834 is a floor, not a total.

**What replaced it.** dnsdist already writes to a unix socket
(`newFrameStreamUnixLogger`); the `dnstap` process was only relaying it to disk.
The supervisor now consumes that socket directly, so there is no file and no
window.

No crate does this. `framestream` 0.2.5 provides only an `EncoderWriter` — it
writes the unidirectional flow and has no reader or control-frame handling.
dnsdist opens with the *bidirectional* handshake, confirmed by probing a live
instance:

```text
00000000 00000022 00000004 00000001 00000016 "protobuf:dnstap.Dnstap"
escape   len 34   READY    CONTENT_TYPE len 22
```

So `src/logs/framestream.rs` implements the receiving side (READY → ACCEPT →
START → data → STOP → FINISH), and `src/logs/dnstap_proto.rs` decodes the five
protobuf fields we use. That is deliberately not `prost`: five fields out of a
large schema did not justify vendoring the .proto, a build.rs, and `protoc` in
the builder image.

The DNS payload arrives as raw wire format, so `query_log.rs` now parses it with
`hickory-proto` instead of slicing dnstap's text rendering on
`";; ANSWER SECTION:"`. Parsing either succeeds or fails; there is no
half-parsed state, which is what made the fragment losses possible.

**Also removed:** the `dnstap` child process, `logs.yaml`, the entire Go build
stage from the Dockerfile, and the one-second polling loop. That loop logged two
lines a second at info and was about 92% of the container's log output —
enough that it actively obstructed debugging the ACME work. Cleanup now runs
once a minute and only expires old entries.

**Verified:** 18 unit tests, including the exact READY bytes a live dnsdist
sends and a fuzz over every truncation of a valid frame. End to end, 250 queries
fired at 8-way parallelism produced 250 answered by dnsdist and **250 captured**
— no loss. Image 61MB → 50MB.
