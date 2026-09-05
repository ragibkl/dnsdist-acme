#!/usr/bin/env bash
# End-to-end ACME test against Pebble.
#
# Covers the three paths that matter, because each has a distinct failure mode
# and none of them could be exercised while certbot was in the picture:
#
#   1. first issuance      -- store_cert writes the PEM files, dnsdist serves them
#   2. restart, warm cache -- load_cert must ALSO write the files. rustls-acme
#                             does not call store_cert for a cached certificate,
#                             so a cache that only wrote on store would leave
#                             dnsdist's files stale on every restart
#   3. re-issuance         -- a genuinely new certificate reaches dnsdist
#   4. console reachable   -- the cert reload path works
#
# Step 4 exists because nothing else exercises the control socket. The reload is
# gated on dnsdist already running, and every scenario above restarts the
# container, so publish() always takes the "dnsdist not started yet" branch. In
# production the console is used roughly six times a year, at renewal. A broken
# key would therefore stay silent for ~60 days and then fail as an expiry
# outage, with a valid certificate sitting unread on disk.
#
# Usage: tests/e2e/run.sh [--keep]
set -uo pipefail

cd "$(dirname "$0")"
PROJECT=dnsdist-acme-e2e
# The image is pinned through a generated override file rather than the
# ${DNSDIST_ACME_IMAGE} interpolation alone. Compose interpolates in the client,
# so any setup where the docker CLI does not inherit this shell's environment
# -- distrobox/host-exec, sudo without -E, some CI shells -- silently resolves
# the default instead and tests a stale image. A file crosses those boundaries.
OVERRIDE=docker-compose.image.yml
COMPOSE="docker compose -p $PROJECT -f docker-compose.yml -f $OVERRIDE"
KEEP="${1:-}"

pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }

cleanup() {
  if [ "$KEEP" != "--keep" ]; then
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1
    rm -f "$OVERRIDE"
  fi
}
trap cleanup EXIT

# Reads the certificate dnsdist is actually serving on :853. Deliberately not
# the file on disk -- "the file changed" and "dnsdist serves the new cert" are
# different claims, and only the second one matters to a client.
served_cert_fingerprint() {
  docker run --rm --network "${PROJECT}_default" alpine:3.23 sh -c '
    apk add --no-cache openssl >/dev/null 2>&1
    openssl s_client -connect dnsdist.test:853 -servername dnsdist.test </dev/null 2>/dev/null \
      | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2'
}

# rustls-acme builds the CSR with an empty distinguished name, so the domain
# lives in the SAN and NOT in the subject CN. Asserting on the subject silently
# checks nothing.
served_cert_identity() {
  docker run --rm --network "${PROJECT}_default" alpine:3.23 sh -c '
    apk add --no-cache openssl >/dev/null 2>&1
    openssl s_client -connect dnsdist.test:853 -servername dnsdist.test </dev/null 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName -issuer 2>/dev/null | tr "\n" " "'
}

cached_writes() {
  $COMPOSE logs dnsdist-acme 2>/dev/null | grep -c "wrote cached certificate"
}

wait_for_cert_files() {
  for _ in $(seq 1 "${1:-60}"); do
    if $COMPOSE exec -T dnsdist-acme sh -c '[ -s ./certs/fullchain.pem ] && [ -s ./certs/privkey.pem ]' 2>/dev/null; then
      return 0
    fi
    sleep 2
  done
  return 1
}

IMAGE_UNDER_TEST="${DNSDIST_ACME_IMAGE:-dnsdist-acme:acme}"
expected_id=$(docker image inspect -f '{{.Id}}' "$IMAGE_UNDER_TEST" 2>/dev/null)
if [ -z "$expected_id" ]; then
  echo "image $IMAGE_UNDER_TEST not found locally -- build it first"
  exit 1
fi

cat > "$OVERRIDE" <<YAML
services:
  dnsdist-acme:
    image: $IMAGE_UNDER_TEST
YAML

echo "== bringing up pebble + dnsdist-acme (clean state) =="
echo "   image under test: $IMAGE_UNDER_TEST (${expected_id:7:12})"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1
$COMPOSE down -v --remove-orphans >/dev/null 2>&1
$COMPOSE up -d >/dev/null 2>&1 || { echo "compose up failed"; exit 1; }

# Asserted rather than assumed. A stale local image will happily pass most of
# this suite -- the old one even carries a literal console key, so the console
# checks below would authenticate and prove nothing.
running_id=$(docker inspect -f '{{.Image}}' "$($COMPOSE ps -q dnsdist-acme)" 2>/dev/null)
if [ "$running_id" = "$expected_id" ]; then
  ok "container is running the image under test"
else
  bad "container is NOT running $IMAGE_UNDER_TEST (running ${running_id:7:12}, expected ${expected_id:7:12})"
  echo "  refusing to report on a different image than the one requested"
  exit 1
fi

echo
echo "== 1. first issuance =="
if wait_for_cert_files 60; then ok "certificate files written"; else
  bad "certificate files never appeared"
  $COMPOSE logs dnsdist-acme | tail -30
  exit 1
fi

$COMPOSE logs dnsdist-acme 2>/dev/null | grep -q "wrote new certificate" \
  && ok "issued a new certificate (store_cert path)" \
  || bad "no 'wrote new certificate' in logs"

identity=$(served_cert_identity)
echo "$identity" | grep -q "DNS:dnsdist.test" \
  && ok "dnsdist serves a certificate for dnsdist.test on :853" \
  || bad "unexpected certificate on :853 -- $identity"

echo "$identity" | grep -qi "pebble" \
  && ok "certificate was issued by Pebble" \
  || bad "issuer is not Pebble -- $identity"

first=$(served_cert_fingerprint)
echo "        fingerprint: ${first:0:32}..."

echo
echo "== 2. restart with a warm cache =="
# The regression guard. rustls-acme returns early for a cached certificate and
# never calls store_cert, so this is the path that silently breaks.
before=$(cached_writes)
# Delete the published files so their reappearance proves load_cert wrote them.
$COMPOSE exec -T dnsdist-acme sh -c 'rm -f ./certs/fullchain.pem ./certs/privkey.pem' 2>/dev/null
$COMPOSE restart dnsdist-acme >/dev/null 2>&1

if wait_for_cert_files 45; then
  ok "files rewritten from cache after restart (load_cert path)"
else
  bad "files NOT rewritten from cache -- dnsdist would start with no certificate"
fi

# Counting rather than time-windowing: a fixed --since window is a race.
[ "$(cached_writes)" -gt "$before" ] \
  && ok "used the cached certificate rather than re-issuing" \
  || bad "expected a cached-certificate write in the logs"

same=$(served_cert_fingerprint)
[ -n "$same" ] && [ "$same" = "$first" ] \
  && ok "same certificate still served after restart" \
  || bad "certificate changed unexpectedly across a restart"

echo
echo "== 3. re-issuance after the cache is cleared =="
# Remove the published files too. Otherwise wait_for_cert_files returns on the
# stale ones and the served certificate gets read before issuance finishes.
$COMPOSE exec -T dnsdist-acme sh -c 'rm -rf /acme-cache/* ./certs/fullchain.pem ./certs/privkey.pem' 2>/dev/null
$COMPOSE restart dnsdist-acme >/dev/null 2>&1

if wait_for_cert_files 60; then ok "certificate files written again"; else
  bad "no certificate after clearing the cache"
fi

# dnsdist needs a moment to pick the new file up on start.
second=""
for _ in $(seq 1 20); do
  second=$(served_cert_fingerprint)
  [ -n "$second" ] && [ "$second" != "$first" ] && break
  sleep 3
done
if [ -n "$second" ] && [ "$second" != "$first" ]; then
  ok "a genuinely new certificate reached dnsdist"
  echo "        fingerprint: ${second:0:32}..."
else
  bad "dnsdist is still serving the old certificate -- reload did not take effect"
fi

echo
echo "== 4. dnsdist console, the certificate reload path =="
# The key never enters the container's own environment -- it is generated in the
# supervisor and handed to children via Command::env() -- so a plain `exec` here
# cannot authenticate. Read it back from the dnsdist child and supply it the way
# run_dnsdist_reload_cert does, which is what exercises the getenv/setKey/ACL
# path in dnsdist.conf.
dnsdist_key() {
  $COMPOSE exec -T dnsdist-acme sh -c \
    'tr "\0" "\n" < /proc/$(pgrep -n dnsdist)/environ | grep "^CONSOLE_KEY=" | cut -d= -f2-' 2>/dev/null \
    | tr -d "[:space:]"
}

key_a=$(dnsdist_key)
console=$($COMPOSE exec -T -e "CONSOLE_KEY=$key_a" dnsdist-acme sh -c \
  'dnsdist -C dnsdist.conf -c 127.0.0.1 -e "showVersion()"' 2>&1)

# Asserted on output, not exit status: the console client exits 0 even when it
# rejects the key, which is why run_dnsdist_reload_cert inspects output too.
echo "$console" | grep -qi "not valid\|key mismatch\|closed by the server\|Unable to connect\|refused" \
  && bad "console rejected the generated key: $(echo "$console" | tail -1)" \
  || ok "console accepted the generated key"

echo "$console" | grep -qi "dnsdist" \
  && ok "console returned a version string" \
  || bad "console produced no version output: $(echo "$console" | tail -2 | tr '\n' ' ')"

# The key is handed to children via Command::env(), so it is deliberately absent
# from the supervisor's own environment -- nothing that can read /proc/1/environ
# learns it, and it is not inherited by any future child by accident.
pid1_key=$($COMPOSE exec -T dnsdist-acme sh -c 'tr "\0" "\n" < /proc/1/environ | grep -c "^CONSOLE_KEY=" || true' 2>/dev/null | tr -d "[:space:]")
[ "$pid1_key" = "0" ] \
  && ok "key is absent from the supervisor's own environment" \
  || bad "CONSOLE_KEY leaked into the supervisor environment"

# The property the whole change rests on: a fresh key per start, not a constant
# baked into the image.
[ ${#key_a} -ge 40 ] \
  && ok "dnsdist received a 32-byte key through its environment" \
  || bad "no usable CONSOLE_KEY in the dnsdist environment (got ${#key_a} chars)"

$COMPOSE restart dnsdist-acme >/dev/null 2>&1
wait_for_cert_files 45 >/dev/null 2>&1
key_b=""
for _ in $(seq 1 20); do
  key_b=$(dnsdist_key)
  [ ${#key_b} -ge 40 ] && break
  sleep 2
done

if [ ${#key_b} -ge 40 ] && [ "$key_a" != "$key_b" ]; then
  ok "a different key after restart (generated per start, not baked in)"
elif [ "$key_a" = "$key_b" ]; then
  bad "same key across restarts -- it is a constant, not generated"
else
  bad "could not read the key after restart"
fi

grep -rq "setKey('" ../../dnsdist.conf \
  && bad "dnsdist.conf still contains a literal key" \
  || ok "dnsdist.conf holds no literal key"

echo
echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
