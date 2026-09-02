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
#
# Usage: tests/e2e/run.sh [--keep]
set -uo pipefail

cd "$(dirname "$0")"
PROJECT=dnsdist-acme-e2e
COMPOSE="docker compose -p $PROJECT"
KEEP="${1:-}"

pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }

cleanup() {
  if [ "$KEEP" != "--keep" ]; then
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1
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

echo "== bringing up pebble + dnsdist-acme (clean state) =="
$COMPOSE down -v --remove-orphans >/dev/null 2>&1
$COMPOSE up -d >/dev/null 2>&1 || { echo "compose up failed"; exit 1; }

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
echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
