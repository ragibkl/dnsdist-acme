#!/usr/bin/env sh
# Run a dnsdist console command against a node.
#
#   scripts/console.sh jp-dns1 'showServers()'
#   scripts/console.sh jp-dns1 'topClients(5)'
#   scripts/console.sh local   'showRules()'
#
# The console key is generated per process start and passed to dnsdist through
# its environment, so unlike the old committed literal there is no constant to
# paste. This reads the key back from the running dnsdist and supplies it the
# same way the supervisor's reload path does.
#
# Requires docker access on the target, which is the point: console access now
# needs root on the box rather than the ability to read GitHub. Anyone with that
# can already read the TLS private keys off disk, so this grants no new
# privilege -- it only restores the convenience the published key used to give.
set -eu

usage() {
    echo "usage: $0 <node|local> '<lua expression>'" >&2
    echo "example: $0 jp-dns1 'showServers()'" >&2
    exit 2
}

[ $# -eq 2 ] || usage
target=$1
expr=$2

# Runs on the node itself. Kept as one self-contained script so it can be piped
# straight into `ssh sh -s`.
remote_script() {
    cat <<'INNER'
set -eu
CID=$(docker ps -q -f name=dnsdist | head -1)
if [ -z "$CID" ]; then
    echo "no running dnsdist container found" >&2
    exit 1
fi

# Absent on images predating the generated key, where dnsdist.conf still holds
# the literal. Leaving CONSOLE_KEY unset there is correct: the config supplies
# its own, so this script works across a partly rolled-out fleet.
KEY=$(docker exec "$CID" sh -c \
    'tr "\0" "\n" < /proc/$(pgrep -n dnsdist)/environ | grep "^CONSOLE_KEY=" | cut -d= -f2-' \
    2>/dev/null || true)

if [ -n "$KEY" ]; then
    set -- docker exec -e "CONSOLE_KEY=$KEY" "$CID"
else
    echo "note: no CONSOLE_KEY in the dnsdist environment; falling back to the" >&2
    echo "      key in dnsdist.conf (pre-rollout image)" >&2
    set -- docker exec "$CID"
fi

# EXPR is passed as a positional argument, never interpolated into the quoted
# string: a Lua expression containing double quotes -- print("x"), or any rule
# taking a string -- would otherwise terminate the quoting and be parsed as
# shell words.
out=$("$@" sh -c 'dnsdist -C dnsdist.conf -c 127.0.0.1 -e "$1"' _ "$EXPR" 2>&1) || true
printf '%s\n' "$out"

# The console client exits 0 even when it refuses to run the command, so the
# only reliable signal is the output. These are the two rejections dnsdist 2.0.4
# produces; they share no common substring.
if printf '%s' "$out" | grep -qi \
    "console key is not valid\|key mismatch\|closed by the server\|Unable to connect\|refused"; then
    echo "console refused the command (see above)" >&2
    exit 1
fi
INNER
}

# Single-quote for a POSIX shell: wrap in quotes and escape any embedded ones.
# Not printf '%q' -- that is a bashism and this script declares sh.
sq() {
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

payload="EXPR=$(sq "$expr")
$(remote_script)"

if [ "$target" = "local" ]; then
    printf '%s' "$payload" | sh -s
else
    printf '%s' "$payload" | ssh -o BatchMode=yes -o ConnectTimeout=15 \
        "root@${target}.bancuh.com" sh -s
fi
