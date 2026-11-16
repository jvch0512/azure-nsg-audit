#!/usr/bin/env bash
cd "$(dirname "$0")/.." || exit 2
BIN=bin/azure-nsg-audit
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
ok() { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
exp() { local name=$1 want=$2; shift 2; "$BIN" "$@" >/dev/null 2>&1; local got=$?; [ "$got" = "$want" ] && ok "$name" || bad "$name (got $got, want $want)"; }
exp "default exit 0" 0 examples
exp "fail-on high" 1 examples --fail-on high
exp "fail-on critical" 1 examples --fail-on critical
exp "clean file passes" 0 examples/hardened.json --fail-on medium
exp "missing path" 2 "$T/none"
exp "bad flag" 2 --bogus
exp "no args" 2
exp "bad fail-on" 2 examples --fail-on low
exp "two paths" 2 examples examples
"$BIN" examples --tsv | head -1 | grep -q '^# 3 files, 9 findings$' && ok "tsv header" || bad "tsv header"
"$BIN" examples --tsv | sed -n 2p | awk -F'\t' 'NF==4{exit 0} {exit 1}' && ok "tsv columns" || bad "tsv columns"
"$BIN" examples | head -1 | grep -q '^3 files, 9 findings$' && ok "human header" || bad "human header"
printf '{"name":"n","securityRules":[{"name":"r","priority":1,"direction":"Inbound","access":"Allow","sourceAddressPrefix":"*","destinationPortRange":"22","description":"d"}]}' > "$T/one.json"
"$BIN" "$T/one.json" --tsv | grep -q $'\tNSG001\tone.json#n/r\t' && ok "single file label" || bad "single file label"
head -c 2000 /dev/urandom > "$T/bin.json"
"$BIN" "$T/bin.json" >/dev/null 2>&1; [ $? -le 1 ] && ok "binary input survives" || bad "binary input"
exit $fail
