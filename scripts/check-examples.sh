#!/usr/bin/env bash
# Proves the guardrails work end to end on real Terraform files:
#
#   1. examples/secure   must produce no findings at all.
#   2. examples/insecure must trigger exactly the rules listed in
#      examples/insecure/expected-rules.txt - no more, no fewer.
#
# Requires: conftest, jq.
set -euo pipefail

cd "$(dirname "$0")/.."

run() {
  # Conftest exits non-zero when it finds problems; we inspect the JSON instead.
  conftest test --parser hcl2 --policy policy --output json "$1" || true
}

echo "Checking examples/secure (expecting no findings)..."
secure=$(run examples/secure/main.tf)
secure_count=$(jq '[.[] | (.failures // []) + (.warnings // []) | .[]] | length' <<<"$secure")
if [ "$secure_count" -ne 0 ]; then
  echo "FAIL: the secure example produced ${secure_count} finding(s):" >&2
  jq -r '.[] | (.failures // []) + (.warnings // []) | .[].msg' <<<"$secure" >&2
  exit 1
fi
echo "  ok"

echo "Checking examples/insecure (expecting every rule to fire)..."
insecure=$(run examples/insecure/main.tf)
actual=$(jq -r '[.[] | (.failures // [])[] | .metadata.rule] | unique | .[]' <<<"$insecure")
expected=$(sort -u examples/insecure/expected-rules.txt)

if [ "$actual" != "$expected" ]; then
  echo "FAIL: the rules that fired do not match expected-rules.txt." >&2
  echo "--- expected" >&2
  echo "$expected" >&2
  echo "--- actual" >&2
  echo "$actual" >&2
  exit 1
fi
echo "  ok: $(wc -l <<<"$actual" | tr -d ' ') rules fired, as expected"
