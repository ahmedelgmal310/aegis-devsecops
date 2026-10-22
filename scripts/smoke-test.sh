#!/usr/bin/env bash
# Functional smoke test against the deployed ledger. The API token is read
# from the Secret that the Sealed Secrets controller decrypted in-cluster,
# which also proves the secret pipeline works end to end.
source "$(dirname "$0")/lib.sh"
require kubectl curl

PORT="${PORT:-18080}"
step "Smoke test"
kubectl -n aegis port-forward svc/ledger "$PORT:80" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 1; done

token="$(kubectl -n aegis get secret ledger-api -o jsonpath='{.data.token}' | base64 -d)"
[[ -n "$token" ]] || die "ledger-api secret is empty: the SealedSecret was not decrypted"
ok "SealedSecret decrypted in-cluster into Secret aegis/ledger-api"

base="http://127.0.0.1:$PORT"
code="$(curl -s -o /dev/null -w '%{http_code}' "$base/api/v1/transactions")"
[[ "$code" == 401 ]] || die "expected 401 without a token, got $code"
ok "unauthenticated request rejected (401)"

created="$(curl -fs -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"amount":125000,"currency":"EGP","description":"Smoke test payment"}' "$base/api/v1/transactions")"
id="$(grep -oE 'txn_[0-9a-f]{32}' <<<"$created" | head -1)"
[[ -n "$id" ]] || die "create failed: $created"
ok "transaction created: $id"

curl -fs -H "Authorization: Bearer $token" "$base/api/v1/transactions/$id" | grep -q "Smoke test payment" \
  || die "could not read back $id"
ok "transaction read back"

code="$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"amount":-1,"currency":"BTC","description":"<script>alert(1)</script>"}' "$base/api/v1/transactions")"
[[ "$code" == 422 ]] || die "expected 422 for invalid input, got $code"
ok "malicious input rejected (422)"

version="$(curl -fs "$base/version")"
ok "running build: $version"
summary "### Smoke test" "" "Sealed secret decrypted, auth enforced (401), CRUD works, invalid input rejected (422). Build: \`$version\`" ""
