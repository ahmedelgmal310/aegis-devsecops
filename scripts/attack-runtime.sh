#!/usr/bin/env bash
# Attack simulation, part 2: behaves like an attacker who already has code
# execution inside a container, and proves that Falco detects each step.
#
# The drill runs in a separate, non-enforced namespace (aegis-drill) because
# the real workload is distroless and has no shell to abuse.
source "$(dirname "$0")/lib.sh"
require kubectl

NS=aegis-drill
REPORT="$REPORT_DIR/runtime.md"

step "Attack simulation: post-exploitation inside a container"
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
  labels:
    pod-security.kubernetes.io/enforce: baseline
---
apiVersion: v1
kind: Pod
metadata:
  name: compromised-app
  namespace: $NS
spec:
  automountServiceAccountToken: false
  containers:
    - name: app
      image: $DRILL_IMAGE
      command: ["sleep", "3600"]
      resources:
        limits: {cpu: 100m, memory: 64Mi}
EOF
kubectl -n "$NS" wait pod/compromised-app --for=condition=Ready --timeout=180s >/dev/null
ok "drill pod running"

since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
attack() {
  printf '  %s$%s %s\n' "$YELLOW" "$RESET" "$1"
  kubectl -n "$NS" exec compromised-app -- sh -c "$1" >/dev/null 2>&1 || true
}
attack 'id && whoami && hostname'
attack 'cat /etc/shadow'
attack 'wget -q -T 3 -O /dev/null http://example.com'

step "Falco alerts"
expected=("Aegis Shell Spawned in Workload" "Aegis Discovery Tool Executed" "Aegis Credential File Read")
found=()
deadline=$((SECONDS + 90))
while (( SECONDS < deadline )); do
  logs="$(kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco --since-time="$since" --tail=-1 2>/dev/null || true)"
  found=()
  for rule in "${expected[@]}"; do
    grep -q "\"rule\":\"$rule\"" <<<"$logs" && found+=("$rule")
  done
  (( ${#found[@]} == ${#expected[@]} )) && break
  sleep 5
done

printf '| Falco rule | Priority | Example output |\n|---|---|---|\n' > "$REPORT"
for rule in "${expected[@]}"; do
  line="$(grep -m1 "\"rule\":\"$rule\"" <<<"$logs" || true)"
  if [[ -n "$line" ]]; then
    priority="$(grep -oE '"priority":"[A-Za-z]+"' <<<"$line" | cut -d'"' -f4)"
    output="$(grep -oE '"output":"[^"]+"' <<<"$line" | cut -d'"' -f4 | cut -c1-150)"
    ok "DETECTED  [$priority] $rule"
    printf '      %s\n' "$output"
    printf '| %s | %s | `%s` |\n' "$rule" "$priority" "$output" >> "$REPORT"
  else
    fail "MISSED  $rule"
    printf '| %s | - | **not detected** |\n' "$rule" >> "$REPORT"
  fi
done

total="$(grep -c '"rule":' <<<"$logs" || true)"
ok "$total Falco alerts raised during the drill"
kubectl delete namespace "$NS" --wait=false >/dev/null

summary "### Attack simulation: runtime detection" "" "$(cat "$REPORT")" ""
(( ${#found[@]} == ${#expected[@]} )) || die "Falco missed $(( ${#expected[@]} - ${#found[@]} )) expected alert(s)"
ok "every attacker action was detected by Falco"
