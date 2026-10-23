#!/usr/bin/env bash
# Attack simulation, part 2: behaves like an attacker who already has code
# execution inside a container, proves that Falco detects each step, and that
# the incident responder contains the compromised pod automatically:
#
#   detect   Falco raises an alert for every attacker action
#   contain  the pod is cut off the network and detached from its Deployment
#   recover  the Deployment replaces it with a clean pod that keeps working
#   preserve evidence is stored in an immutable ConfigMap before deletion
#   clean up the isolated pod is terminated after the forensic hold
#   observe  Prometheus records the incident and fires the alert
#
# The drill runs in a separate, non-enforced namespace (aegis-drill) because
# the real workload is distroless and has no shell to abuse.
source "$(dirname "$0")/lib.sh"
require kubectl jq

NS=aegis-drill
APP=compromised-app
PROBE_URL="http://prometheus-server.monitoring.svc/-/healthy"
REPORT="$REPORT_DIR/runtime.md"
RESPONSE_REPORT="$REPORT_DIR/response.md"
failures=0

step "Attack simulation: post-exploitation inside a container"
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NS
  labels:
    pod-security.kubernetes.io/enforce: baseline
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: $APP
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels: {app: $APP}
  template:
    metadata:
      labels: {app: $APP}
    spec:
      automountServiceAccountToken: false
      terminationGracePeriodSeconds: 0
      containers:
        - name: app
          image: $DRILL_IMAGE
          command: ["sleep", "3600"]
          resources:
            limits: {cpu: 100m, memory: 64Mi}
---
# Same response setup as the aegis namespace: quarantined pods lose all
# traffic, and the responder may act on pods here.
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: aegis-quarantine
  namespace: $NS
spec:
  podSelector:
    matchLabels:
      aegis.dev/quarantine: "true"
  policyTypes: ["Ingress", "Egress"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: aegis-responder
  namespace: $NS
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get, list, patch, delete]
  - apiGroups: [""]
    resources: [pods/log]
    verbs: [get]
  - apiGroups: [apps]
    resources: [replicasets]
    verbs: [get]
  - apiGroups: [""]
    resources: [events]
    verbs: [create]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: aegis-responder
  namespace: $NS
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: aegis-responder
subjects:
  - kind: ServiceAccount
    name: aegis-responder
    namespace: aegis-response
EOF
kubectl -n "$NS" rollout status "deploy/$APP" --timeout=180s >/dev/null
victim="$(kubectl -n "$NS" get pods -l "app=$APP" -o jsonpath='{.items[0].metadata.name}')"
ok "drill pod running: $victim"

# Before the attack the pod can reach the rest of the cluster, so a failure
# after containment really is the quarantine and not a broken network.
if kubectl -n "$NS" exec "$victim" -- wget -q -T 5 -O /dev/null "$PROBE_URL" >/dev/null 2>&1; then
  ok "baseline: the pod reaches in-cluster services"
else
  die "baseline failed: the drill pod cannot reach $PROBE_URL, the isolation test would be meaningless"
fi

# Prometheus must have scraped the responder's zero-valued counters before
# the attack, otherwise the first incident is a new series, not an increase.
scraped() {
  kubectl get --raw "/api/v1/namespaces/monitoring/services/prometheus-server:80/proxy/api/v1/query?query=count(aegis_responder_events_total)"     | jq -e '.data.result[0].value[1] | tonumber > 0' >/dev/null
}
for _ in $(seq 1 45); do scraped 2>/dev/null && break; sleep 2; done
scraped 2>/dev/null && ok "prometheus is scraping the responder" || warn "responder metrics not scraped yet"

since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
attack_started=$SECONDS
attack() {
  printf '  %s$%s %s\n' "$YELLOW" "$RESET" "$1"
  kubectl -n "$NS" exec "$victim" -- sh -c "$1" >/dev/null 2>&1 || true
}
attack 'id && whoami && hostname'
attack 'cat /etc/shadow'
attack 'wget -q -T 3 -O /dev/null http://example.com'

# ---------------------------------------------------------------- detect
step "Detect: Falco alerts"
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
    failures=$((failures + 1))
  fi
done
total="$(grep -c '"rule":' <<<"$logs" || true)"
ok "$total Falco alerts raised during the drill"
summary "### Attack simulation: runtime detection" "" "$(cat "$REPORT")" ""

# ---------------------------------------------------------------- respond
printf '| Response step | Expected | Result |\n|---|---|---|\n' > "$RESPONSE_REPORT"
check() { # check TITLE EXPECTED RESULT PASSED
  if [[ "$4" == true ]]; then
    ok "$1: $3"
  else
    fail "$1: $3"
    failures=$((failures + 1))
  fi
  printf '| %s | %s | %s |\n' "$1" "$2" "$3" >> "$RESPONSE_REPORT"
}
# wait_for SECONDS COMMAND...: retry until the command succeeds.
wait_for() {
  local until=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    (( SECONDS > until )) && return 1
    sleep 2
  done
}
pod_json() { kubectl -n "$NS" get pod "$victim" -o json 2>/dev/null; }
quarantined() { [[ "$(pod_json | jq -r '.metadata.labels["aegis.dev/quarantine"] // ""')" == "true" ]]; }

step "Contain: automated incident response"
if wait_for 60 quarantined; then
  incident="$(pod_json | jq -r '.metadata.annotations["aegis.dev/incident"]')"
  rule="$(pod_json | jq -r '.metadata.annotations["aegis.dev/falco-rule"]')"
  check "Pod quarantined" "within seconds" "incident \`$incident\` ($rule), $((SECONDS - attack_started))s after the first command" true
else
  check "Pod quarantined" "within seconds" "**not quarantined**" false
  kubectl -n aegis-response logs deploy/aegis-responder --tail=50 || true
  summary "### Automated incident response" "" "$(cat "$RESPONSE_REPORT")" ""
  die "the responder did not contain the compromised pod"
fi

owners="$(pod_json | jq -r '.metadata.ownerReferences // [] | length')"
check "Detached from its Deployment" "no owner" "$owners owner references, selector labels removed" "$([[ $owners == 0 ]] && echo true || echo false)"

replacement_ready() {
  kubectl -n "$NS" get pods -l "app=$APP" -o json \
    | jq -e --arg v "$victim" '[.items[] | select(.metadata.name != $v)
        | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))] | length > 0'
}
if wait_for 90 replacement_ready; then
  replacement="$(kubectl -n "$NS" get pods -l "app=$APP" -o jsonpath='{.items[0].metadata.name}')"
  check "Clean replacement running" "Deployment self-heals" "\`$replacement\` Ready" true
else
  check "Clean replacement running" "Deployment self-heals" "**no replacement**" false
fi

if kubectl -n "$NS" exec "$victim" -- wget -q -T 5 -O /dev/null "$PROBE_URL" >/dev/null 2>&1; then
  check "Quarantined pod isolated" "network blocked" "**still reaches the cluster**" false
else
  check "Quarantined pod isolated" "network blocked" "all traffic blocked (NetworkPolicy)" true
fi
if [[ -n "${replacement:-}" ]] && kubectl -n "$NS" exec "$replacement" -- wget -q -T 5 -O /dev/null "$PROBE_URL" >/dev/null 2>&1; then
  check "Replacement unaffected" "network works" "reaches in-cluster services" true
else
  check "Replacement unaffected" "network works" "**blocked**" false
fi

step "Preserve: forensic evidence"
evidence="incident-$incident"
if wait_for 30 kubectl -n aegis-response get configmap "$evidence"; then
  cm="$(kubectl -n aegis-response get configmap "$evidence" -o json)"
  immutable="$(jq -r '.immutable' <<<"$cm")"
  files="$(jq -r '.data | keys | join(", ")' <<<"$cm")"
  containment="$(jq -r '.data["incident.json"] | fromjson | .containmentSec' <<<"$cm")"
  containment_ms="$(awk -v s="$containment" 'BEGIN { printf "%d", s * 1000 }')"
  check "Evidence preserved" "immutable ConfigMap" "\`$evidence\` (immutable=$immutable): $files" "$([[ $immutable == true ]] && echo true || echo false)"
  check "Detection to containment" "under 5 s" "${containment_ms} ms (Falco event time to network isolation)" \
    "$(awk -v s="$containment" 'BEGIN { print (s < 5) ? "true" : "false" }')"
  jq -r '.data["incident.json"]' <<<"$cm" > "$REPORT_DIR/incident.json"
else
  check "Evidence preserved" "immutable ConfigMap" "**missing**" false
fi

reason="$(kubectl -n "$NS" get events --field-selector "involvedObject.name=$victim,reason=Quarantined" \
  -o jsonpath='{.items[0].message}' 2>/dev/null || true)"
check "Kubernetes Event on the pod" "audit trail" "$([[ -n $reason ]] && echo "\`Quarantined\`: ${reason:0:90}..." || echo "**missing**")" \
  "$([[ -n $reason ]] && echo true || echo false)"

step "Clean up: termination after the forensic hold"
gone() { ! kubectl -n "$NS" get pod "$victim" >/dev/null 2>&1; }
hold="$(kubectl -n aegis-response get deploy aegis-responder \
  -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="RESPONDER_HOLD_SECONDS")].value}')"
if wait_for $(( ${hold:-300} + 60 )) gone; then
  check "Quarantined pod terminated" "after ${hold:-300} s hold" "deleted by the responder" true
else
  check "Quarantined pod terminated" "after ${hold:-300} s hold" "**still running**" false
fi

step "Observe: Prometheus"
prom() { # prom PATH: GET from the Prometheus API through the API server proxy
  kubectl get --raw "/api/v1/namespaces/monitoring/services/prometheus-server:80/proxy$1"
}
contained_metric() {
  prom "/api/v1/query?query=sum(aegis_responder_events_total%7Bdecision%3D%22contained%22%7D)" \
    | jq -e '.data.result[0].value[1] | tonumber >= 1'
}
alert_firing() {
  prom "/api/v1/alerts" | jq -e '.data.alerts[] | select(.labels.alertname == "AegisRuntimeThreatContained" and .state == "firing")'
}
if wait_for 120 contained_metric; then
  check "Incident recorded in Prometheus" "metric" "\`aegis_responder_events_total{decision=\"contained\"}\` >= 1" true
else
  check "Incident recorded in Prometheus" "metric" "**no data**" false
fi
if wait_for 120 alert_firing; then
  check "Alert fired" "AegisRuntimeThreatContained" "firing (severity critical)" true
else
  check "Alert fired" "AegisRuntimeThreatContained" "**not firing**" false
fi

kubectl delete namespace "$NS" --wait=false >/dev/null
summary "### Automated incident response" "" "$(cat "$RESPONSE_REPORT")" ""
(( failures == 0 )) || die "$failures runtime detection or response check(s) failed"
ok "every attacker action was detected, and the compromised pod was contained, replaced and cleaned up"
