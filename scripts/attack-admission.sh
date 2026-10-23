#!/usr/bin/env bash
# Attack simulation, part 1: tries to deploy insecure workloads and proves
# that the admission layer (Kyverno + Pod Security Admission) rejects each
# one, while the signed and hardened release is still accepted.
#
#   SIGNED_IMAGE=ghcr.io/...@sha256:...    signed release (must be allowed)
#   UNSIGNED_IMAGE=ghcr.io/...@sha256:...  same repo, never signed (optional)
source "$(dirname "$0")/lib.sh"
require kubectl

NS=aegis
SIGNED_IMAGE="${SIGNED_IMAGE:?set SIGNED_IMAGE to the signed ledger image digest}"
UNSIGNED_IMAGE="${UNSIGNED_IMAGE:-}"
REPORT="$REPORT_DIR/admission.md"
failures=0

printf '| Attempt | Expected | Result | Enforced by |\n|---|---|---|---|\n' > "$REPORT"

# pod NAME IMAGE [key=value ...] renders a pod that passes every control
# unless one of the overrides weakens it.
pod() {
  local name="$1" image="$2"; shift 2
  local automount=false ro=true privileged=false nonroot=true uid=65532 resources=limits sa=default
  for kv in "$@"; do
    case "$kv" in
      automount=*) automount="${kv#*=}" ;;
      sa=*) sa="${kv#*=}" ;;
      ro=*) ro="${kv#*=}" ;;
      privileged=*) privileged="${kv#*=}" ;;
      root=true) nonroot=false; uid=0 ;;
      resources=none) resources=none ;;
    esac
  done
  local res_block="      resources:
        limits: {cpu: 100m, memory: 64Mi}"
  [[ "$resources" == none ]] && res_block=""
  cat <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $name
  namespace: $NS
spec:
  serviceAccountName: $sa
  automountServiceAccountToken: $automount
  securityContext:
    runAsNonRoot: $nonroot
    runAsUser: $uid
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: app
      image: $image
      securityContext:
        allowPrivilegeEscalation: $privileged
        privileged: $privileged
        readOnlyRootFilesystem: $ro
        capabilities: {drop: ["ALL"]}
$res_block
EOF
}

reason_of() {
  # Condense an admission error to its policy name and message.
  tr '\n' ' ' <<<"$1" \
    | grep -oE '(policy [a-z0-9-]+ error: [^;]+|violates PodSecurity "restricted:latest": [^(;]+|denied the request: [^;]{0,160}|error looking up service account [^;]+)' \
    | head -1 | sed -E 's/[[:space:]]+$//'
}

expect_denied() {
  local title="$1" manifest="$2" out
  if out="$(kubectl apply --dry-run=server -f - <<<"$manifest" 2>&1)"; then
    fail "NOT BLOCKED  $title"
    printf '| %s | blocked | **allowed** | - |\n' "$title" >> "$REPORT"
    failures=$((failures + 1))
    return
  fi
  local why; why="$(reason_of "$out")"
  ok "BLOCKED  $title"
  printf '      %s\n' "${why:-$out}"
  printf '| %s | blocked | blocked | %s |\n' "$title" "$(sed 's/|/\\|/g' <<<"${why:-admission webhook}")" >> "$REPORT"
}

expect_allowed() {
  local title="$1" manifest="$2" out
  if out="$(kubectl apply --dry-run=server -f - <<<"$manifest" 2>&1)"; then
    ok "ALLOWED  $title"
    printf '| %s | allowed | allowed | all policies passed |\n' "$title" >> "$REPORT"
  else
    fail "WRONGLY BLOCKED  $title"
    printf '      %s\n' "$out"
    printf '| %s | allowed | **blocked** | - |\n' "$title" >> "$REPORT"
    failures=$((failures + 1))
  fi
}

step "Attack simulation: trying to get insecure workloads into the cluster"

expect_allowed "Signed, attested and hardened release" \
  "$(pod release-check "$SIGNED_IMAGE")"

if [[ -n "$UNSIGNED_IMAGE" ]]; then
  expect_denied "Unsigned image pushed to the trusted registry" \
    "$(pod unsigned-image "$UNSIGNED_IMAGE")"
else
  warn "UNSIGNED_IMAGE not set, skipping the unsigned image test"
fi

expect_denied "Image from Docker Hub" \
  "$(pod dockerhub-image "$DRILL_IMAGE")"
expect_denied "Mutable tag instead of a digest" \
  "$(pod mutable-tag "${SIGNED_IMAGE%@*}:main")"
expect_denied "Privileged container" \
  "$(pod privileged "$SIGNED_IMAGE" privileged=true)"
expect_denied "Container running as root" \
  "$(pod run-as-root "$SIGNED_IMAGE" root=true)"
expect_denied "Writable root filesystem" \
  "$(pod writable-fs "$SIGNED_IMAGE" ro=false)"
expect_denied "No CPU or memory limits" \
  "$(pod no-limits "$SIGNED_IMAGE" resources=none)"
expect_denied "Kubernetes API token mounted" \
  "$(pod api-token "$SIGNED_IMAGE" automount=true)"
expect_denied "Borrowing the incident responder's API identity" \
  "$(pod borrowed-identity "$SIGNED_IMAGE" automount=true sa=aegis-responder)"

target="$(kubectl -n "$NS" get pods -l app.kubernetes.io/name=ledger -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -n "$target" ]]; then
  if out="$(kubectl -n "$NS" debug "$target" --image="$DRILL_IMAGE" --target=ledger -- true 2>&1)"; then
    fail "NOT BLOCKED  kubectl debug into a running pod"
    printf '| kubectl debug into a running pod | blocked | **allowed** | - |\n' >> "$REPORT"
    failures=$((failures + 1))
  else
    ok "BLOCKED  kubectl debug into a running pod"
    printf '      %s\n' "$(reason_of "$out")"
    printf '| kubectl debug into a running pod | blocked | blocked | %s |\n' "$(reason_of "$out")" >> "$REPORT"
  fi
fi

summary "### Attack simulation: admission control" "" "$(cat "$REPORT")" ""
if (( failures > 0 )); then
  die "$failures admission check(s) did not behave as expected"
fi
ok "every insecure workload was rejected and the signed release was accepted"
