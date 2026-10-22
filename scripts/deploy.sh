#!/usr/bin/env bash
# Deploys the ledger through Argo CD and waits until it is Synced and Healthy.
#
#   deploy.sh                          # prod overlay on main (GitOps)
#   deploy.sh <git-sha> <image@digest> # CI: commit under test, fresh digest
source "$(dirname "$0")/lib.sh"
require kubectl

REVISION="${1:-main}"
IMAGE="${2:-}"
OVERLAY="${OVERLAY:-deploy/k8s/overlays/prod}"
REPO_URL="${REPO_URL:-https://github.com/ahmedelgmal310/aegis-devsecops.git}"
TIMEOUT="${TIMEOUT:-420}"

images_block=""
if [[ -n "$IMAGE" ]]; then
  images_block="    kustomize:
      images:
        - $IMAGE"
fi

step "Argo CD: syncing $OVERLAY @ $REVISION"
kubectl apply -f - >/dev/null <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ledger
  namespace: argocd
spec:
  project: aegis
  source:
    repoURL: $REPO_URL
    targetRevision: $REVISION
    path: $OVERLAY
$images_block
  destination:
    server: https://kubernetes.default.svc
    namespace: aegis
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - ServerSideApply=true
    retry:
      limit: 5
      backoff:
        duration: 10s
        factor: 2
        maxDuration: 2m
EOF

deadline=$((SECONDS + TIMEOUT))
while true; do
  sync="$(kubectl -n argocd get application ledger -o jsonpath='{.status.sync.status}' 2>/dev/null || true)"
  health="$(kubectl -n argocd get application ledger -o jsonpath='{.status.health.status}' 2>/dev/null || true)"
  if [[ "$sync" == "Synced" && "$health" == "Healthy" ]]; then
    break
  fi
  if (( SECONDS > deadline )); then
    fail "application not healthy after ${TIMEOUT}s (sync=$sync health=$health)"
    kubectl -n argocd get application ledger -o jsonpath='{range .status.conditions[*]}{.type}: {.message}{"\n"}{end}' || true
    kubectl -n aegis get deploy,rs,pods,sealedsecrets,secrets -o wide || true
    kubectl -n aegis get events --sort-by=.lastTimestamp | tail -25 || true
    exit 1
  fi
  sleep 5
done

ok "ledger is Synced and Healthy"
kubectl -n argocd get application ledger
kubectl -n aegis get deploy,pods -o wide
summary "### GitOps deployment" "" \
  "Argo CD synced \`$OVERLAY\` at \`$REVISION\` and the ledger is **Synced / Healthy**." ""
