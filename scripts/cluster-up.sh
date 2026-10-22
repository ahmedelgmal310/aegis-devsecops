#!/usr/bin/env bash
# Creates a kind cluster with the full Aegis security stack:
# Sealed Secrets, Kyverno + policies, Falco and Argo CD.
source "$(dirname "$0")/lib.sh"
require kind kubectl helm curl sha256sum

CLUSTER_NAME="${CLUSTER_NAME:-aegis}"
INSTALL_FALCO="${INSTALL_FALCO:-true}"
SEALED_SECRETS_KEY_FILE="${SEALED_SECRETS_KEY_FILE:-$HOME/.aegis/sealed-secrets.key}"
SEALED_SECRETS_CERT_FILE="$ROOT_DIR/deploy/sealed-secrets/sealing-cert.pem"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# preload IMAGE...: pull on the host with retries and load into the kind node.
# Public registries occasionally throttle anonymous pulls from CI runners.
preload() {
  for img in "$@"; do
    for attempt in 1 2 3 4; do
      docker pull -q "$img" >/dev/null 2>&1 && break
      warn "pull failed for $img (attempt $attempt), retrying"
      sleep $((attempt * 10))
    done
    kind load docker-image "$img" --name "$CLUSTER_NAME" >/dev/null 2>&1 \
      || warn "could not preload $img; the node will pull it itself"
  done
}

step "Kubernetes cluster ($KIND_NODE_IMAGE)"
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  ok "kind cluster '$CLUSTER_NAME' already exists"
else
  kind create cluster --name "$CLUSTER_NAME" --config "$ROOT_DIR/deploy/kind/cluster.yaml" \
    --image "$KIND_NODE_IMAGE" --wait 180s
fi
kubectl config use-context "kind-$CLUSTER_NAME" >/dev/null

step "Sealed Secrets $SEALED_SECRETS_VERSION (bring-your-own sealing key)"
if [[ -f "$SEALED_SECRETS_KEY_FILE" ]]; then
  kubectl -n kube-system create secret tls aegis-sealing-key \
      --cert="$SEALED_SECRETS_CERT_FILE" --key="$SEALED_SECRETS_KEY_FILE" --dry-run=client -o yaml \
    | kubectl label --local -f - sealedsecrets.bitnami.com/sealed-secrets-key=active -o yaml \
    | kubectl apply -f - >/dev/null
  ok "sealing key loaded (the private key never leaves this machine or the CI secret store)"
else
  warn "no sealing key at $SEALED_SECRETS_KEY_FILE; committed SealedSecrets will not decrypt"
fi
fetch_verified \
  "https://github.com/bitnami-labs/sealed-secrets/releases/download/$SEALED_SECRETS_VERSION/controller.yaml" \
  "$SEALED_SECRETS_CONTROLLER_SHA256" "$tmp/sealed-secrets.yaml"
kubectl apply -f "$tmp/sealed-secrets.yaml" >/dev/null
kubectl -n kube-system rollout status deploy/sealed-secrets-controller --timeout=180s

step "Kyverno (chart $KYVERNO_CHART_VERSION) and admission policies"
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update >/dev/null
helm upgrade --install kyverno kyverno/kyverno --namespace kyverno --create-namespace \
  --version "$KYVERNO_CHART_VERSION" --wait --timeout 10m >/dev/null
ok "kyverno installed"
# The admission webhook needs a few seconds to get its TLS certificate.
for attempt in $(seq 1 30); do
  kubectl apply -f "$ROOT_DIR/deploy/policies/" >/dev/null 2>&1 && break
  (( attempt == 30 )) && die "kyverno admission webhook never became ready"
  sleep 5
done
for p in $(kubectl get validatingpolicies.policies.kyverno.io -o name) $(kubectl get imagevalidatingpolicies.policies.kyverno.io -o name); do
  kubectl wait "$p" --for=jsonpath='{.status.conditionStatus.ready}'=true --timeout=180s >/dev/null
  ok "policy ready: ${p#*/}"
done

if [[ "$INSTALL_FALCO" == "true" ]]; then
  step "Falco (chart $FALCO_CHART_VERSION) with Aegis runtime rules"
  helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null
  helm upgrade --install falco falcosecurity/falco --namespace falco --create-namespace \
    --version "$FALCO_CHART_VERSION" -f "$ROOT_DIR/deploy/falco/values.yaml" \
    --set-file 'customRules.aegis-rules\.yaml'="$ROOT_DIR/deploy/falco/aegis-rules.yaml" \
    --wait --timeout 10m >/dev/null
  ok "falco running with $(grep -c '^- rule:' "$ROOT_DIR/deploy/falco/aegis-rules.yaml") custom rules"
fi

step "Argo CD $ARGOCD_VERSION"
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f - >/dev/null
fetch_verified \
  "https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/install.yaml" \
  "$ARGOCD_INSTALL_SHA256" "$tmp/argocd.yaml"
# shellcheck disable=SC2046
preload $(grep -oE 'image: [^ ]+' "$tmp/argocd.yaml" | awk '{print $2}' | grep -v dex | sort -u)
kubectl apply -n argocd --server-side --force-conflicts -f "$tmp/argocd.yaml" >/dev/null
for workload in deploy/argocd-redis deploy/argocd-repo-server statefulset/argocd-application-controller; do
  kubectl -n argocd rollout status "$workload" --timeout=300s
done
kubectl apply -f "$ROOT_DIR/deploy/argocd/project.yaml" >/dev/null
ok "argo cd ready, project 'aegis' restricted to this repository and namespace"

summary "### Platform" "" \
  "| Component | Version |" "|---|---|" \
  "| Kubernetes (kind) | ${KIND_NODE_IMAGE%@*} |" \
  "| Kyverno | chart $KYVERNO_CHART_VERSION |" \
  "| Falco | chart $FALCO_CHART_VERSION |" \
  "| Argo CD | $ARGOCD_VERSION |" \
  "| Sealed Secrets | $SEALED_SECRETS_VERSION |" ""
