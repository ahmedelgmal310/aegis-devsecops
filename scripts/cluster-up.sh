#!/usr/bin/env bash
# Creates a kind cluster with the full Aegis security stack:
# Sealed Secrets, Kyverno + policies, Falco (wired to the incident responder
# over mutual TLS), Prometheus and Argo CD.
source "$(dirname "$0")/lib.sh"
require kind kubectl helm curl sha256sum openssl

CLUSTER_NAME="${CLUSTER_NAME:-aegis}"
INSTALL_FALCO="${INSTALL_FALCO:-true}"
SEALED_SECRETS_KEY_FILE="${SEALED_SECRETS_KEY_FILE:-$HOME/.aegis/sealed-secrets.key}"
SEALED_SECRETS_CERT_FILE="$ROOT_DIR/deploy/sealed-secrets/sealing-cert.pem"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

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

step "Mutual TLS between Falco and the incident responder"
# A throwaway CA per cluster: the responder only accepts alerts from a client
# certificate it signed (CN=falco), and Falco only sends alerts to a server
# presenting a certificate it signed. In production cert-manager would issue
# and rotate these; nothing here is ever committed.
if kubectl -n aegis-response get secret aegis-responder-tls >/dev/null 2>&1 \
   && kubectl -n falco get secret falco-responder-client >/dev/null 2>&1; then
  ok "certificates already issued"
else
  pki="$tmp/pki"; mkdir -p "$pki"
  svc=aegis-responder.aegis-response.svc
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 \
    -subj "/CN=aegis-response-ca" -keyout "$pki/ca.key" -out "$pki/ca.crt" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  issue() { # issue NAME CN EXTENSIONS
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$2" \
      -keyout "$pki/$1.key" -out "$pki/$1.csr" 2>/dev/null
    printf '%s\n' "$3" > "$pki/$1.ext"
    openssl x509 -req -in "$pki/$1.csr" -CA "$pki/ca.crt" -CAkey "$pki/ca.key" -CAcreateserial \
      -days 30 -extfile "$pki/$1.ext" -out "$pki/$1.crt" 2>/dev/null
  }
  issue server aegis-responder "subjectAltName=DNS:$svc,DNS:$svc.cluster.local
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature"
  issue client falco "extendedKeyUsage=clientAuth
keyUsage=critical,digitalSignature"
  for ns in aegis-response falco; do
    kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  done
  kubectl -n aegis-response create secret generic aegis-responder-tls \
    --from-file=tls.crt="$pki/server.crt" --from-file=tls.key="$pki/server.key" --from-file=ca.crt="$pki/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n falco create secret generic falco-responder-client \
    --from-file=client.crt="$pki/client.crt" --from-file=client.key="$pki/client.key" --from-file=ca.crt="$pki/ca.crt" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  ok "CA, responder server certificate and Falco client certificate issued (P-256, 30 days)"
fi

if [[ "$INSTALL_FALCO" == "true" ]]; then
  step "Falco (chart $FALCO_CHART_VERSION) with Aegis runtime rules"
  helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update >/dev/null
  helm upgrade --install falco falcosecurity/falco --namespace falco --create-namespace \
    --version "$FALCO_CHART_VERSION" -f "$ROOT_DIR/deploy/falco/values.yaml" \
    --set-file 'customRules.aegis-rules\.yaml'="$ROOT_DIR/deploy/falco/aegis-rules.yaml" \
    --wait --timeout 10m >/dev/null
  ok "falco running with $(grep -c '^- rule:' "$ROOT_DIR/deploy/falco/aegis-rules.yaml") custom rules"
fi

step "Prometheus (chart $PROMETHEUS_CHART_VERSION) with Aegis alerting rules"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts --force-update >/dev/null
{
  echo "serverFiles:"
  echo "  alerting_rules.yml:"
  sed 's/^/    /' "$ROOT_DIR/deploy/monitoring/aegis-rules.yaml"
} > "$tmp/prometheus-rules.yaml"
helm upgrade --install prometheus prometheus-community/prometheus --namespace monitoring --create-namespace \
  --version "$PROMETHEUS_CHART_VERSION" -f "$ROOT_DIR/deploy/monitoring/values.yaml" -f "$tmp/prometheus-rules.yaml" \
  --wait --timeout 10m >/dev/null
ok "prometheus running with $(grep -c '^      - alert:' "$ROOT_DIR/deploy/monitoring/aegis-rules.yaml") Aegis alerting rules"

step "Argo CD $ARGOCD_VERSION"
kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f - >/dev/null
fetch_verified \
  "https://raw.githubusercontent.com/argoproj/argo-cd/$ARGOCD_VERSION/manifests/install.yaml" \
  "$ARGOCD_INSTALL_SHA256" "$tmp/argocd.yaml"
sed -i "s|image: public.ecr.aws/docker/library/redis:8.2.3-alpine|image: $ARGOCD_REDIS_IMAGE|" "$tmp/argocd.yaml"
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
  "| Falco | chart $FALCO_CHART_VERSION, alerts to the responder over mTLS |" \
  "| Prometheus | chart $PROMETHEUS_CHART_VERSION |" \
  "| Argo CD | $ARGOCD_VERSION |" \
  "| Sealed Secrets | $SEALED_SECRETS_VERSION |" ""
