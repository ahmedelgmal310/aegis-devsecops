# Runbook

## Use your own sealing key

The SealedSecret in `deploy/k8s/base/sealed-secret.yaml` was encrypted with
`deploy/sealed-secrets/sealing-cert.pem`. To run the project with your own key:

```bash
mkdir -p ~/.aegis
openssl req -x509 -days 3650 -nodes -newkey rsa:4096 \
  -keyout ~/.aegis/sealed-secrets.key -out ~/.aegis/sealed-secrets.crt \
  -subj "/CN=sealed-secret/O=aegis-devsecops"
cp ~/.aegis/sealed-secrets.crt deploy/sealed-secrets/sealing-cert.pem

kubectl create secret generic ledger-api -n aegis \
    --from-literal=token="$(openssl rand -hex 32)" --dry-run=client -o yaml \
  | kubeseal --cert deploy/sealed-secrets/sealing-cert.pem --scope strict -o yaml \
  > deploy/k8s/base/sealed-secret.yaml

# CI needs the private key to decrypt it in the ephemeral cluster.
gh secret set SEALED_SECRETS_KEY < ~/.aegis/sealed-secrets.key
```

`scripts/cluster-up.sh` loads `~/.aegis/sealed-secrets.key` (or
`SEALED_SECRETS_KEY_FILE`) into the controller before it starts.

## Rotate the API token

Re-seal a new token with the command above, commit, and push. Argo CD syncs the
new SealedSecret; restart the deployment so the pods read the new file:

```bash
kubectl -n aegis rollout restart deploy/ledger
```

## A pod is rejected at admission

```bash
kubectl -n aegis get events --sort-by=.lastTimestamp | tail
kubectl get policyreports -A
```

The message names the policy and the failed rule. Typical causes: the image is
not signed by the pipeline on `main`, it is referenced by tag instead of
digest, or the manifest weakened a security setting. Fix the source, never the
policy.

## Falco raised an alert

1. Identify the pod from the alert fields (`k8s.pod.name`, `k8s.ns.name`).
2. Isolate it: `kubectl -n <ns> label pod <pod> quarantine=true` and apply a
   deny-all NetworkPolicy selecting `quarantine=true`.
3. Preserve evidence before deleting: `kubectl -n <ns> logs <pod> > evidence.log`.
4. Delete the pod; the Deployment recreates it from the signed image.
5. Find the entry point (application logs, ZAP and SAST findings) and fix it.

## Roll back a release

Revert the promote commit on `main`. Argo CD syncs the previous digest, which
is still signed and still passes admission.
