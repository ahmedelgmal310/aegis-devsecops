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

## A pod was contained by the incident responder

Containment is automatic (alert `AegisRuntimeThreatContained`). The isolated
pod keeps running, without any network, for the forensic hold (5 minutes in
prod) so it can be inspected live, then the responder deletes it.

```bash
# What happened, and when
kubectl -n aegis-response get configmaps -l aegis.dev/incident
kubectl -n aegis-response get configmap incident-<id> -o jsonpath='{.data.incident\.json}'
kubectl -n aegis-response get configmap incident-<id> -o jsonpath='{.data.falco-alert\.json}'

# The quarantined pod (while the hold lasts) and the audit trail
kubectl get pods -A -l aegis.dev/quarantine=true
kubectl -n <ns> get events --field-selector reason=Quarantined
```

1. Read `incident.json` (rule, playbook decision, detection and containment
   times, node, images) and the alert.
2. During the hold, inspect the pod (`kubectl exec` still works; the network
   does not). Extend the hold by editing the `aegis.dev/terminate-after`
   annotation if you need more time.
3. Find the entry point (application logs in the evidence, ZAP and SAST
   findings), fix it and ship the fix through the pipeline.

## Roll out a new response rule

1. Add the rule to `deploy/response/base/playbook.json` with
   `"mode": "notify"` and ship it through the pipeline.
2. Watch `AegisWouldHaveContained` and the `WouldQuarantine` Events:
   `kubectl get events -A --field-selector reason=WouldQuarantine`.
3. If it only fired on real attacks (or on the drill), change the mode to
   `enforce`. If it fired on legitimate behaviour, narrow its match first.

To dry-run the whole responder, for example on a new cluster, set
`RESPONDER_MODE=notify` on the Deployment: every rule then reports without
acting.

## The responder could not contain a threat

Alert `AegisContainmentFailed` (or `AegisResponseActionErrors`): the attacker
may still have network access.

```bash
kubectl -n aegis-response logs deploy/aegis-responder --tail=100
kubectl auth can-i patch pods -n <ns> --as=system:serviceaccount:aegis-response:aegis-responder
```

Contain manually with the same mechanism the responder uses:
`kubectl -n <ns> label pod <pod> aegis.dev/quarantine=true` (the
`aegis-quarantine` NetworkPolicy isolates it), then remove the selector labels
so the Deployment replaces it. A namespace the responder should protect needs
the `aegis-quarantine` NetworkPolicy, the `aegis-responder` Role and an entry
in `deploy/response/base/playbook.json`.

## Falco alerts are dropped as unauthenticated

Alert `AegisAlertsDropped{reason="unauthenticated"}` means something other
than Falco is calling the responder, or Falco's client certificate no longer
matches the responder's CA. Re-run `scripts/cluster-up.sh` to reissue both
from the same CA, then restart the responder and Falco.

## Roll back a release

Revert the promote commit on `main`. Argo CD syncs the previous digest, which
is still signed and still passes admission.
