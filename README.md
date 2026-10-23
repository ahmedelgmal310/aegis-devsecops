# Aegis: an end-to-end DevSecOps platform

[![DevSecOps Pipeline](https://github.com/ahmedelgmal310/aegis-devsecops/actions/workflows/devsecops.yml/badge.svg)](https://github.com/ahmedelgmal310/aegis-devsecops/actions/workflows/devsecops.yml)
[![CodeQL](https://github.com/ahmedelgmal310/aegis-devsecops/actions/workflows/codeql.yml/badge.svg)](https://github.com/ahmedelgmal310/aegis-devsecops/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ahmedelgmal310/aegis-devsecops/badge)](https://scorecard.dev/viewer/?uri=github.com/ahmedelgmal310/aegis-devsecops)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Aegis secures the whole path from a `git push` to a running pod. Code is
scanned before it is built, every image is signed and carries a signed SBOM
and vulnerability report, the cluster refuses anything that cannot prove where
it came from, and Falco watches what happens after deployment.

The pipeline does not just scan. On every release it **attacks its own
cluster** and fails if any attack gets through. And when an attack does reach
a running container, the cluster **fights back on its own**: the compromised
pod is isolated within milliseconds of detection, its evidence is preserved,
and a clean replacement takes over.

## How it works

```mermaid
flowchart LR
    subgraph CI["GitHub Actions: DevSecOps pipeline"]
        direction TB
        A["Secrets<br/>Gitleaks"] --> G{{"All gates<br/>green?"}}
        B["SAST<br/>Semgrep, gosec, CodeQL"] --> G
        C["SCA<br/>govulncheck, Trivy"] --> G
        D["IaC<br/>Checkov, Hadolint,<br/>kubeconform, Terraform"] --> G
        E["Policy tests<br/>Kyverno CLI, Falco"] --> G
        F["Unit tests, race,<br/>fuzzing, 80% gate"] --> G
        G --> H["Build multi-arch image"]
        H --> I["Trivy image gate"]
        I --> J["SBOM (Syft, SPDX)"]
        J --> K["Sign + attest<br/>cosign keyless"]
        K --> L["SLSA provenance"]
    end
    L --> M["E2E on Kubernetes"]
    M --> N["Promote digest<br/>to prod overlay"]
    N --> O["Argo CD syncs prod"]
```

```mermaid
flowchart LR
    git[(Git: prod overlay)] --> argo[Argo CD]
    argo --> api[Kubernetes API]
    api --> psa[Pod Security<br/>restricted]
    api --> kyv[Kyverno]
    kyv -->|"signature, SBOM,<br/>vuln attestation"| rekor[(Sigstore Rekor)]
    kyv --> pod[ledger pod<br/>distroless, non-root,<br/>read-only, no egress]
    ss[Sealed Secrets] -->|decrypts token| pod
    falco[Falco eBPF] -.runtime detection.-> pod
    falco -->|alerts over mTLS| resp[aegis-responder]
    resp -->|"quarantine, replace,<br/>evidence, terminate"| api
    resp -.metrics.-> prom[Prometheus<br/>alerting rules]
```

## Security controls

| Layer | Control | Tooling |
|---|---|---|
| Code | Secret scanning on the full git history | Gitleaks |
| Code | Static analysis, results in GitHub code scanning | Semgrep, gosec, CodeQL (`security-extended`) |
| Dependencies | Reachable vulnerabilities, dependency and license scan, weekly updates | govulncheck, Trivy, Dependabot |
| Infrastructure | Kubernetes, Dockerfile, Terraform and workflow misconfigurations | Checkov, Hadolint, kubeconform, actionlint |
| Policy | Admission policies unit-tested like code | Kyverno CLI, `falco -V` |
| Build | Distroless, non-root, multi-arch image; build fails on fixable HIGH/CRITICAL CVEs | Docker Buildx, Trivy |
| Supply chain | Keyless signature, signed SPDX SBOM, signed vulnerability report, SLSA provenance | cosign, Syft, Sigstore, GitHub attestations |
| Admission | Only images signed by this pipeline on `main`, with an SBOM and no CRITICAL CVEs, may run | Kyverno `ImageValidatingPolicy` |
| Admission | Trusted registry only, digest pinning, read-only rootfs, limits, no API token, no debug containers | Kyverno `ValidatingPolicy` |
| Workload | Pod Security `restricted`, seccomp, all capabilities dropped, UID 65532 | Kubernetes PSA |
| Network | Default deny, the ledger has zero egress | NetworkPolicy |
| Secrets | Encrypted in git, decrypted only inside the cluster, mounted as a file | Sealed Secrets (bring-your-own key) |
| Delivery | Git is the source of truth, drift is reverted automatically | Argo CD (self-heal, prune) |
| Runtime | Shells, discovery tools and credential reads are detected | Falco (modern eBPF) + custom rules |
| Response | Compromised pods are isolated, preserved as evidence, replaced and terminated automatically | aegis-responder (Go), NetworkPolicy, Argo CD |
| Observability | Every incident is a metric and a Prometheus alert; alert rules are unit-tested | Prometheus, promtool |
| Application | Auth, validation, rate limiting, strict headers, verified by DAST | Go, OWASP ZAP |
| Pipeline | Actions pinned to SHAs, images pinned to digests, least-privilege tokens | Scorecard, CODEOWNERS |
| Cloud | ECR with KMS and immutable tags, GitHub OIDC role, no static keys | Terraform, scanned by Checkov |

The full threat model, mapped to STRIDE and the OWASP Top 10 CI/CD Security
Risks, is in [docs/threat-model.md](docs/threat-model.md).

## The pipeline attacks its own cluster

After deploying through Argo CD, the end-to-end stage runs two attack
simulations against the live cluster.

**Admission control** ([`scripts/attack-admission.sh`](scripts/attack-admission.sh)):
an unsigned image pushed to the trusted registry, an image from Docker Hub, a
mutable tag, a privileged container, a root container, a writable filesystem,
missing limits, a mounted API token and `kubectl debug`. Each one must be
rejected, and the signed release must still be accepted.

**Runtime detection** ([`scripts/attack-runtime.sh`](scripts/attack-runtime.sh)):
acts like an attacker with code execution in a container (spawns a shell, runs
discovery tools, reads `/etc/shadow`, tries to reach the internet). Falco must
raise an alert for every step.

Then OWASP ZAP scans the running service, and only if everything passed is the
image digest promoted to the prod overlay that Argo CD deploys.

## The cluster fights back: automated incident response

Detection alone leaves an attacker with a working shell until someone reads
the alert. Aegis closes that gap with **aegis-responder**, a small Go service
([`app/internal/responder`](app/internal/responder)) that turns Falco alerts
into action, driven by a declarative playbook
([`deploy/response/base/playbook.json`](deploy/response/base/playbook.json)):

```mermaid
flowchart LR
    atk([Attacker in a container]) -->|shell, cat /etc/shadow| pod[Pod]
    falco[Falco eBPF] -.detects.-> pod
    falco -->|"alert (mutual TLS)"| resp[aegis-responder]
    resp -->|1. quarantine| np[NetworkPolicy:<br/>no traffic]
    resp -->|2. evidence| cm[(Immutable ConfigMap:<br/>alert, pod, logs)]
    np --> rs[3. Deployment starts<br/>a clean replacement]
    resp -->|4. after forensic hold| del[Terminate]
    resp -.-> prom[Prometheus alert]
```

1. **Quarantine.** The pod gets `aegis.dev/quarantine=true` and loses the
   labels its ReplicaSet selects on. A NetworkPolicy cuts all of its traffic,
   the Service stops routing to it, and the Deployment starts a clean pod.
2. **Evidence.** The alert, the full pod object and recent logs are written to
   an immutable ConfigMap. The responder may create evidence but never read,
   edit or delete it.
3. **Terminate.** The isolated pod stays alive for a forensic hold (live
   inspection without network), then a stateless reconcile loop deletes it,
   with a UID precondition so it never touches a newer pod.
4. **Observe.** Every decision is a metric; `AegisRuntimeThreatContained`,
   `AegisContainmentFailed` and `AegisResponderDown` are Prometheus alerts
   unit-tested with `promtool`.

The responder is treated as a high-value target itself: it only accepts
alerts from Falco's client certificate (mutual TLS), only from the `falco`
namespace, only for allowlisted namespaces and only when the alert's
container ID matches the live pod. It has namespaced Roles only (no
ClusterRole, no Secrets, no exec), its image is signed and verified at
admission like the workload, and the admission drill proves no other pod can
borrow its API identity. Reconnaissance (`whoami`, `wget`) is recorded, not
contained, so noise never kills healthy pods.

The runtime drill ([`scripts/attack-runtime.sh`](scripts/attack-runtime.sh))
proves the whole loop on every release: detect, contain, recover, preserve,
clean up and alert.

## Results from the latest release

| Stage | Result |
|---|---|
| Secret scanning | 15 commits scanned, no leaks |
| SAST | Semgrep: 111 rules, 0 findings · gosec: 0 issues · CodeQL: clean |
| SCA | govulncheck: no vulnerabilities · Trivy: 0 HIGH/CRITICAL |
| IaC | Checkov: 586 passed, 0 failed (Kubernetes, Dockerfile, Terraform, Actions) |
| Policy tests | Kyverno CLI · Falco rules validated · promtool: 6 alerting rules unit-tested |
| Unit tests | 88.9% coverage (gate 80%), race detector and fuzzing |
| Images | Ledger and responder: distroless, amd64 + arm64, 0 vulnerabilities, signed SBOMs |
| Supply chain | Signature, SBOM and vulnerability attestations verified with cosign; SLSA provenance verified with `gh attestation verify` |
| Admission attacks | 10/10 blocked, signed release accepted |
| Runtime attacks | 3/3 detected by Falco |
| Automated response | Pod isolated **11 ms** after detection, clean replacement Ready, evidence preserved (immutable), pod terminated after the hold, Prometheus alert fired |
| DAST | OWASP ZAP: 67 passed, 0 warnings, 0 failures |
| Delivery | Argo CD Synced / Healthy, digest promoted to prod |

## Run it yourself

Requirements: Docker, [kind](https://kind.sigs.k8s.io/), kubectl, Helm 4 and
about 6 GB of free memory.

```bash
git clone https://github.com/ahmedelgmal310/aegis-devsecops.git
cd aegis-devsecops
make demo      # cluster + platform, GitOps deploy, smoke test, attacks + response, DAST
make down      # delete the cluster
```

`make help` lists the individual steps. The committed SealedSecret can only be
decrypted with the project's private sealing key. Without it, generate your own
key pair and re-seal the token as described in [docs/runbook.md](docs/runbook.md).

### Verify a release without trusting me

```bash
IMAGE=ghcr.io/ahmedelgmal310/aegis-ledger@sha256:<digest>   # see deploy/k8s/overlays/prod
ID=https://github.com/ahmedelgmal310/aegis-devsecops/.github/workflows/devsecops.yml@refs/heads/main

cosign verify "$IMAGE" --certificate-identity "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
cosign verify-attestation "$IMAGE" --type spdxjson --certificate-identity "$ID" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify "oci://$IMAGE" --repo ahmedelgmal310/aegis-devsecops
```

## Repository layout

```
app/                    Go services (ledger API, incident responder), Dockerfile, tests, fuzz test
deploy/k8s/             Kustomize base + overlays (ci, prod)
deploy/policies/        Kyverno policies and their unit tests
deploy/falco/           Falco values and custom runtime rules
deploy/response/        Incident responder: playbook, RBAC, NetworkPolicies, overlays
deploy/monitoring/      Prometheus values, alerting rules and their unit tests
deploy/argocd/          Argo CD project and application
deploy/dast/            OWASP ZAP rule thresholds
infra/terraform/aws/    ECR, KMS and GitHub OIDC role
scripts/                Cluster bootstrap, deploy, smoke test, attack simulations, DAST
docs/                   Threat model and runbook
.github/                Pipeline, CodeQL, Scorecard, Dependabot, CODEOWNERS
```

## Tech stack

Go 1.27 · Docker Buildx · GitHub Actions · Kubernetes 1.36 (kind) · Kyverno 1.19 ·
Falco 0.45 · Prometheus 3.15 · Argo CD 3.5 · Sealed Secrets · Sigstore cosign 3 · Syft · Trivy ·
Semgrep · CodeQL · gosec · govulncheck · Gitleaks · Checkov · Hadolint ·
OWASP ZAP · Terraform · OpenSSF Scorecard

## License

[MIT](LICENSE)
