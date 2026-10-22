# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them
privately through GitHub's
[private vulnerability reporting](https://github.com/ahmedelgmal310/aegis-devsecops/security/advisories/new).

You can expect an acknowledgement within 3 working days and a status update
within 10 working days.

## Supported versions

Only the latest image promoted to `deploy/k8s/overlays/prod` is supported.
Every release is signed; verify it before running it:

```bash
cosign verify ghcr.io/ahmedelgmal310/aegis-ledger@sha256:<digest> \
  --certificate-identity https://github.com/ahmedelgmal310/aegis-devsecops/.github/workflows/devsecops.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
