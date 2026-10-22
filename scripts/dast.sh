#!/usr/bin/env bash
# DAST: OWASP ZAP baseline scan against the ledger running in the cluster.
source "$(dirname "$0")/lib.sh"
require kubectl docker curl

PORT="${PORT:-18081}"
step "DAST: OWASP ZAP baseline scan"

# On Linux ZAP shares the host network; Docker Desktop reaches the host
# through host.docker.internal instead.
if [[ "$(uname -s)" == "Linux" ]]; then
  bind=127.0.0.1; target="http://127.0.0.1:$PORT"; net=(--network host)
else
  bind=0.0.0.0; target="http://host.docker.internal:$PORT"; net=()
fi

kubectl -n aegis port-forward --address "$bind" svc/ledger "$PORT:80" >/dev/null 2>&1 &
pf=$!
trap 'kill $pf 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 1; done

cp "$ROOT_DIR/deploy/dast/zap-rules.tsv" "$REPORT_DIR/zap-rules.tsv"
chmod -R a+rwX "$REPORT_DIR"

set +e
docker run --rm "${net[@]}" -v "$REPORT_DIR:/zap/wrk:rw" "$ZAP_IMAGE" \
  zap-baseline.py -t "$target" -c zap-rules.tsv -m 2 \
  -r zap-report.html -w zap-report.md -J zap-report.json
rc=$?
set -e

# zap-baseline exit codes: 0 = clean, 1 = FAIL rules hit, 2 = warnings only.
case "$rc" in
  0) ok "no alerts above the configured thresholds" ;;
  2) warn "warnings reported, see reports/zap-report.html" ;;
  *) die "ZAP found issues configured as FAIL (exit $rc), see reports/zap-report.html" ;;
esac
summary "### DAST (OWASP ZAP baseline)" "" "Exit code \`$rc\` (0 = no alerts). Full report in the \`security-reports\` artifact." ""
