#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
# Requires a saved tfplan inside the workspace (from terraform plan -out=tfplan).
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/lab-3-4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

# Write plan.json next to tfplan. Use -chdir so a relative WORKSPACE path
# doesn't get doubled after a cd (a common bash footgun).
terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"

EXIT=0
{
  echo "["
  FIRST=1
  # AWS namespaces only. Including a GCP namespace here would "pass" with zero
  # coverage on an AWS plan — the exact empty-pass lesson from Step 3.
  #
  # gap05_aws and gap06_aws are intentionally excluded from this gate: their
  # remediation (Lambda in a VPC with a NAT Gateway) was deliberately deferred
  # given cost scope — see main.tf header and WRITEUP.md. Their .rego files
  # and tests still exist and pass under `opa test`, proving detection works;
  # they're just not blocking merges while the gap is knowingly open.
  #
  # gap08_waf_aws is also excluded: AWS WAFv2 does not support direct
  # association with HTTP APIs, so this check would never be satisfiable
  # without an architecture change out of scope for this capstone.
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws \
            compliance.gap01_aws compliance.gap02_aws compliance.gap03_aws compliance.gap04_aws \
            compliance.gap07_aws compliance.gap08_aws ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    # Capture JSON even when conftest exits non-zero; use that exit code for the gate.
    set +e
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json")
    STATUS=$?
    set -e
    [[ $STATUS -eq 0 ]] || EXIT=1
    printf '%s' "$OUT"
  done
  echo
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT
