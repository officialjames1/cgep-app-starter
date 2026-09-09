#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id>
set -euo pipefail

RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true

VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

# Guard: fail clearly (not with a cryptic ls error) if nothing was pulled down,
# and fail if more than one bundle matched instead of silently taking the first.
MATCHES=$(ls evidence-*.tar.gz 2>/dev/null | wc -l | tr -d ' ')
if [[ "$MATCHES" -eq 0 ]]; then
  echo "FAIL: no bundle found for run ${RUN_ID} in ${VAULT}/${PREFIX}" >&2
  exit 1
elif [[ "$MATCHES" -gt 1 ]]; then
  echo "FAIL: expected exactly 1 bundle, found ${MATCHES} in ${VAULT}/${PREFIX}" >&2
  exit 1
fi
BUNDLE=$(ls evidence-*.tar.gz)

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$($SHASUM "${BUNDLE}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }

# 2. Authenticity + timestamp
# Identity is pinned to this exact repo + workflow so a signature from any
# other GitHub Actions run (even a legitimate one elsewhere) is rejected.
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity-regexp "^https://github.com/officialjames1/cgep-labs/\.github/workflows/grc-gate\.yml@.*$" \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"

# 3. Preservation
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# NOTE: this is a lexicographic string comparison, not a real date comparison.
# It only works because both timestamps are fixed-width ISO 8601
# (YYYY-MM-DDTHH:MM:SSZ), where lexicographic order == chronological order.
# Do not reformat either timestamp without revisiting this check.
[[ "$RETAIN_UNTIL" > "$NOW" ]] || { echo "FAIL: retention expired"; exit 1; }

echo "CHAIN INTACT for run ${RUN_ID}"
