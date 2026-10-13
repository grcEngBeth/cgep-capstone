#!/usr/bin/env bash
# scripts/policy-gate.sh
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
# Requires a saved tfplan inside the workspace (terraform plan -out=tfplan).
# Fails closed: any policy violation, or any conftest error, returns non-zero.
# Prints each violation (control ID + remediation) so a developer reading the
# failed PR knows exactly what to fix.
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/policy-gate"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

terraform -chdir="$WORKSPACE" show -json tfplan > "$WORKSPACE/plan.json"

set +e
conftest test --policy "$POLICY_DIR" --all-namespaces --output=json "$WORKSPACE/plan.json" > "$EVIDENCE_DIR/conftest-results.json"
STATUS=$?
set -e

# Coverage line, so an empty pass (zero policies evaluated) is visible.
python3 -c 'import json,sys
d=json.load(open(sys.argv[1]))
print("policy-gate: checks passed:", sum(x.get("successes",0) for x in d), "| violations:", sum(len(x.get("failures") or []) for x in d))' "$EVIDENCE_DIR/conftest-results.json" || true

# Print every violation message (these carry the SOC 2 control ID and the fix).
python3 -c 'import json,sys,os
gha = os.environ.get("GITHUB_ACTIONS") == "true"
for x in json.load(open(sys.argv[1])):
    for f in (x.get("failures") or []):
        msg = f.get("msg", "")
        print("VIOLATION: " + msg)
        if gha:
            print("::error title=Policy gate violation::" + msg)' "$EVIDENCE_DIR/conftest-results.json" || true

if [[ $STATUS -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
  echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $STATUS
