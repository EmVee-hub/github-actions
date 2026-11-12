#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "${GITHUB_ACTION_PATH}/../.." && pwd)"
: "${INPUT_IMAGE:?Image must be specified}"
: "${INPUT_VEX_PATH:?VEX path must be specified}"
: "${GITHUB_WORKSPACE:=$PWD}"
: "${GRYPE_BIN:=grype}"
: "${REPORT_DIR:=security-reports}"
: "${INPUT_MODE:=shadow}"
: "${INPUT_EXPOSURE:=unknown}"

if [[ "$INPUT_MODE" != shadow && "$INPUT_MODE" != enforce ]]; then
  echo "ERROR: mode must be shadow or enforce" >&2; exit 2
fi
if [[ "$INPUT_EXPOSURE" != public && "$INPUT_EXPOSURE" != internal && "$INPUT_EXPOSURE" != unknown ]]; then
  echo "ERROR: exposure must be public, internal, or unknown" >&2; exit 2
fi
if [[ "$INPUT_VEX_PATH" = /* ]]; then
  VEX="$INPUT_VEX_PATH"
else
  VEX="$GITHUB_WORKSPACE/$INPUT_VEX_PATH"
fi
if [[ "$REPORT_DIR" != /* ]]; then
  REPORT_DIR="$GITHUB_WORKSPACE/$REPORT_DIR"
fi
mkdir -p "$REPORT_DIR"

# Fail closed on invalid/missing VEX. This is a minimum sanity check, not
# full schema or security approval of VEX statements.
python3 "$ROOT/scripts/validate_vex.py" "$VEX"

if ! command -v "$GRYPE_BIN" >/dev/null 2>&1 && [[ ! -x "$GRYPE_BIN" ]]; then
  echo "ERROR: Grype executable missing: $GRYPE_BIN" >&2; exit 2
fi
"$GRYPE_BIN" version
# Updating the vulnerability DB is required before computing KEV-negative values.
# A DB update/network failure fails this action even in shadow mode.
"$GRYPE_BIN" db update

# Use the explicit action config so project-level Grype ignore rules cannot
# silently suppress findings. Only the explicit project VEX may suppress.
"$GRYPE_BIN" "$INPUT_IMAGE" \
  --config "$GITHUB_ACTION_PATH/grype.yaml" \
  --by-cve \
  --vex "$VEX" \
  --output json > "$REPORT_DIR/grype.json"

# Fetch CISA-published SSVC data for distinct unsuppressed CVEs.
python3 "$ROOT/scripts/fetch_vulnrichment.py" \
  --input "$REPORT_DIR/grype.json" \
  --output "$REPORT_DIR/vulnrichment.json"

DECISION=$(python3 "$ROOT/scripts/evaluate.py" \
  --vulnrichment "$REPORT_DIR/vulnrichment.json" \
  --input "$REPORT_DIR/grype.json" \
  --vex "$VEX" \
  --policy-dir "$ROOT/policy" \
  --image "$INPUT_IMAGE" \
  --exposure "$INPUT_EXPOSURE" \
  --output "$REPORT_DIR/decision.json" \
  --markdown "$REPORT_DIR/report.md")
echo "Admission decision: $DECISION (mode=$INPUT_MODE)"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "admission=$DECISION"
    echo "report_json=$REPORT_DIR/decision.json"
    echo "report_markdown=$REPORT_DIR/report.md"
  } >> "$GITHUB_OUTPUT"
fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  cat "$REPORT_DIR/report.md" >> "$GITHUB_STEP_SUMMARY"
fi
if [[ "$INPUT_MODE" == enforce && "$DECISION" != ALLOW ]]; then
  echo "ERROR: release not permitted by policy: $DECISION" >&2
  exit 3
fi

