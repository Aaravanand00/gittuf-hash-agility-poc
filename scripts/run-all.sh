#!/usr/bin/env bash
# ==============================================================================
# Script: run-all.sh
# Purpose: Orchestrate all phases of the Hash Agility PoC (Phases 0-4)
# Usage:
#   ./scripts/run-all.sh                    # run all phases
#   ./scripts/run-all.sh --skip-phase 1,2   # skip phases 1 and 2
# ==============================================================================

set -e
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${POC_ROOT}/results"

mkdir -p "${RESULTS_DIR}"

SKIP_PHASES=""

# Parse --skip-phase flag
for arg in "$@"; do
    case "${arg}" in
        --skip-phase=*)
            SKIP_PHASES="${arg#*=}"
            ;;
        --skip-phase)
            shift
            SKIP_PHASES="${1:-}"
            ;;
    esac
done

should_skip() {
    local phase="$1"
    echo "${SKIP_PHASES}" | tr ',' '\n' | grep -q "^${phase}$"
}

run_phase() {
    local phase_num="$1"
    local script="$2"
    local name="$3"

    if should_skip "${phase_num}"; then
        echo ">>> Skipping Phase ${phase_num}: ${name}"
        return 0
    fi

    echo ""
    echo "========================================================================"
    echo ">>> Running Phase ${phase_num}: ${name}"
    echo "========================================================================"
    bash "${SCRIPT_DIR}/${script}"
    local EXIT=$?
    if [ ${EXIT} -ne 0 ]; then
        echo ">>> Phase ${phase_num} FAILED with exit code ${EXIT}"
        exit ${EXIT}
    fi
    echo ">>> Phase ${phase_num} PASSED (exit 0)"
}

echo "========================================================================"
echo " gittuf Hash Agility PoC — Full Run"
echo " Date: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "========================================================================"

run_phase 0 "00-env.sh"              "Environment Check & Version Pinning"
run_phase 1 "01-baseline.sh"         "Baseline SHA-1 Repo + gittuf Init"
run_phase 2 "03-verification-matrix.sh" "Verification Matrix (Scenarios A-D)"
run_phase 3 "04-attestation.sh"      "DSSE Genesis Attestation (Approach C)"
run_phase 4 "05-edge-cases.sh"       "Edge Cases"

echo ""
echo "========================================================================"
echo " ALL PHASES COMPLETE"
echo " Results in: ${RESULTS_DIR}"
echo "========================================================================"
ls -1 "${RESULTS_DIR}"
