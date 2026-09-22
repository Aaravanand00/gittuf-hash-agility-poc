#!/usr/bin/env bash
# ==============================================================================
# Script: 00-env.sh
# Purpose: Phase 1 Environment Check & Version Pinning for GAP-1 Extended PoC
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RESULTS_DIR="${POC_ROOT}/results"

mkdir -p "${RESULTS_DIR}"
ENV_LOG="${RESULTS_DIR}/env.txt"

exec > >(tee "${ENV_LOG}") 2>&1

echo "======================================================================"
echo " PHASE 1: ENVIRONMENT CHECK & VERSION PINNING"
echo " Date: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "======================================================================"
echo

# Helper function to execute command, log output, and log exit code
run_cmd() {
    local label="$1"
    shift
    echo "[CMD] ${label}: $*"
    "$@"
    local exit_code=$?
    echo "EXIT: ${exit_code}"
    echo "----------------------------------------------------------------------"
    return ${exit_code}
}

# 1. Check Git Version (Expect >= 2.45)
run_cmd "Git Version" git --version

# 2. Check Go Version (Expect >= 1.21)
run_cmd "Go Version" go version

# 3. Locate & Check Gittuf Binary
GITTUF_BIN="${POC_ROOT}/../gittuf.exe"
if [ ! -f "${GITTUF_BIN}" ]; then
    GITTUF_BIN="/c/Users/explo/Desktop/gittuf/gittuf.exe"
fi
if [ ! -f "${GITTUF_BIN}" ]; then
    GITTUF_BIN="$(command -v gittuf || true)"
fi

if [ -n "${GITTUF_BIN}" ]; then
    run_cmd "Gittuf Version" "${GITTUF_BIN}" version
    run_cmd "Gittuf CLI Help" "${GITTUF_BIN}" --help
else
    echo "[WARNING] gittuf binary not found."
    echo "EXIT: 127"
fi

# 4. Check ssh-keygen availability for key generation
run_cmd "SSH Keygen Availability" which ssh-keygen || true

echo
echo "======================================================================"
echo " PHASE 1 ENVIRONMENT CHECK COMPLETE. LOG SAVED TO ${ENV_LOG}"
echo "======================================================================"

