#!/usr/bin/env bash
# ==============================================================================
# Script: 01-baseline.sh
# Purpose: Phase 0 Setup Baseline SHA-1 Repository & Full gittuf Policy
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${POC_ROOT}/keys"
WORK_DIR="${POC_ROOT}/work"
OLD_REPO="${WORK_DIR}/old-repo"
RESULTS_DIR="${POC_ROOT}/results"

mkdir -p "${KEYS_DIR}" "${WORK_DIR}" "${RESULTS_DIR}"
BASELINE_LOG="${RESULTS_DIR}/01-baseline.txt"

# Locate gittuf binary
GITTUF_BIN="$(command -v gittuf 2>/dev/null || true)"
if [ -z "${GITTUF_BIN}" ]; then
    CURRENT_USER="${USER:-${USERNAME:-}}"
    for candidate in \
        "${HOME}/go/bin/gittuf" \
        "${HOME}/go/bin/gittuf.exe" \
        "/c/Users/${CURRENT_USER}/go/bin/gittuf.exe" \
        "/mnt/c/Users/${CURRENT_USER}/go/bin/gittuf.exe" \
        "${POC_ROOT}/bin/gittuf" \
        "${POC_ROOT}/bin/gittuf.exe" \
        "${POC_ROOT}/../gittuf.exe"; do
        if [ -n "${candidate}" ] && [ -f "${candidate}" ]; then
            GITTUF_BIN="${candidate}"
            break
        fi
    done
fi

exec > >(tee "${BASELINE_LOG}") 2>&1

echo "======================================================================"
echo " PHASE 0: SETUP BASELINE SHA-1 REPOSITORY & GITTUF POLICY"
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

# 1. Generate Disposable SSH Keys in keys/
echo "=== Step 1: Generating Ed25519 Keys in keys/ ==="
if [ ! -f "${KEYS_DIR}/root" ]; then
    ssh-keygen -t ed25519 -N "" -f "${KEYS_DIR}/root" -C "root-key" &> /dev/null
fi
if [ ! -f "${KEYS_DIR}/policy" ]; then
    ssh-keygen -t ed25519 -N "" -f "${KEYS_DIR}/policy" -C "policy-key" &> /dev/null
fi
if [ ! -f "${KEYS_DIR}/dev" ]; then
    ssh-keygen -t ed25519 -N "" -f "${KEYS_DIR}/dev" -C "dev-key" &> /dev/null
fi
echo "Keys generated successfully in keys/."
echo "----------------------------------------------------------------------"

# 2. Create work/old-repo (SHA-1 Git Repo)
echo "=== Step 2: Initializing SHA-1 Repository in work/old-repo ==="
rm -rf "${OLD_REPO}"
mkdir -p "${OLD_REPO}"
cd "${OLD_REPO}"

run_cmd "Git Init (SHA-1)" git init -b main
git config user.name "Developer User"
git config user.email "dev@example.com"
git config gpg.format ssh
git config user.signingkey "${KEYS_DIR}/dev.pub"

# Make initial 3 commits
echo "# Baseline SHA-1 Repository" > README.md
git add README.md
run_cmd "Commit 1" git commit -m "Initial commit"

echo "Feature A content" > feature_a.txt
git add feature_a.txt
run_cmd "Commit 2" git commit -m "Add feature A"

echo "Feature B content" > feature_b.txt
git add feature_b.txt
run_cmd "Commit 3" git commit -m "Add feature B"

# Annotated Tag v1.0.0
run_cmd "Annotated Tag v1.0.0" git tag -a v1.0.0 -m "Release version 1.0.0"

# 3. Initialize gittuf metadata BEFORE recording main reference
echo "=== Step 3: Initializing gittuf Root of Trust & Policies ==="

# Initialize Root of Trust
run_cmd "gittuf trust init" "${GITTUF_BIN}" trust init -k "${KEYS_DIR}/root" --create-rsl-entry

# Add Policy Key to Root of Trust
run_cmd "gittuf trust add-policy-key" "${GITTUF_BIN}" trust add-policy-key -k "${KEYS_DIR}/root" --policy-key "${KEYS_DIR}/policy.pub" --create-rsl-entry

# Initialize Policy
run_cmd "gittuf policy init" "${GITTUF_BIN}" policy init -k "${KEYS_DIR}/policy" --create-rsl-entry

# Add Developer Key to Policy
run_cmd "gittuf policy add-key" "${GITTUF_BIN}" policy add-key -k "${KEYS_DIR}/policy" --public-key "${KEYS_DIR}/dev.pub" --create-rsl-entry

# Retrieve Developer Key ID from policy-staging
DEV_KEY_ID="$("${GITTUF_BIN}" policy list-principals --policy-ref policy-staging 2>/dev/null | grep -o 'SHA256:[^ :]*' | head -n1 || true)"
if [ -z "${DEV_KEY_ID}" ]; then
    DEV_KEY_ID="${KEYS_DIR}/dev.pub"
fi
echo "Retrieved Developer Principal ID: ${DEV_KEY_ID}"

# Add Rule protecting refs/heads/main
run_cmd "gittuf policy add-rule" "${GITTUF_BIN}" policy add-rule -k "${KEYS_DIR}/policy" --rule-name protect-main --rule-pattern "refs/heads/main" --authorize "${DEV_KEY_ID}" --create-rsl-entry

# Apply staged policy locally
run_cmd "gittuf policy apply" "${GITTUF_BIN}" policy apply -k "${KEYS_DIR}/policy" --local-only

# 4. Record main ref in RSL AFTER policy apply + add 2 more developer commits
echo "=== Step 4: Recording RSL Entries under Active Policy ==="

# Record main baseline commit in RSL under policy
run_cmd "RSL Record main (Baseline)" "${GITTUF_BIN}" rsl record main --local-only

echo "Commit 4 content" >> README.md
git add README.md
run_cmd "Commit 4" git commit -m "Update README with Commit 4"
run_cmd "RSL Record main (Commit 4)" "${GITTUF_BIN}" rsl record main --local-only

echo "Commit 5 content" >> README.md
git add README.md
run_cmd "Commit 5" git commit -m "Update README with Commit 5"
run_cmd "RSL Record main (Commit 5)" "${GITTUF_BIN}" rsl record main --local-only

# Print RSL Log
run_cmd "gittuf rsl log" "${GITTUF_BIN}" rsl log

# 5. Baseline Verification
echo "=== Step 5: Running gittuf verify-ref --verbose main ==="
run_cmd "gittuf verify-ref --verbose main" "${GITTUF_BIN}" verify-ref --verbose main
VERIFY_EXIT=$?

echo
echo "======================================================================"
echo " PHASE 0 BASELINE COMPLETE. VERIFY-REF EXIT CODE: ${VERIFY_EXIT}"
echo " LOG SAVED TO ${BASELINE_LOG}"
echo "======================================================================"

