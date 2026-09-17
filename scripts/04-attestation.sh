#!/usr/bin/env bash
# ==============================================================================
# Script: 04-attestation.sh
# Purpose: Phase 3 Execution â€” Make Approach C real (Genesis DSSE Attestation)
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${POC_ROOT}/keys"
WORK_DIR="${POC_ROOT}/work"
RESULTS_DIR="${POC_ROOT}/results"
ATTEST_REPO="${WORK_DIR}/new-repo-attest"
OLD_REPO="${WORK_DIR}/old-repo"

GITTUF_BIN="${POC_ROOT}/../gittuf.exe"
if [ ! -f "${GITTUF_BIN}" ]; then
    GITTUF_BIN="/c/Users/explo/Desktop/gittuf/gittuf.exe"
fi

LOG_FILE="${RESULTS_DIR}/04-attestation.txt"

(
    echo "======================================================================"
    echo " PHASE 3: ATTESTATION GENESIS"
    echo "======================================================================"

    OLD_SHA1="$(cd "${OLD_REPO}" && git rev-parse refs/heads/main)"
    NEW_SHA256="$(cd "${ATTEST_REPO}" && git rev-parse refs/heads/main)"

    echo "[CMD] Running Go snippet to generate DSSE attestation..."
    cd "${POC_ROOT}"
    go run scripts/dsse_sign.go "${OLD_SHA1}" "${NEW_SHA256}" "${KEYS_DIR}/root" "${ATTEST_REPO}/genesis_attestation.json"
    
    cd "${ATTEST_REPO}"
    echo "[CMD] Generated Attestation File:"
    cat genesis_attestation.json

    echo "[CMD] Storing it under refs/gittuf/attestations"
    # To store it in the tree, we need to create a blob and put it in a tree under refs/gittuf/attestations
    BLOB_ID=$(git hash-object -w genesis_attestation.json)
    
    # We will put it in a known path in the attestations tree, or just push it.
    # Wait, the prompt says "store it under the attestations ref".
    # I will create a simple tree for refs/gittuf/attestations.
    printf "100644 blob ${BLOB_ID}\tgenesis_attestation.json\n" > tree_input.txt
    TREE_ID=$(git mktree < tree_input.txt)
    COMMIT_ID=$(echo "Initial Genesis Attestation" | git commit-tree ${TREE_ID})
    git update-ref refs/gittuf/attestations ${COMMIT_ID}

    echo "[CMD] Running gittuf verify-ref to confirm it passes"
    "${GITTUF_BIN}" verify-ref --verbose main

    echo "[CMD] Tampering with the attestation payload"
    # Tamper with the JSON by replacing a character in the base64 payload
    sed -i 's/"payload": "/"payload": "X/' genesis_attestation.json
    BLOB_ID_TAMPERED=$(git hash-object -w genesis_attestation.json)
    printf "100644 blob ${BLOB_ID_TAMPERED}\tgenesis_attestation.json\n" > tree_input_tampered.txt
    TREE_ID_TAMPERED=$(git mktree < tree_input_tampered.txt)
    COMMIT_ID_TAMPERED=$(echo "Tampered Genesis Attestation" | git commit-tree ${TREE_ID_TAMPERED})
    git update-ref refs/gittuf/attestations ${COMMIT_ID_TAMPERED}

    echo "[CMD] Running gittuf verify-ref with tampered attestation"
    "${GITTUF_BIN}" verify-ref --verbose main || echo "Verification failed as expected!"
) > "${LOG_FILE}" 2>&1

EXIT_CODE=$?
exit ${EXIT_CODE}

