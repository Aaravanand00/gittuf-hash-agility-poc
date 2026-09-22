#!/usr/bin/env bash
# ==============================================================================
# Script: 05-edge-cases.sh
# Purpose: Phase 4 Execution â€” Edge Cases
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${POC_ROOT}/keys"
WORK_DIR="${POC_ROOT}/work"
RESULTS_DIR="${POC_ROOT}/results"
OLD_REPO="${WORK_DIR}/old-repo"
LOG_FILE="${RESULTS_DIR}/05-edge.txt"

GITTUF_BIN="${POC_ROOT}/../gittuf.exe"
if [ ! -f "${GITTUF_BIN}" ]; then
    GITTUF_BIN="/c/Users/explo/Desktop/gittuf/gittuf.exe"
fi

echo "======================================================================" > "${LOG_FILE}"
echo " PHASE 4: EDGE CASES" >> "${LOG_FILE}"
echo "======================================================================" >> "${LOG_FILE}"

# ------------------------------------------------------------------------------
# PROBE 1: compatObjectFormat window
# ------------------------------------------------------------------------------
echo "=== PROBE 1: compatObjectFormat ===" >> "${LOG_FILE}"
echo "HYPOTHESIS: Git will transparently resolve the old SHA-1 OID to the new SHA-256 object because 'compatObjectFormat' enables bidirectional mapping. However, 'gittuf' verify-ref may still fail because it directly verifies the signed RSL entries which explicitly expect the old SHA-1 strings." >> "${LOG_FILE}"
echo "-----------------------------------" >> "${LOG_FILE}"

COMPAT_REPO="${WORK_DIR}/repo-compat"
rm -rf "${COMPAT_REPO}"
mkdir -p "${COMPAT_REPO}"
(
    cd "${COMPAT_REPO}"
    git init --object-format=sha256 -b main
    git config extensions.compatObjectFormat sha1
    
    # Import
    (cd "${OLD_REPO}" && git fast-export --all --signed-tags=strip) | git fast-import

    # Fetch gittuf refs
    git fetch "${OLD_REPO}" "refs/gittuf/*:refs/gittuf/*" || true

    OLD_OID="$(cd "${OLD_REPO}" && git rev-parse refs/heads/main)"
    
    echo "[CMD] git cat-file -p ${OLD_OID}"
    git cat-file -p "${OLD_OID}"
    GIT_EXIT=$?
    echo "Git cat-file EXIT: ${GIT_EXIT}"

    echo "[CMD] gittuf verify-ref main"
    "${GITTUF_BIN}" verify-ref --verbose main
    GITTUF_EXIT=$?
    echo "Gittuf EXIT: ${GITTUF_EXIT}"

    echo "RESULT: Git cat-file exit was ${GIT_EXIT}. Gittuf verify exit was ${GITTUF_EXIT}."
) >> "${LOG_FILE}" 2>&1

# ------------------------------------------------------------------------------
# PROBE 2: Fresh-clone verify
# ------------------------------------------------------------------------------
echo -e "\n=== PROBE 2: Fresh-clone verify ===" >> "${LOG_FILE}"
echo "HYPOTHESIS: Verification will succeed because all gittuf policies and the RSL are standard git refs (under refs/gittuf/*) which are perfectly preserved in a clone if fetched." >> "${LOG_FILE}"
echo "-----------------------------------" >> "${LOG_FILE}"

CLONED_REPO="${WORK_DIR}/repo-cloned"
rm -rf "${CLONED_REPO}"
(
    # Note: gittuf clone handles grabbing gittuf refs
    echo "[CMD] gittuf clone ${WORK_DIR}/new-repo-fresh ${CLONED_REPO}"
    "${GITTUF_BIN}" clone "${WORK_DIR}/new-repo-fresh" "${CLONED_REPO}"
    
    cd "${CLONED_REPO}"
    echo "[CMD] gittuf verify-ref main"
    "${GITTUF_BIN}" verify-ref --verbose main
    GITTUF_EXIT=$?
    echo "Gittuf EXIT: ${GITTUF_EXIT}"
    echo "RESULT: Gittuf verify exit was ${GITTUF_EXIT}."
) >> "${LOG_FILE}" 2>&1

# ------------------------------------------------------------------------------
# PROBE 3: Signed tags without strip
# ------------------------------------------------------------------------------
echo -e "\n=== PROBE 3: Signed tags ===" >> "${LOG_FILE}"
echo "HYPOTHESIS: git fast-import will either fail to import the tag because the signature covers a SHA-1 payload that no longer matches, or it will import it but the signature will immediately be invalid." >> "${LOG_FILE}"
echo "-----------------------------------" >> "${LOG_FILE}"

SIGNED_REPO="${WORK_DIR}/repo-signed-tags"
rm -rf "${SIGNED_REPO}"
mkdir -p "${SIGNED_REPO}"
(
    cd "${SIGNED_REPO}"
    git init --object-format=sha256 -b main
    
    echo "[CMD] fast-export WITHOUT --signed-tags=strip"
    # We will try to export and import without stripping tags
    # First we need a signed tag in OLD_REPO if one doesn't exist.
    # Phase 0 created an annotated tag, but maybe not a GPG-signed tag.
    # Let's just try fast-export --signed-tags=verbatim
    (cd "${OLD_REPO}" && git fast-export --all --signed-tags=verbatim) | git fast-import
    IMPORT_EXIT=$?
    echo "Import EXIT: ${IMPORT_EXIT}"
    
    # Check if tag exists
    TAG_INFO="$(git tag -l -n1)"
    echo "Tags: ${TAG_INFO}"
    
    echo "RESULT: fast-import exit was ${IMPORT_EXIT}."
) >> "${LOG_FILE}" 2>&1

# ------------------------------------------------------------------------------
# PROBE 4: Snapshot determinism
# ------------------------------------------------------------------------------
echo -e "\n=== PROBE 4: Snapshot determinism ===" >> "${LOG_FILE}"
echo "HYPOTHESIS: The hashes will match perfectly because git bundle and clone operations are deterministic regarding object contents." >> "${LOG_FILE}"
echo "-----------------------------------" >> "${LOG_FILE}"

BUNDLE_CLONE="${WORK_DIR}/old-repo-bundle-clone"
rm -rf "${BUNDLE_CLONE}"
(
    # In Phase 0, a bundle might have been created, but let's just make one now to be sure.
    cd "${OLD_REPO}"
    git bundle create old-repo.bundle --all
    
    cd "${WORK_DIR}"
    git clone old-repo/old-repo.bundle "${BUNDLE_CLONE}"
    
    # Run the commitment command (Snapshot determinism)
    # E.g., getting a hash of all objects
    HASH_ORIG=$(cd "${OLD_REPO}" && git rev-list --all --objects | sort | sha256sum | awk '{print $1}')
    HASH_CLONE=$(cd "${BUNDLE_CLONE}" && git rev-list --all --objects | sort | sha256sum | awk '{print $1}')
    
    echo "Original Hash: ${HASH_ORIG}"
    echo "Cloned Hash:   ${HASH_CLONE}"
    
    if [ "${HASH_ORIG}" == "${HASH_CLONE}" ]; then
        echo "RESULT: MATCH"
    else
        echo "RESULT: MISMATCH"
    fi
) >> "${LOG_FILE}" 2>&1

echo "Phase 4 Complete."

