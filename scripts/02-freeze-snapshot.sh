#!/usr/bin/env bash
# ==============================================================================
# Script: 02-freeze-snapshot.sh
# Purpose: Phase 1 Pre-Migration Repository Freeze & Rekor-Free Snapshot Anchor
# ==============================================================================

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
KEYS_DIR="${POC_ROOT}/keys"
WORK_DIR="${POC_ROOT}/work"
OLD_REPO="${WORK_DIR}/old-repo"
ARCHIVES_DIR="${POC_ROOT}/archives"
RESULTS_DIR="${POC_ROOT}/results"

mkdir -p "${ARCHIVES_DIR}" "${RESULTS_DIR}" "${WORK_DIR}"
SNAPSHOT_LOG="${RESULTS_DIR}/02-snapshot.txt"

exec > >(tee "${SNAPSHOT_LOG}") 2>&1

echo "======================================================================"
echo " PHASE 1: PRE-MIGRATION REPOSITORY FREEZE & SNAPSHOT COMMITMENT"
echo " Date: $(date -u +'%Y-%m-%dT%H:%M:%SZ')"
echo "======================================================================"
echo

# 1. Compute OID-ONLY commitment (privacy-safe: no ref names)
echo "=== Step 1: Computing OID-Only Commitment ==="
if [ ! -d "${OLD_REPO}/.git" ]; then
    echo "ERROR: work/old-repo does not exist. Run Phase 0 baseline first."
    exit 1
fi

ROOT_FP=$(ssh-keygen -l -f "${KEYS_DIR}/root.pub" | awk '{print $2}')
echo "Root Key Fingerprint: ${ROOT_FP}"

# Collect OIDs
compute_commitment() {
    (
        cd "${OLD_REPO}"
        # Migrated branch and tag tips (OID only)
        git show-ref --heads --tags | awk '{print $1}'
        # RSL tip
        git rev-parse refs/gittuf/reference-state-log
        # Policy tip
        git rev-parse refs/gittuf/policy
        # Root key fingerprint
        echo "${ROOT_FP}"
    ) | LC_ALL=C sort -u
}

compute_commitment > "${WORK_DIR}/oid-commitment.txt"
COMMITMENT_SHA256=$(sha256sum "${WORK_DIR}/oid-commitment.txt" | awk '{print $1}')

echo "--- OID Commitment Content (work/oid-commitment.txt) ---"
cat "${WORK_DIR}/oid-commitment.txt"
echo "--------------------------------------------------------"
echo "Commitment SHA-256: ${COMMITMENT_SHA256}"
echo

# 2. Create git bundle of old repo
echo "=== Step 2: Creating Git Bundle (archives/old-repo.bundle) ==="
BUNDLE_FILE="${ARCHIVES_DIR}/old-repo.bundle"
rm -f "${BUNDLE_FILE}"
(
    cd "${OLD_REPO}"
    git bundle create "${BUNDLE_FILE}" --all
)
BUNDLE_SHA256=$(sha256sum "${BUNDLE_FILE}" | awk '{print $1}')
echo "Bundle SHA-256: ${BUNDLE_SHA256}"
echo

# 3. Create archives/snapshot-manifest.json
echo "=== Step 3: Generating archives/snapshot-manifest.json ==="
FROZEN_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SHA1_HEAD=$(cd "${OLD_REPO}" && git rev-parse HEAD)
RSL_TIP=$(cd "${OLD_REPO}" && git rev-parse refs/gittuf/reference-state-log)
POLICY_OID=$(cd "${OLD_REPO}" && git rev-parse refs/gittuf/policy)
MANIFEST_FILE="${ARCHIVES_DIR}/snapshot-manifest.json"

cat <<EOF > "${MANIFEST_FILE}"
{
  "schema_version": "gap1-poc-v1",
  "frozen_at": "${FROZEN_AT}",
  "sha1_repo_head": "${SHA1_HEAD}",
  "rsl_tip": "${RSL_TIP}",
  "policy_oid": "${POLICY_OID}",
  "bundle_sha256": "${BUNDLE_SHA256}",
  "commitment_sha256": "${COMMITMENT_SHA256}",
  "root_key_fingerprint": "${ROOT_FP}"
}
EOF

echo "--- Snapshot Manifest (archives/snapshot-manifest.json) ---"
cat "${MANIFEST_FILE}"
echo "-----------------------------------------------------------"
echo

# 4. Sign the manifest with root SSH key
echo "=== Step 4: Signing Manifest with Root Key (ssh-keygen -Y sign) ==="
rm -f "${MANIFEST_FILE}.sig"
ssh-keygen -Y sign -f "${KEYS_DIR}/root" -n file "${MANIFEST_FILE}"
echo "Signature generated: ${MANIFEST_FILE}.sig"

# Verify signature round-trip
ALLOWED_SIGNERS="${WORK_DIR}/allowed_signers"
echo "root-key $(cat "${KEYS_DIR}/root.pub")" > "${ALLOWED_SIGNERS}"

echo "Verifying signature with ssh-keygen -Y verify..."
ssh-keygen -Y verify -f "${ALLOWED_SIGNERS}" -I "root-key" -n file -s "${MANIFEST_FILE}.sig" < "${MANIFEST_FILE}"
VERIFY_STATUS=$?
if [ ${VERIFY_STATUS} -eq 0 ]; then
    echo "[PASS] Root key signature verified successfully (Exit: 0)"
else
    echo "[FAIL] Root key signature verification failed (Exit: ${VERIFY_STATUS})"
fi
echo

# 5. Optional RFC 3161 timestamp
echo "=== Step 5: Optional RFC 3161 Timestamp (freetsa.org) ==="
TS_TOKEN="${ARCHIVES_DIR}/snapshot-manifest.tsr"
if command -v openssl &>/dev/null && command -v curl &>/dev/null; then
    TS_QUERY="${WORK_DIR}/manifest.tsq"
    openssl ts -query -data "${MANIFEST_FILE}" -no_nonce -sha256 -cert -out "${TS_QUERY}" 2>/dev/null || true
    if [ -f "${TS_QUERY}" ]; then
        curl -s -m 5 -H "Content-Type: application/timestamp-query" --data-binary @"${TS_QUERY}" https://freetsa.org/tsr > "${TS_TOKEN}" 2>/dev/null || true
        if [ -s "${TS_TOKEN}" ]; then
            echo "[INFO] RFC 3161 timestamp acquired from freetsa.org and saved to ${TS_TOKEN}"
        else
            rm -f "${TS_TOKEN}"
            echo "[INFO] RFC 3161 timestamp request skipped/unavailable (optional)."
        fi
    fi
else
    echo "[INFO] openssl or curl not found; RFC 3161 timestamp skipped (optional)."
fi
echo

# 6. Recompute commitment twice for determinism proof
echo "=== Step 6: Determinism Verification (Recompute Twice) ==="
RUN1=$(compute_commitment | sha256sum | awk '{print $1}')
RUN2=$(compute_commitment | sha256sum | awk '{print $1}')

echo "Original Hash:  ${COMMITMENT_SHA256}"
echo "Recompute Run1: ${RUN1}"
echo "Recompute Run2: ${RUN2}"

if [ "${COMMITMENT_SHA256}" = "${RUN1}" ] && [ "${COMMITMENT_SHA256}" = "${RUN2}" ]; then
    echo "[PASS] Determinism proof verified: byte-identical commitment hash across all runs."
else
    echo "[FAIL] Determinism mismatch detected!"
    exit 1
fi
echo

echo "======================================================================"
echo " PHASE 1 COMPLETE. LOG SAVED TO ${SNAPSHOT_LOG}"
echo "======================================================================"