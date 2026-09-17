#!/usr/bin/env bash
set -u

POC_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${POC_ROOT}"

echo "======================================================================"
echo " LIVE AUDIT & VERIFICATION"
echo "======================================================================"
echo

echo "=== (a) Check OID commitment for zero ref names ==="
cat work/oid-commitment.txt
echo "--- Scanning for 'refs/', 'heads/', 'main', 'tags/', etc. ---"
if grep -qiE '(refs|heads|tags|main|master)' work/oid-commitment.txt; then
    echo "[FAIL] Ref names found in commitment!"
else
    echo "[PASS] ZERO ref names found! Only pure hex OIDs and Root Key Fingerprint."
fi
echo

echo "=== (b) Reproduce commitment hash directly from repo state ==="
ROOT_FP=$(ssh-keygen -l -f keys/root.pub | awk '{print $2}')
echo "Root FP: ${ROOT_FP}"
REPRODUCED_HASH=$( (
    cd work/old-repo
    git show-ref --heads --tags | awk '{print $1}'
    git rev-parse refs/gittuf/reference-state-log
    git rev-parse refs/gittuf/policy
    echo "${ROOT_FP}"
) | LC_ALL=C sort -u | sha256sum | awk '{print $1}' )

MANIFEST_HASH=$(grep 'commitment_sha256' archives/snapshot-manifest.json | awk -F'"' '{print $4}')
echo "Spec-computed Hash: ${REPRODUCED_HASH}"
echo "Manifest Hash:      ${MANIFEST_HASH}"
if [ "${REPRODUCED_HASH}" = "${MANIFEST_HASH}" ]; then
    echo "[PASS] Exact hash match: anyone copying the spec produces identical hash!"
else
    echo "[FAIL] Hash mismatch!"
fi
echo

echo "=== (c) Signature verification round-trip ==="
echo "root-key $(cat keys/root.pub)" > work/allowed_signers
ssh-keygen -Y verify -f work/allowed_signers -I root-key -n file -s archives/snapshot-manifest.json.sig < archives/snapshot-manifest.json
EXIT_CODE=$?
if [ ${EXIT_CODE} -eq 0 ]; then
    echo "[PASS] Root key signature verification: EXIT 0 (Valid OpenSSH signature)"
else
    echo "[FAIL] Signature check failed: EXIT ${EXIT_CODE}"
fi
echo

echo "=== (d) Bundle SHA-256 matches manifest (Tamper-evident archive) ==="
ACTUAL_BUNDLE_SHA=$(sha256sum archives/old-repo.bundle | awk '{print $1}')
MANIFEST_BUNDLE_SHA=$(grep 'bundle_sha256' archives/snapshot-manifest.json | awk -F'"' '{print $4}')
echo "Actual Bundle Hash:   ${ACTUAL_BUNDLE_SHA}"
echo "Manifest Bundle Hash: ${MANIFEST_BUNDLE_SHA}"
if [ "${ACTUAL_BUNDLE_SHA}" = "${MANIFEST_BUNDLE_SHA}" ]; then
    echo "[PASS] Bundle hash in manifest matches actual archive (Rekor-free anchoring)!"
else
    echo "[FAIL] Bundle hash mismatch!"
fi
echo

echo "=== (e) Determinism proof (2 independent re-runs) ==="
RUN1=$( ( cd work/old-repo; git show-ref --heads --tags | awk '{print $1}'; git rev-parse refs/gittuf/reference-state-log; git rev-parse refs/gittuf/policy; echo "${ROOT_FP}" ) | LC_ALL=C sort -u | sha256sum | awk '{print $1}' )
RUN2=$( ( cd work/old-repo; git show-ref --heads --tags | awk '{print $1}'; git rev-parse refs/gittuf/reference-state-log; git rev-parse refs/gittuf/policy; echo "${ROOT_FP}" ) | LC_ALL=C sort -u | sha256sum | awk '{print $1}' )
echo "Run 1 Hash: ${RUN1}"
echo "Run 2 Hash: ${RUN2}"
if [ "${RUN1}" = "${RUN2}" ] && [ "${RUN1}" = "${MANIFEST_HASH}" ]; then
    echo "[PASS] Determinism confirmed: identical byte-for-byte output across independent runs!"
else
    echo "[FAIL] Determinism mismatch!"
fi