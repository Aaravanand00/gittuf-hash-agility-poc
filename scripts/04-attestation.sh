#!/bin/bash
set -e

echo "=== Phase 3: Hash-Equivalence Attestation (Approach C) ==="

SHA1_HEAD=$(git -C work/old-repo rev-parse main)
SHA256_HEAD=$(git -C work/new-repo-attest rev-parse main)

echo "[1] Generating DSSE PAE and payload for $SHA1_HEAD -> $SHA256_HEAD..."
go run scripts/04-dsse-helper.go pae $SHA1_HEAD $SHA256_HEAD > work/pae.txt
go run scripts/04-dsse-helper.go payload $SHA1_HEAD $SHA256_HEAD > work/payload.txt

echo "[2] Signing PAE with old root key (gittuf native format)..."
rm -f work/pae.txt.sig
ssh-keygen -Y sign -n git -f keys/root work/pae.txt

echo "[3] Building DSSE JSON envelope..."
go run scripts/04-dsse-helper.go envelope $SHA1_HEAD $SHA256_HEAD keys/root.pub work/pae.txt.sig > work/hash-equivalence.json

echo "[4] Pushing to refs/gittuf/attestations in new SHA-256 repository..."
cd work/new-repo-attest
BLOB=$(git hash-object -w ../hash-equivalence.json)
TREE=$(printf "100644 blob %s\thash-equivalence.json\n" "$BLOB" | git mktree)
COMMIT=$(git commit-tree $TREE -m "Add hash equivalence attestation")
git update-ref refs/gittuf/attestations $COMMIT
cd ../..
echo "    -> Committed as $COMMIT"

echo "--------------------------------------------------------"
echo "[5] VERIFICATION (Positive Test)"
echo "--------------------------------------------------------"
git -C work/new-repo-attest show refs/gittuf/attestations:hash-equivalence.json > work/extracted.json

cat work/extracted.json | grep -oP '"sig": "\K[^"]+' | base64 -d > work/extracted.sig
cat work/extracted.json | grep -oP '"payload": "\K[^"]+' | base64 -d > work/extracted_payload.txt
PAYLOAD_LEN=$(wc -c < work/extracted_payload.txt)
echo -n "DSSEv1 28 application/vnd.in-toto+json $PAYLOAD_LEN " > work/extracted_pae.txt
cat work/extracted_payload.txt >> work/extracted_pae.txt

echo "root $(cat keys/root.pub)" > keys/allowed_signers
ssh-keygen -Y verify -n git -I root -f keys/allowed_signers -s work/extracted.sig < work/extracted_pae.txt
echo "    -> Verification SUCCESSFUL"

echo "--------------------------------------------------------"
echo "[6] VERIFICATION (Negative Tamper Test)"
echo "--------------------------------------------------------"
go run scripts/04-dsse-helper.go tamper work/extracted.json > work/tampered.json
cat work/tampered.json | grep -oP '"payload": "\K[^"]+' | base64 -d > work/tampered_payload.txt
TAMPERED_LEN=$(wc -c < work/tampered_payload.txt)
echo -n "DSSEv1 28 application/vnd.in-toto+json $TAMPERED_LEN " > work/tampered_pae.txt
cat work/tampered_payload.txt >> work/tampered_pae.txt

if ssh-keygen -Y verify -n git -I root -f keys/allowed_signers -s work/extracted.sig < work/tampered_pae.txt 2>/dev/null; then
  echo "    -> ERROR: Tampered signature verified successfully (FAIL-OPEN)"
  exit 1
else
  echo "    -> Verification FAILED (FAIL-CLOSED - Expected)"
fi

echo "=== Phase 3 Completed ==="

