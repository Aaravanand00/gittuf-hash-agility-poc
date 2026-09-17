# Canonical Specification: Pre-Migration Snapshot & Merkle Tree Hash Formula

**Version:** 1.0.0 (GAP-1 Extended PoC)  
**Status:** Canonical Draft  
**Purpose:** Resolves Gap #3 by defining an unambiguous, deterministic, language-agnostic hash formula for `gittuf` pre-migration repository state snapshots.

---

## 1. Overview

During a Git repository migration from SHA-1 to SHA-256, `gittuf` preserves historical signature continuity by creating a frozen snapshot of all pre-migration reference tips ($T_{\text{migrate}}$). 

To ensure $O(1)$ fixed payload size (32 bytes) and complete verification reproducibility across different implementations (Go, Rust, Python, Shell), this specification mandates the exact canonical line format, sorting rules, leaf hashing, and pairwise Merkle tree reduction algorithm.

---

## 2. Canonical Serialization Rules

### 2.1 Ref Tip Tuples
For every reference tip in the pre-migration SHA-1 repository (e.g., `refs/heads/*`, `refs/tags/*`), a 3-tuple is captured:
1. `ref_name` (`string`): Full reference name (e.g., `refs/heads/main`).
2. `sha1_target` (`string`): 40-character lowercase hexadecimal SHA-1 commit/tag ID.
3. `sha256_target` (`string`): 64-character lowercase hexadecimal SHA-256 translated commit/tag ID.

### 2.2 Canonical Ordering
All 3-tuples **MUST** be sorted in strictly ascending lexicographical order by byte value of `ref_name` (C-locale ASCII order).

### 2.3 Canonical Line String Encoding
Each sorted tuple $i$ is formatted into a UTF-8 string using colon separator (`:`):

$$\text{CanonicalLine}_i = \text{ref\_name}_i \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{sha1\_target}_i \mathbin{\Vert} \text{":"} \mathbin{\Vert} \text{sha256\_target}_i$$

*Example:*
```
refs/heads/feature/auth:a1b2c3d4e5f60718293041526374859607182930:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
refs/heads/main:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b:8f4e3c2b1a0d9e8f7c6b5a4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f
```

---

## 3. Merkle Tree Hash Calculation Algorithm

### 3.1 Leaf Node Hash
For each canonical line string $i$, compute the leaf digest using SHA-256:

$$H_{\text{leaf}, i} = \text{SHA-256}(\text{UTF-8-BYTES}(\text{CanonicalLine}_i))$$

### 3.2 Tree Layer Pairwise Hashing
Let the current layer of nodes be $N_0, N_1, \dots, N_{k-1}$.
While $k > 1$:
1. Pair adjacent nodes $(N_{2j}, N_{2j+1})$.
2. If the number of nodes $k$ is **odd**, duplicate the last node $N_{k-1}$ as its own right sibling.
3. Compute parent node:
   $$P_j = \text{SHA-256}(N_{2j} \mathbin{\Vert} N_{2j+1})$$
4. Set the new layer as $P_0, P_1, \dots$ and repeat.

The final remaining single 32-byte hash is the **`PreMigrationMerkleRoot`**.

---

## 4. `snapshot-manifest.json` Schema

The `SnapshotManifest` records the repository freeze state without requiring external transparency log (Rekor) services:

```json
{
  "version": "1.0.0",
  "sha1RepoID": "old-repo-archive-v1",
  "freezeTimestamp": "2026-09-17T03:48:00Z",
  "preMigrationMerkleRoot": "64_char_hex_sha256_merkle_root",
  "totalRefTips": 10000,
  "canonicalRefTips": [
    {
      "refName": "refs/heads/main",
      "sha1Target": "40_char_hex",
      "sha256Target": "64_char_hex"
    }
  ],
  "signerPublicKeyHex": "ed25519_pubkey_hex",
  "signatureHex": "ed25519_signature_over_canonical_payload"
}
```

---

## 5. Genesis Entry Binding Formula

To cryptographically bind the `SnapshotManifest` to the new SHA-256 RSL chain (resolving Gap #2), the initial RSL entry in the SHA-256 repository MUST encode the canonical string:

$$\text{GenesisPayload} = \text{"GAP1-GENESIS-ATTESTATION|Merkle:"} \mathbin{\Vert} \text{PreMigrationMerkleRoot} \mathbin{\Vert} \text{"|Archive:"} \mathbin{\Vert} \text{sha1RepoID} \mathbin{\Vert} \text{"|Policy:"} \mathbin{\Vert} \text{SHA256InitialPolicyRoot}$$

This payload MUST be signed by the historical SHA-1 Root Keys prior to RSL log initialization.
