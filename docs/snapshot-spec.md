# Canonical Specification: Pre-Migration Snapshot & OID-Only Commitment Formula

**Version:** 1.1.0 (GAP-1 Extended PoC)  
**Status:** Canonical Specification  
**Purpose:** Resolves Gap #3 by defining an unambiguous, deterministic, privacy-safe, language-agnostic hash formula for `gittuf` pre-migration repository state snapshots.

---

## 1. Overview & Security Goals

During a Git repository migration from SHA-1 to SHA-256, `gittuf` preserves historical signature and policy continuity by freezing the legacy repository state at an epoch boundary.

To anchor this frozen state without introducing external transparency log dependencies (e.g., Rekor), the maintainer computes an **OID-Only Commitment**:
1. **Privacy-Safe (No Reference Names):** Does not expose internal branch or tag naming schemes in the commitment payload.
2. **Deterministic & Language-Agnostic:** Any verifier using Git, Go, Rust, Python, or standard POSIX shell tools produces byte-for-byte identical output.
3. **Cryptographically Bound:** Anchors content tips, RSL log state, active policy state, and root key identity.

---

## 2. Canonical Inputs

The commitment set $S$ contains the following items:
1. **Migrated Branch and Tag Tips:** The Git object IDs (OIDs) of all heads and tags present at the freeze boundary (`git show-ref --heads --tags | awk '{print $1}'`).
2. **RSL Tip OID:** The Git object ID of the latest entry on the Reference State Log (`git rev-parse refs/gittuf/reference-state-log`).
3. **Policy OID:** The Git object ID of the active policy state (`git rev-parse refs/gittuf/policy`).
4. **Root Key Fingerprint:** The standard OpenSSH public key SHA-256 fingerprint of the legacy root of trust key (`ssh-keygen -l -f keys/root.pub | awk '{print $2}'`, formatted as `SHA256:<base64_hash>`).

---

## 3. Serialization & Sorting Rules

1. **Item Formatting:**
   - Git OIDs MUST be represented as lowercase 40-character hexadecimal strings.
   - The Root Key Fingerprint MUST retain its exact OpenSSH representation: prefix `SHA256:` followed by standard unpadded base64.
2. **Deduplication:** Any duplicate entries MUST be removed.
3. **Canonical Sorting Order:**
   - All entries MUST be sorted in strictly ascending lexicographical order based on raw byte values (POSIX C-locale / ASCII byte order).
   - In shell implementations: `LC_ALL=C sort -u`.
4. **Encoding & Delimiters:**
   - Plain UTF-8 encoded text.
   - Each item MUST be terminated by a single Unix newline character (`\n`, `0x0A`).
   - No carriage returns (`\r`, `0x0D`) are permitted.

*Example sorted commitment payload (`work/oid-commitment.txt`):*
```
5a7fea3522fbef360e922164f27739d9a6195767
SHA256:3IKLsLQeQ3fM+zR3++q7ZX7mCuUt6vttO1jm0/LUUF0
a89bb1da5f74415ebb7a543377484159ef868ed1
d2811b27ad214ca726979c6cfa4c8531f835e656
e02537180f5c17c7c32542ce643cb953a660d67d
```

---

## 4. Hash Computation Formula

The commitment hash is the single-pass SHA-256 digest over the canonical byte stream:

$$\text{CommitmentSHA256} = \text{SHA-256}\left(\text{UTF-8-BYTES}\left(\text{Line}_1 \mathbin{\Vert} \text{"\n"} \mathbin{\Vert} \dots \mathbin{\Vert} \text{Line}_n \mathbin{\Vert} \text{"\n"}\right)\right)$$

The resulting 32-byte digest MUST be formatted as a 64-character lowercase hexadecimal string.

---

## 5. `snapshot-manifest.json` Schema

The commitment hash, metadata, and repository archive fingerprint are serialized to `archives/snapshot-manifest.json`:

```json
{
  "schema_version": "gap1-poc-v1",
  "frozen_at": "2026-09-17T01:24:14Z",
  "sha1_repo_head": "e02537180f5c17c7c32542ce643cb953a660d67d",
  "rsl_tip": "5a7fea3522fbef360e922164f27739d9a6195767",
  "policy_oid": "a89bb1da5f74415ebb7a543377484159ef868ed1",
  "bundle_sha256": "acfc8520deb282871c637b509aee40a165e9a9054f0820398b0ac20547993c0d",
  "commitment_sha256": "bc9c9ecfb5c61e8dcdf52c0010f2ddce33a4382c9df8ebd4a1cf723719255dee",
  "root_key_fingerprint": "SHA256:3IKLsLQeQ3fM+zR3++q7ZX7mCuUt6vttO1jm0/LUUF0"
}
```

---

## 6. Root Key Signature & Optional RFC 3161 Timestamp

1. **Digital Signature:**
   - The manifest file is signed with the legacy Root SSH key using OpenSSH file signing:
     ```bash
     ssh-keygen -Y sign -f keys/root -n file archives/snapshot-manifest.json
     ```
   - Produces `archives/snapshot-manifest.json.sig`.
2. **Signature Verification:**
   - Verifiers validate the signature using the root public key in an `allowed_signers` file:
     ```bash
     ssh-keygen -Y verify -f allowed_signers -I root-key -n file -s archives/snapshot-manifest.json.sig < archives/snapshot-manifest.json
     ```
3. **External Proof of Time (RFC 3161):**
   - An optional timestamp token (`archives/snapshot-manifest.tsr`) may be acquired from a public Time Stamping Authority (e.g., freetsa.org) to establish a trusted freeze time without relying on a centralized transparency log.