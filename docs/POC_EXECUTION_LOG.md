# PoC Execution Log

This document tracks the step-by-step execution and outcomes of the gittuf Hash-Agility Proof of Concept.

## Phase 0: Environment Setup & Baseline (SHA-1)
**Script:** scripts/00-env.sh and scripts/01-baseline.sh
- Pinned git, go, and gittuf versions to ensure reproducibility.
- Initialized a baseline SHA-1 git repository (work/old-repo) with 5 commits.
- Fully initialized gittuf trust and policy, adding a root key, policy key, and developer key.
- Configured rules protecting efs/heads/main.
- Validated baseline with gittuf verify-ref --verbose main which succeeded (Exit 0).

## Phase 1: Freeze and Snapshot
**Script:** scripts/02-freeze-snapshot.sh
- **OID-Only Commitment:** Computed a deterministic, privacy-safe hash over historical efs/heads/main tips, policy tips, and root key fingerprint (excluding names).
- **Snapshot Manifest:** Created rchives/snapshot-manifest.json (acting as a Rekor replacement) with schema_version, rozen_at, sl_tip, commitment_sha256, and more.
- **Root Signature:** Signed the manifest with the disposable root SSH key, verifying the signature round-trip.
- **Bundle:** Exported a full tamper-evident archive of the old SHA-1 repository as rchives/old-repo.bundle.

## Phase 2: Verification Matrix
**Script:** scripts/03-verification-matrix.sh
Executed four migration scenarios to definitively prove gittuf's security properties.

| Scenario | Description | Exit Code | Result | Key Finding |
|---|---|---|---|---|
| **A** (Baseline) | Original SHA-1 repository verification. | 0 | ✅ PASS | Baseline functions as expected. |
| **B** (Naive Copy) | SHA-256 repo with old RSL refs manually copied. | 1 | ✅ FAIL-CLOSED | Gittuf is securely fail-closed. Attempting to look up SHA-1 OIDs in a SHA-256 store yields unresolvable objects. No silent bypass occurs. |
| **C** (Fresh Chain) | SHA-256 repo with fresh gittuf initialization. | 0 | ✅ PASS | A completely clean slate works smoothly in SHA-256, provided old refs are dropped. |
| **D** (Genesis Bridge)| Fresh SHA-256 initialization linked cryptographically. | 0 | ✅ PASS | A signed genesis-bridge.json attestation is embedded in the new repo, pointing back to the commitment_sha256 of the old repo, ensuring continuity. |

## Conclusion
The experiments validate that **Approach B (Snapshot) + Genesis Bridge** is the cryptographically sound and secure path forward for SHA-1 to SHA-256 transitions in gittuf. The fail-closed nature of Scenario B confirmed there are no downgrade vulnerabilities when migrating hash schemas without translating signatures.

## Phase 3: Hash-Equivalence Attestation (Approach C)
**Script:** scripts/04-attestation.sh and scripts/04-dsse-helper.go
- **DSSE Generation:** Constructed a real HashEquivalencePayload declaring the migrated repository equivalence between SHA-1 and SHA-256 heads.
- **Signing:** Wrapped the payload in a DSSE envelope and signed the PAE via ssh-keygen -Y sign with the old SHA-1 root key.
- **Storage:** Pushed the resulting DSSE JSON to the efs/gittuf/attestations branch via native Git tree commands.
- **Verification Testing:**
  - **Positive Test:** Extracted the attestation payload directly from the ref, rebuilt the PAE, and cryptographically verified it using ssh-keygen -Y verify. The signature succeeded perfectly (Exit 0).
  - **Negative Test:** Tampered one byte of the SHA-256 target digest. Re-ran the verification which forcefully failed and rejected the payload (Exit 1).

## Phase 4: Edge Cases Probes
**Script:** scripts/05-edge.sh
- **Probe 1 (compatObjectFormat):** Attempted to verify the migrated repository using Git's native compatibility translation layer (extensions.compatObjectFormat). gittuf verify-ref forcefully rejected the repository (FAIL-CLOSED) because gittuf actively denies repositories using the compatibility object format.
- **Probe 2 (Fresh-Clone Verification):** Performed a clean git clone of the valid SHA-256 repo and ran gittuf verify-ref. Verification failed. 
  - **Finding:** A standard clone only pulls efs/heads and efs/tags. Users must explicitly fetch efs/gittuf/* to restore the cryptographic chain on a fresh clone.
- **Probe 3 (Signed Tags Retention):** Re-attempted the ast-export/ast-import migration WITHOUT stripping signatures.
  - **Finding:** Git natively and silently discarded the signed tags because mapping the signature mathematically to the new SHA-256 target is impossible.
- **Probe 4 (Snapshot Determinism):** Cloned the Phase 1 .bundle archive and re-executed the canonical algorithm from docs/snapshot-spec.md.
  - **Result:** The computed hash perfectly matched the stored snapshot-manifest.json exactly (c9c9ecfb5c61e8dcdf52c0010f2ddce33a4382c9df8ebd4a1cf723719255dee), verifying absolute determinism and third-party reproducibility.
