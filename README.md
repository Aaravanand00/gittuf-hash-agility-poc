# gittuf GAP-1 (Hash Agility) Proof of Concept

**Authors:** Aashish Pandit (GitHub: @imshubham22apr-gif), Aarav Anand, Aastha Priya  
**Date:** September 2026  
**Context:** Empirical evaluation of Git SHA-1 -> SHA-256 migration strategies in gittuf for maintainers (Paulo Gomes, Patrick Zielinski).  
**Issue Tracking:** [gittuf/gittuf#104](https://github.com/gittuf/gittuf/issues/104) | [GAP-1 Specification](https://github.com/gittuf/gittuf/blob/main/docs/gaps/1/README.md)

---

## 1. Executive Summary

Git is actively transitioning from SHA-1 to SHA-256. Gittuf relies on signed metadata (the Reference State Log / RSL and TUF policies) containing embedded Git object hashes. Historical signatures are tied to the byte representation of the legacy hash, so rewriting those hashes to point at SHA-256 objects breaks the signatures permanently.

This Proof of Concept (PoC) evaluates three architectural solutions to hash agility:

```
                          +--------------------------+
                          |   SHA-1 Git Repository   |
                          |   (gittuf initialized)   |
                          +--------------------------+
                                        |
                         [ Migration to SHA-256 Repo ]
                                        |
           +----------------------------+----------------------------+
           |                            |                            |
           v                            v                            v
  [ Approach A ]               [ Approach B ]               [ Approach C ]
In-Memory Translation      Snapshot + Fresh Start       Cross-Signing Attestation
 (The Epoch System)         (Paulo's Route)              (The Provenance Bridge)
 REJECTED                   PRIMARY RECOMMENDATION       OPTIONAL BRIDGE
 Signatures permanently     Clean epoch boundary, zero   in-toto DSSE statements
 break when translating     debt, signed OID-only        attest hash equivalence
                            commitment + archive bundle
```

The recommended architecture is **Snapshot + Genesis Bridge**:

1. Freeze the SHA-1 legacy state behind an OID-only, privacy-preserving commitment hash.
2. Sign that commitment with the offline root key and archive the repository as a bundle.
3. Bind the legacy state into the new SHA-256 chain, either as a genesis RSL entry or as a cross-signing DSSE attestation.
4. Verify the boundary is fail-closed against translation attacks.

Full empirical findings: [results/RESULTS.md](results/RESULTS.md).

---

## 2. Approach Analysis & Empirical Results

### Approach A: In-Memory Translation Layer (The Epoch System)
* **Design:** Retain SHA-1 metadata unchanged and dynamically translate hashes to SHA-256 in memory via Git's `compatObjectFormat`.
* **Empirical Result:** **REJECTED.**
* **Root Cause:** In gittuf, RSL Reference Entries are **signed Git commit objects** where the `targetID: <sha1_hash>` is serialized directly into the commit message. Even if object lookups are mapped dynamically in-memory, **digital signature verification permanently fails** because the signed commit text contains the original SHA-1 hex string. Modifying the text invalidates the cryptographic signature.
* **Additional finding:** `gittuf verify-ref` explicitly rejects any repository with `extensions.compatObjectFormat` enabled, so this path is closed at the tool level as well as the cryptographic one.

### Approach B: Freeze + Snapshot + Fresh Start (Paulo's Path)
* **Design:** Treat migration as a hard epoch boundary.
  1. Freeze the SHA-1 repository.
  2. Compute a deterministic commitment over all migrated ref tips plus the gittuf RSL and policy tips.
  3. Export and sign a `snapshot-manifest.json`, and archive the old repository as a Git bundle whose hash is recorded in the manifest.
  4. Initialize fresh gittuf metadata in the SHA-256 repository.
* **Empirical Result:** **RECOMMENDED AS PRIMARY STRATEGY.**
* **Strengths:** Cleanest codebase, zero runtime translation overhead, zero technical debt. The `pkg/gitinterface.Hash` type is already forward-compatible.
* **Note on anchoring:** an earlier draft anchored the snapshot in a public transparency log (Sigstore / Rekor). Following maintainer feedback this is **not** a hard requirement: private repositories cannot leak ref names or OIDs to a public log. The PoC therefore uses an OID-only commitment (no ref names) signed by the root key, with the archive bundle hash recorded in the manifest. See [docs/snapshot-spec.md](docs/snapshot-spec.md) for the canonical, reproducible hash formula.

### Approach C: Cross-Signing in-toto Attestations (The Bridge)
* **Design:** Leverage gittuf's native `internal/attestations` subsystem (`refs/gittuf/attestations`).
  1. Maintainers sign an in-toto DSSE statement declaring cryptographic equivalence between pre-migration SHA-1 commits and post-migration SHA-256 commits.
  2. The verifier queries this attestation when traversing historical commits.
* **Empirical Result:** **VIABLE & COMPLEMENTARY.**
* **Strengths:** Preserves historical signatures 100% intact while enabling unbroken provenance across the hash boundary.

---

## 3. Verification Matrix

| Scenario | Description | Expected | Actual | Exit Code |
| :--- | :--- | :--- | :--- | :--- |
| **A: Baseline** | Original SHA-1 gittuf repository | PASS | **PASS** | 0 |
| **B: Naive Copy** | Fast-exported to SHA-256; `refs/gittuf/*` copied | FAIL | **FAIL** | 1 |
| **C: Fresh Chain** | Fresh SHA-256 repo (no historical state) | PASS | **PASS** | 0 |
| **D: Genesis Bridge** | Fresh SHA-256 repo + RSL genesis link to SHA-1 | PASS | **PASS** | 0 |
| **E: Attestation** | Cross-signing DSSE mapping SHA-1 to SHA-256 | PASS | **PASS** | 0 |

Scenario B is the security-critical one: a naive migration **fails closed**. gittuf tries to resolve the legacy 40-character target IDs recorded in the RSL, cannot find them in the SHA-256 object store, and errors out rather than silently accepting the unverified history.

---

## 4. Running the PoC Locally

### Original Go experiments

```bash
go run .
# Or run test suite:
go test -v .
```

* **Phase 1:** Initializes dummy SHA-1 repo with 3 commits and logs 3 RSL entries.
* **Phase 2:** Converts to SHA-256 repo and captures native object resolution failure (`fatal: Not a valid object name`).
* **Phase 3:** Tests Approach A (translation) and documents signature breakdown.
* **Phase 4:** Tests Approach B (snapshot) and produces `snapshot-manifest.json`.
* **Phase 5:** Tests Approach C (attestations) and produces `hash-equivalence-attestation.json`.

### End-to-end script pipeline

Requirements: `git` (v2.42+, with SHA-256 support), `gittuf` on `PATH`, `go` (v1.20+), plus `jq` and `awk`.

```bash
# Phase 0 - pin tool versions and build the SHA-1 baseline repo
bash scripts/00-env.sh
bash scripts/01-baseline.sh

# Phase 1 - freeze the SHA-1 repository into a signed, OID-only snapshot
bash scripts/02-freeze-snapshot.sh

# Phase 2 - verification matrix (naive copy, fresh chain, genesis bridge)
bash scripts/03-verification-matrix.sh

# Phase 3 - generate and verify a real DSSE hash-equivalence attestation
bash scripts/04-attestation.sh

# Phase 4 - edge cases (compatObjectFormat, fresh clones, signed tags)
bash scripts/05-edge.sh
```

Or run every phase through the orchestrator (supports `--skip-phase-N`):

```bash
bash scripts/run-all.sh
```

Raw output and exit codes for every phase land in [results/](results/).

---

## 5. Codebase Audit Findings

| File / Component | Status | Impact on Migration |
| :--- | :---: | :--- |
| `pkg/gitinterface/hash.go:57` | `NewHash()` accepts 40-char (SHA-1) and 64-char (SHA-256) | **Forward-compatible:** Core hash abstraction is already algorithm-agnostic. |
| `pkg/gitinterface/hash.go:52` | `ZeroHash` is hardcoded to 20 zero bytes (SHA-1) | **Action item:** Must be updated to be repository-format aware. |
| `internal/rsl/rsl.go` | RSL commit messages contain `targetID: <hash>` in signed text | **Key finding:** Confirms why translation layer cannot preserve signatures. |
| `pkg/gitinterface/commit.go:67` | `CommitUsingSpecificKey` uses `go-git` v5 (SHA-1 only) | **Action item:** Use Git CLI signing or upgrade to `go-git` v6 for SHA-256. |
| `internal/attestations/authorization.go:140` | `ReferenceAuthorizationPath()` embeds hash hex in tree paths | **Action item:** Must decouple path parser from fixed SHA-1 length. |

---

## 6. Artifact Schemas

### Snapshot Manifest (`snapshot-manifest.json`)
```json
{
  "schema_version": "gap1-poc-v1",
  "frozen_at": "2026-09-10T13:30:40Z",
  "sha1_repo_head": "e9afffcce72f4dad92289589f980d5840b4d100b",
  "rsl_tip": "d00b97620b6dfcea58d32bc18415d5aac41f9c13",
  "policy_oid": "8c1f0a2b6d4e9f37b5a0c8d1e2f3a4b5c6d7e8f9",
  "bundle_sha256": "b6f1c2d3e4a5968778695a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d",
  "commitment_sha256": "ae385e9bbfc57e9f3ca375de9e1fa0b4b85e3a67827c58f0c61a44ea3af7a9bb",
  "root_key_fingerprint": "SHA256:0ynJqXoQyR0d0Yl4JmX0J3Zt2nJx7V8p9Q1sT4uW5cE",
  "migration_note": "Repository frozen for SHA-1->SHA-256 migration. Old history verifiable via this manifest."
}
```

The manifest is signed with the root key via `ssh-keygen -Y sign`; the commitment covers object IDs only (no ref names), so it can be published or shared without disclosing branch or tag names.

### In-Toto Hash Equivalence Attestation (`hash-equivalence-attestation.json`)
```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "eyJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YxIiwgInByZWRpY2F0ZVR5cGUiOiAiaHR0cHM6Ly9naXR0dWYuZGV2L3ByZWRpY2F0ZS9oYXNoLWVxdWl2YWxlbmNlL3YxIn0...",
  "signatures": [
    {
      "keyid": "root-maintainer-key-1",
      "sig": "5a7f920bc8b603..."
    }
  ]
}
```

---

## 7. Recommended Action Plan for GAP-1

1. **Do not attempt Approach A.** Rewriting historical commit signatures or RSL text breaks signatures permanently and irreversibly.
2. **Adopt Approach B as the canonical migration standard** for `gittuf migrate sha256`, implementing the OID-only commitment natively so the freeze boundary is reproducible by any third party.
3. **Support Approach C attestations** for repositories requiring cryptographic bridge verification across archives. Formalize `https://gittuf.dev/predicate/hash-equivalence/v1` in `gittuf verify-ref` so the verifier bridges epochs at the boundary.
4. **Fix `ZeroHash`** in `pkg/gitinterface/hash.go` to dynamically respect `core.repositoryformatversion`.
5. **Ensure `refs/gittuf/*` is fetched on clone.** A fresh clone does not fetch gittuf namespaces by default, so post-migration repositories fail verification on a clean machine until they are fetched explicitly.

---

## 8. Documentation

* [docs/snapshot-spec.md](docs/snapshot-spec.md) - canonical specification for the OID-only commitment.
* [docs/POC_EXECUTION_LOG.md](docs/POC_EXECUTION_LOG.md) - chronological execution log of all findings.
* [results/RESULTS.md](results/RESULTS.md) - verification matrix, verdicts, and open questions for maintainers.
* [AUDIT.md](AUDIT.md) - gittuf codebase audit notes.
