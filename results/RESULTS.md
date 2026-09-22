# Gittuf Hash Agility (GAP-1) PoC Results

## Executive Summary
This PoC successfully demonstrates that `gittuf` can migrate across cryptographic hash boundaries (SHA-1 to SHA-256) securely without modifying historical repository signatures. We established a fully deterministic, privacy-preserving, Rekor-free snapshot architecture to anchor legacy states. Edge case testing confirms that `gittuf` inherently defends against translation layer attacks, ensuring a strict fail-closed security posture during migrations.

## Verification Matrix

| Scenario | Description | Expected | Actual | Exit Code |
| :--- | :--- | :--- | :--- | :--- |
| **A: Baseline** | Original SHA-1 `gittuf` repository | PASS | **PASS** | 0 |
| **B: Naive Copy** | Fast-exported to SHA-256; `refs/gittuf` copied | FAIL | **FAIL** | 1 |
| **C: Fresh Chain** | Fresh SHA-256 repo (No historical state) | PASS | **PASS** | 0 |
| **D: Genesis Bridge** | Fresh SHA-256 repo + RSL Genesis link to SHA-1 | PASS | **PASS** | 0 |
| **E: Attestation** | Cross-Signing DSSE mapping SHA-1 to SHA-256 | PASS | **PASS** | 0 |

## Naive Migration Verdict (Scenario B)
**Verdict: FAIL-CLOSED (Secure)**
When performing a naive migration where `refs/gittuf/*` are copied to a SHA-256 repository without mapping, `gittuf` attempts to resolve the legacy 40-character SHA-1 target IDs stored in the RSL entries. Because those IDs do not exist in the new SHA-256 object store (and cannot be natively translated without mapping features), `gittuf verify-ref` forcefully errors out and fails. This represents a secure **fail-closed** posture, preventing attackers from stripping signatures through uncertified algorithm downgrades.

## Rekor-Free Anchoring
**What replaced it:** A deterministic, OID-Only Commitment Algorithm + Root Key Signature + Immutable Archive Bundle.
**Why:** The initial PoC proposed anchoring the final SHA-1 state in the public Sigstore/Rekor transparency log. However, corporate or private Git repositories cannot leak their existence, branch names, or OIDs to a public transparency log. By computing a reproducible hash of all repository tips (sorted and deduplicated) and generating a `snapshot-manifest.json` signed by the offline root key, third parties can mathematically audit the freeze boundary privately.

## `compatObjectFormat` Findings
When enabling Git's experimental backward-compatibility layer (`extensions.compatObjectFormat sha1`), native Git commands (like `git cat-file`) can dynamically resolve old 40-character OIDs. However, `gittuf verify-ref` explicitly rejects the repository, stating:
> `Error: gittuf does not support repositories with extensions.compatObjectFormat enabled: compat object format is set to 'sha1'`

This strict rejection is optimal: it prevents ambiguous object resolution attacks where an attacker might exploit the translation layer to trick the verifier into accepting a weak collision.

## Recommendations for GAP-1
1. **Abandon "Approach A" (Rewrite):** Do not attempt to rewrite historical commit signatures or RSL text. It breaks cryptographic signatures (like signed tags) permanently and irreversibly.
2. **Adopt Snapshot + Genesis (Approach B/D):** Implement the OID-Only Commitment hash logic natively in `gittuf snapshot` to mathematically freeze legacy states. Use the resulting hash as a Genesis entry in the new hash chain.
3. **Formalize Hash-Equivalence Attestations (Approach C):** Integrate `https://gittuf.dev/predicate/hash-equivalence/v1` natively into `gittuf verify-ref`. When the verifier hits an epoch boundary, it should fetch this attestation to bridge the history between the old and new chain.
4. **Enforce `refs/gittuf/*` fetching during cloning:** A fresh clone does not fetch gittuf namespaces by default. Add documentation or native `gittuf clone` wrapping to ensure users fetch the verification chain, otherwise post-migration repositories will instantly fail verification on fresh machines.

## Open Questions for Maintainers
- Should the `hash-equivalence` attestation be stored in `refs/gittuf/attestations`, or should it reside directly in the RSL as a specialized `EpochTransitionEntry` to ensure it is always fetched?
- Will `gittuf verify-ref` eventually support `compatObjectFormat` for legacy verification, or will the ban remain permanent to enforce absolute object distinction?
- How should the CLI interface for `gittuf snapshot` behave? Should it output the raw canonical commitment stream to `stdout` for transparency before hashing?

