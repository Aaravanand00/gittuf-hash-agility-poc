# Gittuf Hash Agility PoC (GAP-1)

This repository demonstrates how to securely transition a gittuf-managed Git repository from SHA-1 to SHA-256 without breaking historical cryptographic signatures or relying on external transparency logs.

## Executive Summary
During a hash migration, historical signatures (like signed tags and GPG commits) are inherently tied to the byte representation of the legacy hash. Modifying them to map to a new hash breaks them permanently. This PoC implements a **Snapshot + Genesis Bridge** architecture:
1. We freeze the SHA-1 legacy state using an OID-only, privacy-preserving commitment hash.
2. We sign and archive this state mathematically.
3. We embed the legacy state into a new SHA-256 Genesis RSL entry or a Cross-Signing DSSE Attestation.
4. Edge case testing confirms this approach is ail-closed against translation attacks.

Read the full findings in [results/RESULTS.md](results/RESULTS.md).

## Requirements
- \git\ (v2.42+ with SHA-256 support)
- \gittuf\ (Available in PATH)
- \go\ (v1.20+)
- \jq\ and \wk\

## Reproduce in 5 Commands
You can reproduce the entire end-to-end proof of concept, including the cryptographic bridging and the verification edge cases using the orchestrator:

\\\ash
# 1. Clean the environment and prepare keys
bash scripts/00-env.sh

# 2. Freeze the SHA-1 repository into a signed snapshot
bash scripts/01-snapshot.sh

# 3. Test verification matrix (Naive copy, Fresh chain, Genesis bridge)
bash scripts/03-verification-matrix.sh

# 4. Generate and verify a real DSSE Hash-Equivalence Attestation
bash scripts/04-attestation.sh

# 5. Probe edge cases (compatObjectFormat, clones, signed tags)
bash scripts/05-edge.sh
\\\

Alternatively, run everything at once:
\\\ash
bash scripts/run-all.sh
\\\

## Architecture & Documentation
- \docs/snapshot-spec.md\: Canonical specification for the OID-Only commitment.
- \docs/POC_EXECUTION_LOG.md\: Full chronological execution log of all findings.
- \scripts/\: Core operational scripts.
- \esults/\: Output matrix and findings.
