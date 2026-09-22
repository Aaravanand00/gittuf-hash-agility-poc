# OJT First Month Milestone: Learning, Progress & Project Development Report

**Trainee Names:** Aashish Pandit, Aarav Anand, Aastha Priya  
**GitHub Username (Aashish Pandit):** [imshubham22apr-gif](https://github.com/imshubham22apr-gif)  
**Assigned Project Track:** Open Source Software Supply Chain Security & Cryptographic Agility  
**Project:** [gittuf](https://github.com/gittuf/gittuf) (Linux Foundation / OpenSSF)  
**Evaluation Period:** 16th August 2026 – 15th September 2026  
**Submission Date:** 16th September 2026  

---

## 1. Executive Summary

During the first month of On-the-Job Training (OJT), my work centered on solving a foundational architectural challenge in modern software supply chain security: **Cryptographic Hash Agility (GAP-1 / Issue #104)** in the `gittuf` project.

As Git transitions upstream from SHA-1 (160-bit) to SHA-256 (256-bit) to guard against collision vulnerabilities (e.g., SHAttered and SHA-1 Chosen-Prefix Collisions), security systems like Gittuf—which sign and attest Git object references—must transition gracefully without breaking historical verification or compromising decentralized trust.

Over the last 4 weeks, I completed:
1. An exhaustive codebase audit identifying SHA-1 assumptions across Gittuf subsystems.
2. A comprehensive experimental test harness simulating dual SHA-1 and SHA-256 repository migrations.
3. Empirical implementation and rigorous cryptographic evaluation of three migration architectures:
   * **Approach A (In-Memory Hash Translation Layer):** Proved mathematically and practically unviable due to signature breakage on signed RSL commit messages.
   * **Approach B (Snapshot + Fresh Start - Paulo's Route):** Validated as the **Primary Production Recommendation**, creating a Merkle-anchored snapshot boundary.
   * **Approach C (Cross-Signing in-toto Attestations):** Validated as a **Complementary Provenance Bridge** preserving deep historical verification.
4. Comprehensive unit test coverage and automated reporting tooling.

---

## 2. Weekly Activities & Milestones Achieved

### Week 1 (16 Aug – 22 Aug 2026): Onboarding & Architectural Foundations
* Deep dive into Gittuf's security architecture:
  * Studied the **Reference State Log (RSL)**: an append-only, tamper-evident Git namespace (`refs/gittuf/reference-state-log`) recording all reference changes.
  * Explored **The Update Framework (TUF)** metadata hierarchy: Root, Targets, Delegations, and Policies governing repository state transitions.
  * Examined **in-toto DSSE (Dead Simple Signing Envelope)** specifications for cryptographic attestations.
* Analyzed upstream Git specifications: Git object format transition document, loose object headers, commit object serialization, and `compatObjectFormat` mechanics.
* Formulated the scope and research questions for GAP-1 (Gittuf Issue #104).

### Week 2 (23 Aug – 29 Aug 2026): Codebase Audit & Experimental Scaffolding
* Conducted a file-by-file audit of `pkg/gitinterface/`, `internal/rsl/`, `internal/attestations/`, and `internal/policy/`.
* Discovered critical findings:
  * `pkg/gitinterface/hash.go`: `ZeroHash` is hardcoded to 20 zero bytes, while `NewHash()` is already forward-compatible.
  * `pkg/gitinterface/commit.go`: Employs `go-git/v5` which lacks SHA-256 plumbing support.
  * `internal/attestations/authorization.go`: Tree path slicing expects fixed 40-character SHA-1 lengths.
* Engineered the experimental test harness in Go (`experimental/hash-agility-poc/`), providing automated setup of SHA-1 repositories with initial commits and RSL tracking.
* Implemented repository migration plumbing using `git fast-export` and `git fast-import` to convert repositories to native SHA-256.

### Week 3 (30 Aug – 06 Sep 2026): Core Experiments (Approach A & B)
* **Experiment A Implementation:** Built dynamic translation layer evaluating whether SHA-1 hashes inside RSL entries could be dynamically translated via Git's compatibility mappings.
  * *Result:* ❌ **REJECTED.** Formally demonstrated that because RSL entries are cryptographically signed Git commits containing `targetID: <sha1_hash>` in the commit payload, rewriting or substituting hashes causes digital signature verification to fail permanently.
* **Experiment B Implementation:** Built the "Snapshot + Fresh Start" epoch migration system.
  * Implemented deterministic RSL Merkle chain hashing across historical entries.
  * Implemented `SnapshotManifest` generation, serializing repository freeze points, head commits, and tamper-evident chain roots.
  * Validated that fresh Gittuf initialization on SHA-256 repositories functions with zero runtime translation debt.

### Week 4 (07 Sep – 15 Sep 2026): Approach C, CLI Runner, Unit Tests & Synthesis
* **Experiment C Implementation:** Prototyped the in-toto DSSE cross-signing attestation bridge.
  * Leveraged `refs/gittuf/attestations` to issue cryptographic equivalence statements linking SHA-1 commit hashes to corresponding SHA-256 hashes without modifying historical commits.
* Integrated all experiments into a unified CLI test runner (`go run ./experimental/hash-agility-poc/`) with automated markdown and terminal reporting.
* Authored automated Go unit tests (`poc_test.go`) validating manifest serialization, Merkle chain computation, and finding aggregations.
* Synthesized empirical findings into a formal maintainer proposal for Paulo Gomes and Patrick Zielinski.

---

## 3. Key Learnings & Technical Competencies Acquired

1. **Applied Cryptography & Supply Chain Security:**
   * Practical application of TUF delegation models, root rotation, and threshold signatures.
   * Cryptographic implications of SHA-1 length extension attacks and collision resistance vs SHA-256.
   * in-toto attestation schemas and DSSE signing mechanics.
2. **Git Object Model Internals:**
   * Low-level Git object storage: blob, tree, commit, and tag serialization.
   * Inter-format repository migration mechanics (`compatObjectFormat`, `fast-export`, `fast-import`).
   * Git reference namespaces (`refs/heads`, `refs/gittuf/reference-state-log`, `refs/gittuf/attestations`).
3. **Golang Systems Engineering:**
   * Advanced Go concurrency, process execution piping, and stdin/stdout streaming for Git CLI interop.
   * JSON schema design and deterministic Merkle tree hashing algorithms.
   * Unit testing and test isolation using `t.TempDir()`.
4. **Open Source Collaboration & Contribution:**
   * Working within Linux Foundation / OpenSSF guidelines.
   * Writing formal architectural proposals (GAPs) backed by empirical proof rather than assumptions.

---

## 4. Empirical Evaluation Results

```
============================================================
  GAP-1 HASH AGILITY PoC — FINDINGS SUMMARY
============================================================
Approach A (In-Memory Translation)       : REJECTED ❌
  - Cryptographic signatures break on modified RSL commit text
  - Dynamic object lookup insufficient for signed payloads

Approach B (Snapshot + Fresh Start)      : RECOMMENDED (PRIMARY) ✅
  - Clean epoch boundary
  - Merkle-anchored SnapshotManifest (anchorable to Rekor)
  - Zero runtime overhead and zero technical debt

Approach C (Cross-Signing Attestation)   : VIABLE (COMPLEMENTARY) ✨
  - in-toto DSSE statements provide provenance bridge
  - Preserves 100% of historical signatures untouched
============================================================
```

---

## 5. Month 2 Roadmap & Next Steps

1. **Upstream Review:** Present the GAP-1 PoC and findings report to Gittuf maintainers (Paulo Gomes & Patrick Zielinski) via GitHub Issue #104.
2. **Production CLI Implementation:** Implement the `gittuf migrate sha256` subcommand based on the Experiment B architecture.
3. **Rekor Transparency Log Integration:** Implement automated submission of the `SnapshotManifest` to Sigstore/Rekor to provide public, immutable proof of repository freeze points.
4. **`go-git` Compatibility:** Coordinate upgrade to `go-git/v6` or complete Git CLI signing fallback to support native SHA-256 signing.
