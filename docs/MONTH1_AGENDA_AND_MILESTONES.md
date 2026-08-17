# On-the-Job Training (OJT) — First Month Agenda & Milestones

**Project Track:** Open Source Software Supply Chain Security & Cryptographic Agility  
**Project:** [gittuf](https://github.com/gittuf/gittuf) (Linux Foundation / OpenSSF)  
**Trainee / Contributor:** Shubham Chauhan (imshubham22apr-gif)  
**Evaluation Period:** 16th August 2026 – 15th September 2026 (First Month)  
**Submission Deadline:** 16th September 2026  

---

## 1. Project Track & Context Overview

`gittuf` provides a security layer for Git repositories, bringing cryptographic verification, authorization policies, and access controls grounded in The Update Framework (TUF) and in-toto attestations directly to Git workflows.

As the broader Git ecosystem transitions from SHA-1 to SHA-256 object formatting to defend against collision attacks (e.g., SHAttered, SHA-1 DC), security-critical tooling built on top of Git must support cryptographic hash agility without compromising existing signature chains.

This OJT milestone focuses on **GAP-1 (Gittuf Augmentation Proposal 1): Hash Agility (Issue #104)**: researching, auditing, prototyping, and empirically validating migration strategies for transitioning repositories and Gittuf cryptographic metadata from SHA-1 to SHA-256.

---

## 2. First Month OJT Agenda & Weekly Breakdown

```
Week 1 (Aug 16 - Aug 22): Onboarding, Spec Study & GAP-1 Scoping
    ├── Study gittuf core concepts: RSL, TUF Root of Trust, in-toto Attestations
    ├── Analyze Git SHA-256 transition specifications and compatObjectFormat
    └── Scope GAP-1 Hash Agility architectural challenge (Issue #104)

Week 2 (Aug 23 - Aug 29): Codebase Audit & Experimental Scaffolding
    ├── Systematic audit of gittuf codebase for SHA-1 hardcoding
    ├── Identify friction points in pkg/gitinterface, internal/rsl, internal/attestations
    └── Scaffold dual-format test repository harness and migration plumbing

Week 3 (Aug 30 - Sep 06): Core Experiments (Approach A & Approach B)
    ├── Implement Experiment A: In-memory hash translation layer
    ├── Empirically capture cryptographic signature invalidation in RSL commit messages
    ├── Implement Experiment B: Freeze + Merkle Snapshot + Fresh Start (Paulo's Path)
    └── Implement deterministic RSL Merkle chain hashing and SnapshotManifest export

Week 4 (Sep 07 - Sep 15): Approach C Bridge, CLI Runner, Unit Tests & Findings Synthesis
    ├── Implement Experiment C: Cross-Signing in-toto DSSE attestations bridge
    ├── Build unified evaluation CLI runner with interactive reporting
    ├── Author automated unit tests for manifest serialization and chain hashing
    └── Deliver comprehensive Month 1 Learning & Progress Report for maintainers
```

---

## 3. Milestone Deliverables Summary

| Milestone | Deliverable | Status |
| :--- | :--- | :---: |
| **M1.1: Spec & Problem Scoping** | GAP-1 technical problem formulation and architectural constraints document | Completed |
| **M1.2: Codebase Audit** | Comprehensive audit report identifying SHA-1 assumptions across `pkg/` and `internal/` | Completed |
| **M1.3: Test Environment Scaffolding** | Automated Go harness creating synchronized SHA-1 and SHA-256 test repos with RSL state | Completed |
| **M1.4: Experiment A (Translation)** | Prototype demonstrating why in-memory hash translation breaks signed RSL entries | Completed |
| **M1.5: Experiment B (Snapshot)** | Implementation of deterministic RSL Merkle chain hashing and `SnapshotManifest` | Completed |
| **M1.6: Experiment C (Attestation)** | DSSE in-toto hash-equivalence attestation prototype preserving historical provenance | Completed |
| **M1.7: Evaluation Suite & Reports** | Multi-experiment CLI runner, unit test suite, and final findings documentation | Completed |

---

## 4. Key Performance Indicators (KPIs) & Evaluation Criteria

1. **Depth of Technical Understanding:** Demonstrated mastery of Git plumbing, TUF policy delegation, DSSE signatures, and SHA-256 compatibility.
2. **Empirical Rigor:** Concrete experimental validation of competing architectural hypotheses rather than theoretical conjecture.
3. **Actionable Upstream Contribution:** Deliverables directly aligned with community roadmap (gittuf/gittuf#104) ready for review by project maintainers (Paulo Gomes, Patrick Zielinski).
4. **Code Quality & Verification:** Production-grade Go idioms, zero regressions, and complete unit test coverage.
