# Technical Audit: SHA-1 Assumptions in the Gittuf Codebase

**Authors:** Aashish Pandit (imshubham22apr-gif), Aastha Priya  
**Date:** August 2026  
**Context:** GAP-1 (Hash Agility) preparation under OJT Project Track  
**Reference Issue:** [gittuf/gittuf#104](https://github.com/gittuf/gittuf/issues/104)

---

## 1. Objective

Systematically catalog all locations across the `gittuf` codebase where the Git SHA-1 hashing algorithm (40-hex characters, 20-byte binary length) is assumed, hardcoded, or implicit. This audit establishes the baseline engineering requirements for transitioning gittuf to support SHA-256 repositories.

---

## 2. Component-by-Component Findings

### 2.1 `pkg/gitinterface/hash.go`
* **Line 52 — `ZeroHash` Constant:**
  `var ZeroHash = Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}`
  * *Assessment:* Hardcoded 20-byte array (SHA-1). In SHA-256 repositories, the zero hash sentinel is 32 bytes (64 hex zeros).
  * *Impact:* Low/Medium. Needs repository-format-aware accessor or dynamically sized zero hash.
* **Line 57 — `NewHash(str string)`:**
  * *Assessment:* Already checks both `len(str) == 40` and `len(str) == 64`.
  * *Impact:* Positive finding! The core `Hash` abstraction was designed with forward compatibility in mind.

### 2.2 `internal/rsl/rsl.go` (Reference State Log)
* **Lines 185–215 — RSL Commit Message Format:**
  * *Assessment:* The RSL stores entry details (target ref, target commit ID) directly inside the commit message of a Git commit on `refs/gittuf/reference-state-log`.
  * *Impact:* **Critical.** Because each RSL entry is a cryptographically signed Git commit, the commit body is part of the signed payload. Any attempt to dynamically or statically modify SHA-1 hashes inside RSL commit bodies to their SHA-256 counterparts instantly breaks the commit signature verification.

### 2.3 `pkg/gitinterface/commit.go`
* **Lines 67–127 — `CommitUsingSpecificKey`:**
  * *Assessment:* Relies on `go-git/v5` plumbing for creating signed commits without invoking the system Git CLI.
  * *Impact:* **High.** `go-git/v5` does not support SHA-256 object formats. When creating signed commits in a SHA-256 repository, gittuf will fail unless `go-git` is upgraded to `v6` (which includes experimental SHA-256 support) or execution falls back to invoking the system `git` CLI with signing options.

### 2.4 `internal/attestations/authorization.go`
* **Lines 140–145 — `ReferenceAuthorizationPath`:**
  * *Assessment:* Tree paths for reference authorizations are constructed by splitting Git commit hashes into two-character directory prefixes and remaining characters (e.g., `ab/cd1234...`).
  * *Impact:* **High.** The path parser logic assumes a 40-character length. While the tree partitioning works similarly for 64-character hashes, hardcoded path slicing will throw index out-of-bounds or mismatch errors if not updated.

---

## 3. Conclusions for GAP-1 Strategy

1. **In-Memory Hash Translation (Approach A) is cryptographically invalid:** The signature integrity of the RSL cannot survive hash translation without re-signing. Re-signing requires access to the original private keys of past contributors, which is impossible in open-source decentralized repositories.
2. **Snapshot + Fresh Start (Approach B) is the cleanest solution:** By declaring an epoch boundary, old SHA-1 history is sealed and anchored with a Merkle hash, while the SHA-256 repository begins with fresh, forward-compatible TUF roots.
3. **Cross-Signing Attestations (Approach C) provides optional backwards verification:** Maintainers can bridge the gap using in-toto statements stored outside the original commit chain.
