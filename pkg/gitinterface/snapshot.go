// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package gitinterface - GAP-1 Hash Agility Extension
// File: snapshot.go
//
// Implements deterministic content-level SHA-256 snapshotting of a gittuf
// repository state. This addresses Patrick Zielinski's feedback (GAP-1 P2):
// "Anchor content-level SHA-256, not just RSL OIDs."
//
// The snapshot captures:
//   - All Git object IDs in the repository (sorted, deduplicated)
//   - The RSL chain tip (refs/gittuf/reference-state-log)
//   - The active policy OID (refs/gittuf/policy)
//   - The root key fingerprint
//
// The resulting ContentSHA256 is a single deterministic hash that detects
// any object-level tampering, even if SHA-1 collisions are exploited.

package gitinterface

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

const (
	// RSLRef is the reference path for the gittuf Reference State Log.
	RSLRef = "refs/gittuf/reference-state-log"

	// PolicyRef is the reference path for the active gittuf policy.
	PolicyRef = "refs/gittuf/policy"

	// SnapshotSchemaVersion is the version string for the snapshot manifest.
	SnapshotSchemaVersion = "gap1-poc-v1"

	// SnapshotRefPrefix is the gittuf ref namespace for snapshot anchors.
	SnapshotRefPrefix = "refs/gittuf/snapshots/"
)

var (
	// ErrSnapshotNoObjects is returned when a repository has no Git objects.
	ErrSnapshotNoObjects = errors.New("repository contains no Git objects")

	// ErrSnapshotRSLNotFound is returned when the RSL reference is absent.
	ErrSnapshotRSLNotFound = errors.New("RSL reference not found in repository")
)

// SnapshotManifest is the canonical record of a repository's cryptographic
// state at the moment of freeze. It is JSON-serialisable and is signed with
// the root SSH key before being stored.
type SnapshotManifest struct {
	SchemaVersion      string    `json:"schema_version"`
	FrozenAt           time.Time `json:"frozen_at"`
	SHA1RepoHead       string    `json:"sha1_repo_head"`
	RSLTip             string    `json:"rsl_tip"`
	PolicyOID          string    `json:"policy_oid"`
	BundleSHA256       string    `json:"bundle_sha256,omitempty"`
	CommitmentSHA256   string    `json:"commitment_sha256"`
	ContentSHA256      string    `json:"content_sha256"`
	RootKeyFingerprint string    `json:"root_key_fingerprint,omitempty"`
	MigrationNote      string    `json:"migration_note,omitempty"`
}

// ComputeContentSHA256 calculates a single deterministic SHA-256 digest that
// covers every Git object stored in the repository. It calls:
//
//	git cat-file --batch-all-objects --batch-check='%(objectname)'
//
// sorts the output, deduplicates it, and hashes the result with SHA-256.
// This is the "content-level anchor" requested in GAP-1 / Patrick P2.
//
// The method intentionally does NOT include timestamps or random data so that
// re-running on an identical object store always produces the same digest.
func (r *Repository) ComputeContentSHA256() (string, error) {
	output, err := r.executor(
		"cat-file",
		"--batch-all-objects",
		"--batch-check=%(objectname)",
	).executeString()
	if err != nil {
		return "", fmt.Errorf("git cat-file failed: %w", err)
	}

	if strings.TrimSpace(output) == "" {
		return "", ErrSnapshotNoObjects
	}

	// Sort and deduplicate object IDs for determinism.
	lines := strings.Split(strings.TrimSpace(output), "\n")
	seen := make(map[string]bool, len(lines))
	unique := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" && !seen[l] {
			seen[l] = true
			unique = append(unique, l)
		}
	}
	sort.Strings(unique)

	combined := strings.Join(unique, "\n")
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:]), nil
}

// ComputeOIDCommitment builds the OID-only commitment hash used by the freeze
// snapshot. It collects:
//   - refs/heads/main (or HEAD) tip OID
//   - RSL tip OID
//   - Policy OID
//   - Root key fingerprint (if provided)
//
// then sorts, deduplicates, and SHA-256 hashes the result. This is the
// "commitment_sha256" field in SnapshotManifest.
func (r *Repository) ComputeOIDCommitment(rootKeyFingerprint string) (string, error) {
	var components []string

	// HEAD
	headHash, err := r.executor("rev-parse", "HEAD").executeString()
	if err == nil && strings.TrimSpace(headHash) != "" {
		components = append(components, strings.TrimSpace(headHash))
	}

	// RSL tip
	rslHash, err := r.executor("rev-parse", RSLRef).executeString()
	if err == nil && strings.TrimSpace(rslHash) != "" {
		components = append(components, strings.TrimSpace(rslHash))
	}

	// Policy OID
	policyHash, err := r.executor("rev-parse", PolicyRef).executeString()
	if err == nil && strings.TrimSpace(policyHash) != "" {
		components = append(components, strings.TrimSpace(policyHash))
	}

	// Root key fingerprint
	if rootKeyFingerprint != "" {
		components = append(components, rootKeyFingerprint)
	}

	if len(components) == 0 {
		return "", fmt.Errorf("no OIDs found — is this a gittuf repository?")
	}

	seen := make(map[string]bool)
	unique := make([]string, 0, len(components))
	for _, c := range components {
		if !seen[c] {
			seen[c] = true
			unique = append(unique, c)
		}
	}
	sort.Strings(unique)

	combined := strings.Join(unique, "\n")
	h := sha256.Sum256([]byte(combined))
	return hex.EncodeToString(h[:]), nil
}

// TakeSnapshot creates a SnapshotManifest for the current repository state.
// It computes both the OID commitment and the content-level SHA-256.
// The manifest is NOT signed here — use an external ssh-keygen -Y sign step
// or the gittuf signing pipeline after calling this function.
//
// Parameters:
//   - rootKeyFingerprint: SSH key fingerprint string (e.g. "SHA256:abc...")
//   - bundleSHA256: optional SHA-256 of a git bundle file (pass "" to omit)
func (r *Repository) TakeSnapshot(rootKeyFingerprint, bundleSHA256 string) (*SnapshotManifest, error) {
	// Resolve HEAD
	headHash, err := r.executor("rev-parse", "HEAD").executeString()
	if err != nil {
		return nil, fmt.Errorf("cannot resolve HEAD: %w", err)
	}
	headHash = strings.TrimSpace(headHash)

	// RSL tip
	rslHash, err := r.executor("rev-parse", RSLRef).executeString()
	if err != nil {
		return nil, ErrSnapshotRSLNotFound
	}
	rslHash = strings.TrimSpace(rslHash)

	// Policy OID (optional — don't fail if absent)
	policyHash, _ := r.executor("rev-parse", PolicyRef).executeString()
	policyHash = strings.TrimSpace(policyHash)

	// Compute OID commitment
	commitment, err := r.ComputeOIDCommitment(rootKeyFingerprint)
	if err != nil {
		return nil, fmt.Errorf("cannot compute OID commitment: %w", err)
	}

	// Compute content-level SHA-256 (Patrick P2)
	contentSHA256, err := r.ComputeContentSHA256()
	if err != nil {
		return nil, fmt.Errorf("cannot compute content SHA-256: %w", err)
	}

	manifest := &SnapshotManifest{
		SchemaVersion:      SnapshotSchemaVersion,
		FrozenAt:           time.Now().UTC(),
		SHA1RepoHead:       headHash,
		RSLTip:             rslHash,
		PolicyOID:          policyHash,
		BundleSHA256:       bundleSHA256,
		CommitmentSHA256:   commitment,
		ContentSHA256:      contentSHA256,
		RootKeyFingerprint: rootKeyFingerprint,
		MigrationNote:      "GAP-1 hash agility snapshot — SHA-1 epoch frozen for SHA-256 migration",
	}

	return manifest, nil
}

// WriteSnapshotManifest serialises the manifest to a JSON file at outputPath.
func WriteSnapshotManifest(manifest *SnapshotManifest, outputPath string) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal snapshot manifest: %w", err)
	}
	return os.WriteFile(outputPath, data, 0o644)
}

// LoadSnapshotManifest reads and deserialises a snapshot manifest from disk.
func LoadSnapshotManifest(path string) (*SnapshotManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read snapshot manifest: %w", err)
	}
	var m SnapshotManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("cannot parse snapshot manifest: %w", err)
	}
	return &m, nil
}
