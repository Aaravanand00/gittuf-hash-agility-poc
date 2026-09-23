// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package gitinterface - GAP-1 Hash Agility Extension
// File: bridge.go
//
// Implements the Genesis Bridge — a cryptographically signed record that
// links the last SHA-1 RSL tip to the first SHA-256 RSL tip, enabling
// verifiers to establish a chain of trust across the hash epoch boundary.
//
// Motivation (GAP-1 / Patrick P3):
//   When a gittuf repository migrates from SHA-1 to SHA-256 object format,
//   the entire RSL history is re-written in SHA-256. Without an explicit
//   bridge, there is no verifiable link between the old and new epochs.
//
// The bridge record is stored as a JSON file in refs/gittuf/snapshots/<ts>
// and optionally anchored in Sigstore Rekor for public verifiability.

package gitinterface

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	// ErrBridgeInvalidHash is returned when either OID in a bridge is malformed.
	ErrBridgeInvalidHash = errors.New("bridge contains an invalid hash OID")

	// ErrBridgeMissingField is returned when a required bridge field is empty.
	ErrBridgeMissingField = errors.New("bridge record is missing a required field")
)

// GenesisBridgeRecord is the canonical link between a SHA-1 epoch's final
// RSL tip and the SHA-256 epoch's first RSL tip. Both OIDs must be present
// so that independent verifiers can confirm the transition.
//
// The CommitmentDigest is:
//
//	sha256("genesis-bridge" + "|" + SHA1RSLTip + "|" + SHA256RSLTip + "|" + RFC3339timestamp)
//
// This digest is what gets signed (via ssh-keygen -Y sign) and/or anchored
// in Rekor.
type GenesisBridgeRecord struct {
	SchemaVersion    string    `json:"schema_version"`
	CreatedAt        time.Time `json:"created_at"`
	SHA1RSLTip       string    `json:"sha1_rsl_tip"`
	SHA1HeadOID      string    `json:"sha1_head_oid"`
	SHA256RSLTip     string    `json:"sha256_rsl_tip"`
	SHA256HeadOID    string    `json:"sha256_head_oid"`
	CommitmentDigest string    `json:"commitment_digest"`
	Description      string    `json:"description"`
}

// BridgeVerificationResult holds the output of VerifyGenesisBridge.
type BridgeVerificationResult struct {
	SHA1RSLTip    string
	SHA256RSLTip  string
	CommitmentOK  bool
	ErrorDetail   string
}

// NewGenesisBridge creates a GenesisBridgeRecord linking the SHA-1 epoch
// (captured in sha1RSLTip, sha1HeadOID) to the SHA-256 epoch
// (sha256RSLTip, sha256HeadOID).
//
// It validates that both RSL tip OIDs are non-empty and computes the
// commitment digest that must be externally signed.
func NewGenesisBridge(
	sha1RSLTip, sha1HeadOID,
	sha256RSLTip, sha256HeadOID string,
) (*GenesisBridgeRecord, error) {
	if sha1RSLTip == "" || sha256RSLTip == "" {
		return nil, ErrBridgeMissingField
	}
	if sha1HeadOID == "" || sha256HeadOID == "" {
		return nil, ErrBridgeMissingField
	}

	now := time.Now().UTC()

	// Commitment: sha256("genesis-bridge" | sha1RSLTip | sha256RSLTip | timestamp)
	raw := fmt.Sprintf("genesis-bridge|%s|%s|%s", sha1RSLTip, sha256RSLTip, now.Format(time.RFC3339))
	h := sha256.Sum256([]byte(raw))
	commitment := hex.EncodeToString(h[:])

	return &GenesisBridgeRecord{
		SchemaVersion:    "gap1-bridge-v1",
		CreatedAt:        now,
		SHA1RSLTip:       sha1RSLTip,
		SHA1HeadOID:      sha1HeadOID,
		SHA256RSLTip:     sha256RSLTip,
		SHA256HeadOID:    sha256HeadOID,
		CommitmentDigest: commitment,
		Description:      "GAP-1 Genesis Bridge: links SHA-1 RSL epoch to SHA-256 RSL epoch for continuous chain of trust",
	}, nil
}

// VerifyGenesisBridge verifies that the CommitmentDigest in a GenesisBridgeRecord
// is internally consistent (i.e. derived from its own fields).
//
// NOTE: This does NOT verify the external signature over the record — that
// must be done separately using ssh-keygen -Y verify or Rekor lookup. This
// function only confirms that the commitment math is correct.
func VerifyGenesisBridge(bridge *GenesisBridgeRecord) *BridgeVerificationResult {
	result := &BridgeVerificationResult{
		SHA1RSLTip:   bridge.SHA1RSLTip,
		SHA256RSLTip: bridge.SHA256RSLTip,
	}

	// Re-derive the commitment
	raw := fmt.Sprintf("genesis-bridge|%s|%s|%s",
		bridge.SHA1RSLTip,
		bridge.SHA256RSLTip,
		bridge.CreatedAt.Format(time.RFC3339),
	)
	h := sha256.Sum256([]byte(raw))
	expected := hex.EncodeToString(h[:])

	if expected == bridge.CommitmentDigest {
		result.CommitmentOK = true
	} else {
		result.CommitmentOK = false
		result.ErrorDetail = fmt.Sprintf(
			"commitment mismatch: got %s, expected %s",
			bridge.CommitmentDigest, expected,
		)
	}

	return result
}

// WriteGenesisBridge serialises a GenesisBridgeRecord to a JSON file.
func WriteGenesisBridge(bridge *GenesisBridgeRecord, outputPath string) error {
	data, err := json.MarshalIndent(bridge, "", "  ")
	if err != nil {
		return fmt.Errorf("cannot marshal bridge record: %w", err)
	}
	return os.WriteFile(outputPath, data, 0o644)
}

// LoadGenesisBridge reads and parses a GenesisBridgeRecord from disk.
func LoadGenesisBridge(path string) (*GenesisBridgeRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read bridge record: %w", err)
	}
	var b GenesisBridgeRecord
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("cannot parse bridge record: %w", err)
	}
	return &b, nil
}

// GenesisBridgeSummary returns a human-readable summary for CLI output.
func GenesisBridgeSummary(b *GenesisBridgeRecord) string {
	return fmt.Sprintf(
		"Genesis Bridge (GAP-1)\n"+
			"  Created:        %s\n"+
			"  SHA-1 RSL Tip:  %s\n"+
			"  SHA-1 HEAD:     %s\n"+
			"  SHA-256 RSL Tip:%s\n"+
			"  SHA-256 HEAD:   %s\n"+
			"  Commitment:     %s\n",
		b.CreatedAt.Format(time.RFC3339),
		b.SHA1RSLTip,
		b.SHA1HeadOID,
		b.SHA256RSLTip,
		b.SHA256HeadOID,
		b.CommitmentDigest,
	)
}
