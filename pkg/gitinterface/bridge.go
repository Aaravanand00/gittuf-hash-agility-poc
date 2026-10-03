// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

// Package gitinterface - GAP-1 Hash Agility Extension
// File: bridge.go
//
// Implements the Genesis Bridge — a cryptographically signed record that
// links the last SHA-1 RSL tip to the first SHA-256 RSL tip, enabling
// verifiers to establish a chain of trust across the hash epoch boundary.
//
// Commitment formula:
//
//	sha256("genesis-bridge|sha1|<sha1RSLTip>|<sha1HeadOID>|<sha256RSLTip>|<sha256HeadOID>|<RFC3339timestamp>")
//
// The CommitmentDigest is signed using an SSH private key (sshsig format,
// namespace "gittuf-bridge"). The resulting armored signature and the signer's
// raw SSH public key are embedded in the JSON record so that any verifier
// can independently re-derive and check the signature without needing a
// separate allowed_signers file — they only need the bridge JSON itself.

package gitinterface

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hiddeco/sshsig" //nolint:staticcheck
	"golang.org/x/crypto/ssh"
)

const (
	// bridgeSigNamespace is the sshsig namespace used when signing/verifying
	// the Genesis Bridge commitment digest. Using a distinct namespace prevents
	// signatures created for git commits from being accepted here and vice-versa.
	bridgeSigNamespace = "gittuf-bridge"
)

var (
	// ErrBridgeInvalidHash is returned when either OID in a bridge is malformed.
	ErrBridgeInvalidHash = errors.New("bridge contains an invalid hash OID")

	// ErrBridgeMissingField is returned when a required bridge field is empty.
	ErrBridgeMissingField = errors.New("bridge record is missing a required field")

	// ErrBridgeNotSigned is returned when signature verification is requested
	// but the bridge record carries no embedded signature.
	ErrBridgeNotSigned = errors.New("bridge record has no embedded signature")

	// ErrBridgeSignatureInvalid is returned when the SSH signature over the
	// commitment digest fails verification.
	ErrBridgeSignatureInvalid = errors.New("bridge SSH signature verification failed")
)

// GenesisBridgeRecord is the canonical link between a SHA-1 epoch's final
// RSL tip and the SHA-256 epoch's first RSL tip.
//
// JSON fields:
//   - schema_version    — "gap1-bridge-v1"
//   - created_at        — RFC3339 UTC timestamp of migration freeze
//   - sha1_rsl_tip      — final RSL tip in the SHA-1 epoch
//   - sha1_head_oid     — HEAD commit OID in the SHA-1 epoch
//   - sha256_rsl_tip    — first RSL tip in the SHA-256 epoch
//   - sha256_head_oid   — HEAD commit OID in the SHA-256 epoch
//   - commitment_digest — sha256(...) of canonical fields (see formula above)
//   - signature         — sshsig armored signature over commitment_digest (optional)
//   - signer_public_key — raw SSH public key used for signing (optional)
//   - description       — human-readable note
type GenesisBridgeRecord struct {
	SchemaVersion   string    `json:"schema_version"`
	CreatedAt       time.Time `json:"created_at"`
	SHA1RSLTip      string    `json:"sha1_rsl_tip"`
	SHA1HeadOID     string    `json:"sha1_head_oid"`
	SHA256RSLTip    string    `json:"sha256_rsl_tip"`
	SHA256HeadOID   string    `json:"sha256_head_oid"`
	CommitmentDigest string   `json:"commitment_digest"`
	// Signature is the armored sshsig signature over CommitmentDigest bytes,
	// created with the private key corresponding to SignerPublicKey.
	// Empty when the bridge has not been signed yet.
	Signature       string    `json:"signature,omitempty"`
	// SignerPublicKey is the raw SSH public-key line (e.g. "ssh-ed25519 AAAA...")
	// of the key that produced Signature. Embedded so verifiers need only
	// the bridge JSON — no external allowed_signers file required.
	SignerPublicKey  string    `json:"signer_public_key,omitempty"`
	Description     string    `json:"description"`
}

// BridgeVerificationResult holds the output of VerifyGenesisBridge and
// VerifyGenesisBridgeSignature.
type BridgeVerificationResult struct {
	SHA1RSLTip      string
	SHA256RSLTip    string
	CommitmentOK    bool
	SignatureOK     bool
	SignatureSkipped bool // true when bridge carries no signature
	ErrorDetail     string
}

// NewGenesisBridge creates an unsigned GenesisBridgeRecord.
// Call SignGenesisBridge afterwards to embed a cryptographic signature.
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
	raw := fmt.Sprintf("genesis-bridge|sha1|%s|%s|%s|%s|%s",
		sha1RSLTip, sha1HeadOID, sha256RSLTip, sha256HeadOID, now.Format(time.RFC3339))
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

// SignGenesisBridge signs the bridge's CommitmentDigest using the provided
// SSH private key (PEM bytes). It embeds the armored sshsig signature and
// the corresponding public key into the record in-place.
//
// The signed payload is exactly the UTF-8 encoding of CommitmentDigest
// (the hex string), so a verifier only needs the bridge JSON to confirm
// both the math and the cryptographic signature.
func SignGenesisBridge(bridge *GenesisBridgeRecord, pemPrivateKeyBytes []byte) error {
	if bridge.CommitmentDigest == "" {
		return fmt.Errorf("%w: CommitmentDigest is empty, cannot sign", ErrBridgeMissingField)
	}

	// Parse private key
	signer, err := ssh.ParsePrivateKey(pemPrivateKeyBytes)
	if err != nil {
		return fmt.Errorf("cannot parse SSH private key: %w", err)
	}

	// Sign the commitment digest bytes using sshsig (SHA-512 hash, gittuf-bridge namespace)
	payload := strings.NewReader(bridge.CommitmentDigest)
	sig, err := sshsig.Sign(payload, signer, sshsig.HashSHA512, bridgeSigNamespace)
	if err != nil {
		return fmt.Errorf("sshsig signing failed: %w", err)
	}

	// Embed armored signature
	bridge.Signature = string(sshsig.Armor(sig))

	// Embed the raw public key line so verifiers don't need an external file
	pubKey := signer.PublicKey()
	bridge.SignerPublicKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))

	return nil
}

// VerifyGenesisBridge verifies only the internal commitment math.
// It does NOT verify the cryptographic signature.
// Use VerifyGenesisBridgeSignature for full verification.
func VerifyGenesisBridge(bridge *GenesisBridgeRecord) *BridgeVerificationResult {
	result := &BridgeVerificationResult{
		SHA1RSLTip:   bridge.SHA1RSLTip,
		SHA256RSLTip: bridge.SHA256RSLTip,
	}

	raw := fmt.Sprintf("genesis-bridge|sha1|%s|%s|%s|%s|%s",
		bridge.SHA1RSLTip,
		bridge.SHA1HeadOID,
		bridge.SHA256RSLTip,
		bridge.SHA256HeadOID,
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

// VerifyGenesisBridgeSignature performs FULL verification:
//  1. Re-derives the commitment digest (math check)
//  2. Parses the embedded signer public key from the bridge record
//  3. Verifies the sshsig signature over CommitmentDigest using that key
//     (namespace: "gittuf-bridge", hash: SHA-512)
//
// If the bridge carries no signature, it returns ErrBridgeNotSigned.
// The caller (VerifyRefCrossEpoch) must decide whether to treat unsigned
// bridges as acceptable — by default they are rejected in secure mode.
func VerifyGenesisBridgeSignature(bridge *GenesisBridgeRecord) (*BridgeVerificationResult, error) {
	result := &BridgeVerificationResult{
		SHA1RSLTip:   bridge.SHA1RSLTip,
		SHA256RSLTip: bridge.SHA256RSLTip,
	}

	// Step 1: Commitment math check
	mathResult := VerifyGenesisBridge(bridge)
	result.CommitmentOK = mathResult.CommitmentOK
	if !result.CommitmentOK {
		result.ErrorDetail = mathResult.ErrorDetail
		return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
	}

	// Step 2: Check that signature is present
	if bridge.Signature == "" || bridge.SignerPublicKey == "" {
		result.SignatureSkipped = true
		return result, ErrBridgeNotSigned
	}

	// Step 3: Parse embedded public key
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(bridge.SignerPublicKey))
	if err != nil {
		result.ErrorDetail = fmt.Sprintf("cannot parse embedded signer public key: %v", err)
		return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
	}

	// Step 4: Parse armored sshsig signature
	sig, err := sshsig.Unarmor([]byte(bridge.Signature))
	if err != nil {
		result.ErrorDetail = fmt.Sprintf("cannot parse bridge signature: %v", err)
		return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
	}

	// Step 5: Verify — payload is the CommitmentDigest hex string bytes
	err = sshsig.Verify(
		bytes.NewReader([]byte(bridge.CommitmentDigest)),
		sig,
		pubKey,
		sshsig.HashSHA512,
		bridgeSigNamespace,
	)
	if err != nil {
		result.ErrorDetail = fmt.Sprintf("sshsig verification failed: %v", err)
		return result, fmt.Errorf("%w: %s", ErrBridgeSignatureInvalid, result.ErrorDetail)
	}

	result.SignatureOK = true
	return result, nil
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
	sigStatus := "unsigned"
	if b.Signature != "" {
		sigStatus = "signed ✔"
	}
	return fmt.Sprintf(
		"Genesis Bridge (GAP-1)\n"+
			"  Created:        %s\n"+
			"  SHA-1 RSL Tip:  %s\n"+
			"  SHA-1 HEAD:     %s\n"+
			"  SHA-256 RSL Tip:%s\n"+
			"  SHA-256 HEAD:   %s\n"+
			"  Commitment:     %s\n"+
			"  Signature:      %s\n",
		b.CreatedAt.Format(time.RFC3339),
		b.SHA1RSLTip,
		b.SHA1HeadOID,
		b.SHA256RSLTip,
		b.SHA256HeadOID,
		b.CommitmentDigest,
		sigStatus,
	)
}
