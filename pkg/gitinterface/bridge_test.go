// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewGenesisBridge verifies that a valid bridge is created when all
// required fields are provided.
func TestNewGenesisBridge(t *testing.T) {
	t.Parallel()

	sha1RSL := "abc1230000000000000000000000000000000000"
	sha1Head := "def4560000000000000000000000000000000000"
	sha256RSL := "abc123def456abc123def456abc123def456abc123def456abc123def456abc12300"
	sha256Head := "000111222333444555666777888999aaabbbccc000111222333444555666777888999"

	bridge, err := NewGenesisBridge(sha1RSL, sha1Head, sha256RSL, sha256Head)
	if err != nil {
		t.Fatalf("NewGenesisBridge returned error: %v", err)
	}

	if bridge.SHA1RSLTip != sha1RSL {
		t.Errorf("SHA1RSLTip mismatch: got %s", bridge.SHA1RSLTip)
	}
	if bridge.SHA256RSLTip != sha256RSL {
		t.Errorf("SHA256RSLTip mismatch: got %s", bridge.SHA256RSLTip)
	}
	if bridge.CommitmentDigest == "" {
		t.Error("CommitmentDigest is empty")
	}
	if len(bridge.CommitmentDigest) != 64 {
		t.Errorf("CommitmentDigest should be 64 hex chars, got %d", len(bridge.CommitmentDigest))
	}
	if bridge.SchemaVersion != "gap1-bridge-v1" {
		t.Errorf("unexpected SchemaVersion: %s", bridge.SchemaVersion)
	}
}

// TestNewGenesisBridgeMissingFields verifies that missing required fields
// return ErrBridgeMissingField.
func TestNewGenesisBridgeMissingFields(t *testing.T) {
	t.Parallel()

	_, err := NewGenesisBridge("", "head", "sha256rsl", "sha256head")
	if err != ErrBridgeMissingField {
		t.Errorf("expected ErrBridgeMissingField for empty sha1RSLTip, got: %v", err)
	}

	_, err = NewGenesisBridge("sha1rsl", "head", "", "sha256head")
	if err != ErrBridgeMissingField {
		t.Errorf("expected ErrBridgeMissingField for empty sha256RSLTip, got: %v", err)
	}
}

// TestVerifyGenesisBridge verifies that a freshly created bridge
// passes internal commitment verification.
func TestVerifyGenesisBridge(t *testing.T) {
	t.Parallel()

	bridge, err := NewGenesisBridge(
		"aaa000111222333444555666777888999aaa0001",
		"bbb000111222333444555666777888999bbb0001",
		"ccc000111222333444555666777888999ccc000111222333444555666777888999cc",
		"ddd000111222333444555666777888999ddd000111222333444555666777888999dd",
	)
	if err != nil {
		t.Fatalf("NewGenesisBridge: %v", err)
	}

	result := VerifyGenesisBridge(bridge)
	if !result.CommitmentOK {
		t.Errorf("expected CommitmentOK=true, got false: %s", result.ErrorDetail)
	}
}

// TestVerifyGenesisBridgeTampered verifies that tampering with a bridge
// fails commitment verification.
func TestVerifyGenesisBridgeTampered(t *testing.T) {
	t.Parallel()

	bridge, _ := NewGenesisBridge(
		"aaa000111222333444555666777888999aaa0001",
		"bbb000111222333444555666777888999bbb0001",
		"ccc000111222333444555666777888999ccc000111222333444555666777888999cc",
		"ddd000111222333444555666777888999ddd000111222333444555666777888999dd",
	)

	// Tamper: change SHA256RSLTip
	bridge.SHA256RSLTip = "0000000000000000000000000000000000000000000000000000000000000000"

	result := VerifyGenesisBridge(bridge)
	if result.CommitmentOK {
		t.Error("expected CommitmentOK=false after tampering, got true — tamper detection FAILED")
	}
}

// TestWriteAndLoadGenesisBridge verifies round-trip serialisation.
func TestWriteAndLoadGenesisBridge(t *testing.T) {
	t.Parallel()

	bridge, err := NewGenesisBridge(
		"aaa000111222333444555666777888999aaa0001",
		"bbb000111222333444555666777888999bbb0001",
		"ccc000111222333444555666777888999ccc000111222333444555666777888999cc",
		"ddd000111222333444555666777888999ddd000111222333444555666777888999dd",
	)
	if err != nil {
		t.Fatalf("NewGenesisBridge: %v", err)
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bridge.json")

	if err := WriteGenesisBridge(bridge, path); err != nil {
		t.Fatalf("WriteGenesisBridge: %v", err)
	}

	loaded, err := LoadGenesisBridge(path)
	if err != nil {
		t.Fatalf("LoadGenesisBridge: %v", err)
	}

	if loaded.CommitmentDigest != bridge.CommitmentDigest {
		t.Errorf("CommitmentDigest mismatch after round-trip: got %s", loaded.CommitmentDigest)
	}
	if loaded.SHA1RSLTip != bridge.SHA1RSLTip {
		t.Errorf("SHA1RSLTip mismatch after round-trip: got %s", loaded.SHA1RSLTip)
	}

	// Cleanup
	os.Remove(path)
}

// TestGenesisBridgeSummary verifies that summary output contains key fields.
func TestGenesisBridgeSummary(t *testing.T) {
	t.Parallel()

	bridge, _ := NewGenesisBridge(
		"aaa000111222333444555666777888999aaa0001",
		"bbb000111222333444555666777888999bbb0001",
		"ccc000111222333444555666777888999ccc000111222333444555666777888999cc",
		"ddd000111222333444555666777888999ddd000111222333444555666777888999dd",
	)

	summary := GenesisBridgeSummary(bridge)
	if summary == "" {
		t.Error("GenesisBridgeSummary returned empty string")
	}
	if len(summary) < 50 {
		t.Errorf("summary too short (%d chars): %s", len(summary), summary)
	}
}
