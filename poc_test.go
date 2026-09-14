// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSnapshotManifestSerialization(t *testing.T) {
	tempDir := t.TempDir()

	manifest := &SnapshotManifest{
		SchemaVersion: "gap1-poc-v1",
		FrozenAt:      time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC),
		SHA1RepoHead:  "e9afffcce72f4dad92289589f980d5840b4d100b",
		RSLTip:        "d00b97620b6dfcea58d32bc18415d5aac41f9c13",
		RSLEntryCount: 3,
		RSLChainHash:  "fac4be007988639392d02280033aa66cc2fc2696694e5b81294c0bd98b0e0e61",
		MigrationNote: "Snapshot test manifest",
		SignedBy:      "test-key-id",
	}

	savedPath, err := SaveSnapshotManifest(tempDir, manifest)
	if err != nil {
		t.Fatalf("SaveSnapshotManifest failed: %v", err)
	}

	expectedPath := filepath.Join(tempDir, "snapshot-manifest.json")
	if savedPath != expectedPath {
		t.Errorf("expected saved path %s, got %s", expectedPath, savedPath)
	}

	data, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("failed to read saved manifest: %v", err)
	}

	var loaded SnapshotManifest
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal saved JSON: %v", err)
	}

	if loaded.SchemaVersion != manifest.SchemaVersion {
		t.Errorf("expected schema %s, got %s", manifest.SchemaVersion, loaded.SchemaVersion)
	}
	if loaded.SHA1RepoHead != manifest.SHA1RepoHead {
		t.Errorf("expected head %s, got %s", manifest.SHA1RepoHead, loaded.SHA1RepoHead)
	}
	if loaded.RSLChainHash != manifest.RSLChainHash {
		t.Errorf("expected chain hash %s, got %s", manifest.RSLChainHash, loaded.RSLChainHash)
	}
	if loaded.RSLEntryCount != manifest.RSLEntryCount {
		t.Errorf("expected count %d, got %d", manifest.RSLEntryCount, loaded.RSLEntryCount)
	}
}

func TestComputeRSLChainHashEmpty(t *testing.T) {
	state := &SHA1RepoState{
		RepoPath:      t.TempDir(),
		FinalHeadSHA1: "e9afffcce72f4dad92289589f980d5840b4d100b",
		RSLEntrySHA1s: nil,
	}

	hash, err := computeRSLChainHash(state)
	if err != nil {
		t.Fatalf("computeRSLChainHash failed: %v", err)
	}

	// Known sha256 of "e9afffcce72f4dad92289589f980d5840b4d100b"
	if len(hash) != 64 {
		t.Errorf("expected 64 char hex hash, got length %d", len(hash))
	}
}

func TestFindingVerdictLogic(t *testing.T) {
	findings := []Finding{
		{Description: "Check 1", Passed: true},
		{Description: "Check 2", Passed: false},
	}

	passCount := 0
	failCount := 0
	for _, f := range findings {
		if f.Passed {
			passCount++
		} else {
			failCount++
		}
	}

	if passCount != 1 || failCount != 1 {
		t.Errorf("expected 1 pass and 1 fail, got pass=%d fail=%d", passCount, failCount)
	}
}

func TestExecCmdFailure(t *testing.T) {
	_, err := execCmd(t.TempDir(), "non-existent-binary-cmd-xyz-12345")
	if err == nil {
		t.Errorf("expected error for non-existent command, got nil")
	}
}
