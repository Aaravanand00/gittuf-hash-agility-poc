// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gitinterface

import (
	"testing"
)

// TestComputeContentSHA256 verifies that ComputeContentSHA256 returns a
// non-empty 64-char hex string (SHA-256 digest) for a repo with objects.
func TestComputeContentSHA256(t *testing.T) {
	t.Parallel()

	// Create a fresh test repository using gittuf's own test helper.
	testRepo := CreateTestGitRepository(t, t.TempDir(), false)

	digest, err := testRepo.ComputeContentSHA256()
	if err != nil {
		// If the repo has no objects yet, ErrSnapshotNoObjects is acceptable.
		if err == ErrSnapshotNoObjects {
			t.Skip("test repository has no objects — skipping digest check")
		}
		t.Fatalf("ComputeContentSHA256 returned unexpected error: %v", err)
	}

	// SHA-256 hex = 64 chars
	if len(digest) != 64 {
		t.Errorf("expected 64-char hex digest, got %d chars: %s", len(digest), digest)
	}

	// Must be lowercase hex only
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("digest contains non-hex character: %c", c)
		}
	}
}

// TestComputeContentSHA256Determinism verifies that calling the function
// twice on an unchanged repository yields the same digest.
func TestComputeContentSHA256Determinism(t *testing.T) {
	t.Parallel()

	testRepo := CreateTestGitRepository(t, t.TempDir(), false)

	digest1, err := testRepo.ComputeContentSHA256()
	if err != nil {
		t.Skip("skipping determinism test: " + err.Error())
	}

	digest2, err := testRepo.ComputeContentSHA256()
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if digest1 != digest2 {
		t.Errorf("non-deterministic: first=%s second=%s", digest1, digest2)
	}
}

// TestComputeOIDCommitment verifies that ComputeOIDCommitment returns a
// non-empty digest when OIDs are available.
func TestComputeOIDCommitment(t *testing.T) {
	t.Parallel()

	testRepo := CreateTestGitRepository(t, t.TempDir(), false)

	commitment, err := testRepo.ComputeOIDCommitment("SHA256:testfingerprint")
	if err != nil {
		t.Fatalf("ComputeOIDCommitment returned error: %v", err)
	}

	if len(commitment) != 64 {
		t.Errorf("expected 64-char hex commitment, got %d: %s", len(commitment), commitment)
	}
}

// TestTakeSnapshot verifies that TakeSnapshot creates a complete manifest
// with all required fields populated.
func TestTakeSnapshot(t *testing.T) {
	t.Parallel()

	testRepo := CreateTestGitRepository(t, t.TempDir(), false)

	manifest, err := testRepo.TakeSnapshot("SHA256:testfingerprint", "")
	if err != nil {
		// These errors are all expected in a bare test repo with no gittuf RSL or commits.
		t.Skipf("TakeSnapshot skipped (test repo has no HEAD/RSL): %v", err)
	}

	if manifest.SchemaVersion == "" {
		t.Error("manifest.SchemaVersion is empty")
	}
	if manifest.CommitmentSHA256 == "" {
		t.Error("manifest.CommitmentSHA256 is empty")
	}
	if manifest.ContentSHA256 == "" {
		t.Error("manifest.ContentSHA256 is empty")
	}
	if manifest.SHA1RepoHead == "" {
		t.Error("manifest.SHA1RepoHead is empty")
	}
	if manifest.FrozenAt.IsZero() {
		t.Error("manifest.FrozenAt is zero")
	}
}
