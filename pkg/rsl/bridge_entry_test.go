// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package rsl

import (
	"testing"

	"github.com/gittuf/gittuf/pkg/githash"
)

func TestGenesisBridgeEntry(t *testing.T) {
	priorAlgo := "sha1"
	priorRSL := "1e73ba090dc2cd3a6166866ab81f36ae8965d532"
	priorHead := "984eb14257364893a4b23a18cb1d01945cc8e448"
	currentHead := "1757f76331894752532184969f97d5541d7d5f4aa83e4b12ca6a0b67ae6b5071"

	entry, err := NewGenesisBridgeEntry(priorAlgo, priorRSL, priorHead, currentHead)
	if err != nil {
		t.Fatalf("unexpected error creating GenesisBridgeEntry: %v", err)
	}

	if entry.PriorEpochRSLTip != priorRSL {
		t.Errorf("expected prior RSL tip %s, got %s", priorRSL, entry.PriorEpochRSLTip)
	}
	if entry.CommitmentDigest == "" {
		t.Error("expected non-empty commitment digest")
	}

	// Test commit message formatting and parsing
	msg, err := entry.createCommitMessage(true)
	if err != nil {
		t.Fatalf("failed to create commit message: %v", err)
	}

	dummyID, _ := githash.NewHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	parsed, err := parseGenesisBridgeEntryText(dummyID, msg)
	if err != nil {
		t.Fatalf("failed to parse genesis bridge entry text: %v", err)
	}

	if parsed.PriorEpochRSLTip != priorRSL {
		t.Errorf("parsed prior RSL tip mismatch: expected %s, got %s", priorRSL, parsed.PriorEpochRSLTip)
	}
	if parsed.CommitmentDigest != entry.CommitmentDigest {
		t.Errorf("parsed commitment mismatch: expected %s, got %s", entry.CommitmentDigest, parsed.CommitmentDigest)
	}
}

func TestGenesisBridgeEntryValidation(t *testing.T) {
	// Missing required fields should fail
	_, err := NewGenesisBridgeEntry("sha1", "", "head", "head256")
	if err != ErrInvalidGenesisBridgeEntry {
		t.Errorf("expected ErrInvalidGenesisBridgeEntry for missing RSL tip, got %v", err)
	}

	_, err = NewGenesisBridgeEntry("sha1", "rsl", "", "head256")
	if err != ErrInvalidGenesisBridgeEntry {
		t.Errorf("expected ErrInvalidGenesisBridgeEntry for missing head, got %v", err)
	}
}
