// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"testing"
)

func TestSnapshotCommands(t *testing.T) {
	cmd := New()
	if cmd.Use != "snapshot" {
		t.Errorf("expected Use 'snapshot', got %s", cmd.Use)
	}

	subCommands := cmd.Commands()
	if len(subCommands) < 2 {
		t.Fatalf("expected at least 2 subcommands, got %d", len(subCommands))
	}

	foundFreeze := false
	foundVerify := false
	for _, sc := range subCommands {
		if sc.Name() == "freeze" {
			foundFreeze = true
		}
		if sc.Name() == "verify" {
			foundVerify = true
		}
	}

	if !foundFreeze {
		t.Error("expected 'freeze' subcommand not found")
	}
	if !foundVerify {
		t.Error("expected 'verify' subcommand not found")
	}
}
