// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"testing"
)

func TestBridgeCommands(t *testing.T) {
	cmd := New()
	if cmd.Use != "bridge" {
		t.Errorf("expected Use 'bridge', got %s", cmd.Use)
	}

	subCommands := cmd.Commands()
	if len(subCommands) < 2 {
		t.Fatalf("expected at least 2 subcommands, got %d", len(subCommands))
	}

	foundCreate := false
	foundVerify := false
	for _, sc := range subCommands {
		if sc.Name() == "create" {
			foundCreate = true
		}
		if sc.Name() == "verify" {
			foundVerify = true
		}
	}

	if !foundCreate {
		t.Error("expected 'create' subcommand not found")
	}
	if !foundVerify {
		t.Error("expected 'verify' subcommand not found")
	}
}
