// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package snapshot

import (
	"fmt"

	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/spf13/cobra"
)

type options struct {
	outputFile string
	signingKey string
	bundlePath string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&o.outputFile,
		"output",
		"o",
		"snapshot-manifest.json",
		"path to write the snapshot manifest JSON",
	)
	cmd.Flags().StringVarP(
		&o.signingKey,
		"key",
		"k",
		"",
		"SSH public key fingerprint or identity for root commitment",
	)
	cmd.Flags().StringVarP(
		&o.bundlePath,
		"bundle",
		"b",
		"",
		"optional Git bundle path to hash and link in snapshot",
	)
}

func (o *options) Run(cmd *cobra.Command, args []string) error {
	repo, err := gitinterface.LoadRepository(".")
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}

	cmd.Printf("Capturing GAP-1 cryptographic snapshot of repository...\n")

	manifest, err := repo.TakeSnapshot(o.signingKey, o.bundlePath)
	if err != nil {
		return fmt.Errorf("failed to take snapshot: %w", err)
	}

	if err := gitinterface.WriteSnapshotManifest(manifest, o.outputFile); err != nil {
		return fmt.Errorf("failed to write snapshot manifest: %w", err)
	}

	cmd.Printf("✅ Snapshot created successfully: %s\n", o.outputFile)
	cmd.Printf("   SHA-1 Repo Head:    %s\n", manifest.SHA1RepoHead)
	cmd.Printf("   RSL Tip:            %s\n", manifest.RSLTip)
	cmd.Printf("   OID Commitment:     %s\n", manifest.CommitmentSHA256)
	cmd.Printf("   Content SHA-256:    %s\n", manifest.ContentSHA256)

	return nil
}

type verifyOptions struct {
	manifestFile string
}

func (vo *verifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&vo.manifestFile,
		"manifest",
		"m",
		"snapshot-manifest.json",
		"path to the snapshot manifest JSON to verify",
	)
}

func (vo *verifyOptions) Run(cmd *cobra.Command, args []string) error {
	manifest, err := gitinterface.LoadSnapshotManifest(vo.manifestFile)
	if err != nil {
		return fmt.Errorf("failed to load snapshot manifest: %w", err)
	}

	repo, err := gitinterface.LoadRepository(".")
	if err != nil {
		return fmt.Errorf("failed to open git repository: %w", err)
	}

	cmd.Printf("Verifying repository state against snapshot: %s\n", vo.manifestFile)

	currentContentSHA, err := repo.ComputeContentSHA256()
	if err != nil {
		return fmt.Errorf("failed to compute current content SHA-256: %w", err)
	}

	if currentContentSHA != manifest.ContentSHA256 {
		return fmt.Errorf("❌ Content SHA-256 MISMATCH! Tampering detected.\n  Expected: %s\n  Actual:   %s", manifest.ContentSHA256, currentContentSHA)
	}

	cmd.Printf("✅ Verification PASSED: Content SHA-256 matches snapshot (%s)\n", currentContentSHA)
	return nil
}

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "snapshot",
		Short:             "GAP-1 Hash Agility cryptographic snapshot tools",
		Long:              "Commands to freeze, anchor, and verify content-level SHA-256 repository snapshots during hash migration.",
		DisableAutoGenTag: true,
	}

	// Subcommand: gittuf snapshot freeze / create
	freezeOpt := &options{}
	freezeCmd := &cobra.Command{
		Use:               "freeze",
		Aliases:           []string{"create"},
		Short:             "Freeze repository state into a signed/anchored snapshot manifest",
		RunE:              freezeOpt.Run,
		DisableAutoGenTag: true,
	}
	freezeOpt.AddFlags(freezeCmd)
	rootCmd.AddCommand(freezeCmd)

	// Subcommand: gittuf snapshot verify
	verifyOpt := &verifyOptions{}
	verifyCmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verify repository integrity against a snapshot manifest",
		RunE:              verifyOpt.Run,
		DisableAutoGenTag: true,
	}
	verifyOpt.AddFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)

	return rootCmd
}
