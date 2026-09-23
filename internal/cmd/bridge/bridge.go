// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"fmt"

	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/spf13/cobra"
)

type createOptions struct {
	sha1RSLTip    string
	sha1HeadOID   string
	sha256RSLTip  string
	sha256HeadOID string
	outputFile    string
}

func (co *createOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&co.sha1RSLTip, "sha1-rsl", "", "Tip OID of SHA-1 RSL epoch")
	cmd.Flags().StringVar(&co.sha1HeadOID, "sha1-head", "", "Tip OID of SHA-1 repository HEAD")
	cmd.Flags().StringVar(&co.sha256RSLTip, "sha256-rsl", "", "Initial tip OID of SHA-256 RSL epoch")
	cmd.Flags().StringVar(&co.sha256HeadOID, "sha256-head", "", "Initial tip OID of SHA-256 repository HEAD")
	cmd.Flags().StringVarP(&co.outputFile, "output", "o", "genesis-bridge.json", "Output path for the genesis bridge record")

	_ = cmd.MarkFlagRequired("sha1-rsl")
	_ = cmd.MarkFlagRequired("sha1-head")
	_ = cmd.MarkFlagRequired("sha256-rsl")
	_ = cmd.MarkFlagRequired("sha256-head")
}

func (co *createOptions) Run(cmd *cobra.Command, args []string) error {
	cmd.Printf("Creating GAP-1 Genesis Bridge record...\n")

	bridge, err := gitinterface.NewGenesisBridge(
		co.sha1RSLTip,
		co.sha1HeadOID,
		co.sha256RSLTip,
		co.sha256HeadOID,
	)
	if err != nil {
		return fmt.Errorf("failed to create genesis bridge: %w", err)
	}

	if err := gitinterface.WriteGenesisBridge(bridge, co.outputFile); err != nil {
		return fmt.Errorf("failed to write genesis bridge file: %w", err)
	}

	cmd.Printf("✅ Genesis Bridge created successfully: %s\n", co.outputFile)
	cmd.Printf("%s\n", gitinterface.GenesisBridgeSummary(bridge))
	return nil
}

type verifyOptions struct {
	bridgeFile string
}

func (vo *verifyOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(
		&vo.bridgeFile,
		"file",
		"f",
		"genesis-bridge.json",
		"path to genesis bridge JSON file to verify",
	)
}

func (vo *verifyOptions) Run(cmd *cobra.Command, args []string) error {
	bridge, err := gitinterface.LoadGenesisBridge(vo.bridgeFile)
	if err != nil {
		return fmt.Errorf("failed to load genesis bridge: %w", err)
	}

	cmd.Printf("Verifying Genesis Bridge integrity: %s\n", vo.bridgeFile)

	result := gitinterface.VerifyGenesisBridge(bridge)
	if !result.CommitmentOK {
		return fmt.Errorf("❌ Genesis Bridge verification FAILED: %s", result.ErrorDetail)
	}

	cmd.Printf("✅ Genesis Bridge verification PASSED (Commitment: %s)\n", bridge.CommitmentDigest)
	return nil
}

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "bridge",
		Short:             "GAP-1 Genesis Bridge tools for cross-epoch verification",
		Long:              "Commands to create and verify cryptographic links between SHA-1 and SHA-256 RSL epochs.",
		DisableAutoGenTag: true,
	}

	// Subcommand: gittuf bridge create
	createOpt := &createOptions{}
	createCmd := &cobra.Command{
		Use:               "create",
		Short:             "Create a Genesis Bridge record linking SHA-1 and SHA-256 epochs",
		RunE:              createOpt.Run,
		DisableAutoGenTag: true,
	}
	createOpt.AddFlags(createCmd)
	rootCmd.AddCommand(createCmd)

	// Subcommand: gittuf bridge verify
	verifyOpt := &verifyOptions{}
	verifyCmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verify cryptographic consistency of a Genesis Bridge record",
		RunE:              verifyOpt.Run,
		DisableAutoGenTag: true,
	}
	verifyOpt.AddFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)

	return rootCmd
}
