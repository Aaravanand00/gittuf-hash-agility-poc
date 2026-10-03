// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"fmt"
	"os"

	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/spf13/cobra"
)

type createOptions struct {
	sha1RSLTip    string
	sha1HeadOID   string
	sha256RSLTip  string
	sha256HeadOID string
	outputFile    string
	signingKey    string // path to SSH private key for signing
}

func (co *createOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&co.sha1RSLTip, "sha1-rsl", "", "Tip OID of SHA-1 RSL epoch")
	cmd.Flags().StringVar(&co.sha1HeadOID, "sha1-head", "", "Tip OID of SHA-1 repository HEAD")
	cmd.Flags().StringVar(&co.sha256RSLTip, "sha256-rsl", "", "Initial tip OID of SHA-256 RSL epoch")
	cmd.Flags().StringVar(&co.sha256HeadOID, "sha256-head", "", "Initial tip OID of SHA-256 repository HEAD")
	cmd.Flags().StringVarP(&co.outputFile, "output", "o", "genesis-bridge.json", "Output path for the genesis bridge record")
	cmd.Flags().StringVarP(
		&co.signingKey,
		"signing-key", "k",
		"",
		"Path to SSH private key (PEM) used to cryptographically sign the bridge commitment digest.\n"+
			"Strongly recommended — unsigned bridges will be rejected by 'gittuf verify-ref --bridge-file'.",
	)

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

	// Sign the bridge if a signing key was provided
	if co.signingKey != "" {
		cmd.Printf("Signing bridge commitment with key: %s\n", co.signingKey)
		pemBytes, err := os.ReadFile(co.signingKey)
		if err != nil {
			return fmt.Errorf("cannot read signing key '%s': %w", co.signingKey, err)
		}
		if err := gitinterface.SignGenesisBridge(bridge, pemBytes); err != nil {
			return fmt.Errorf("failed to sign genesis bridge: %w", err)
		}
		cmd.Printf("✅ Bridge signed successfully (signer public key embedded in JSON)\n")
	} else {
		cmd.Printf("⚠️  WARNING: Bridge created WITHOUT a signature.\n")
		cmd.Printf("   Use --signing-key <path> to embed an SSH signature.\n")
		cmd.Printf("   Unsigned bridges will be rejected by 'gittuf verify-ref --bridge-file'.\n")
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

	cmd.Printf("Verifying Genesis Bridge: %s\n\n", vo.bridgeFile)

	// Full verification: commitment math + SSH signature
	result, err := gitinterface.VerifyGenesisBridgeSignature(bridge)
	if err != nil {
		if result != nil && result.CommitmentOK {
			// Math passed but signature failed/missing
			return fmt.Errorf("❌ Bridge commitment ✔ but signature check FAILED: %v", err)
		}
		return fmt.Errorf("❌ Genesis Bridge verification FAILED: %v", err)
	}

	cmd.Printf("✅ Commitment digest ✔\n")
	cmd.Printf("✅ SSH signature     ✔\n")
	cmd.Printf("   Signer key: %s\n", bridge.SignerPublicKey)
	cmd.Printf("   Commitment: %s\n", bridge.CommitmentDigest)
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
		Short:             "Create (and optionally sign) a Genesis Bridge record linking SHA-1 and SHA-256 epochs",
		RunE:              createOpt.Run,
		DisableAutoGenTag: true,
	}
	createOpt.AddFlags(createCmd)
	rootCmd.AddCommand(createCmd)

	// Subcommand: gittuf bridge verify
	verifyOpt := &verifyOptions{}
	verifyCmd := &cobra.Command{
		Use:               "verify",
		Short:             "Verify commitment digest AND SSH signature of a Genesis Bridge record",
		RunE:              verifyOpt.Run,
		DisableAutoGenTag: true,
	}
	verifyOpt.AddFlags(verifyCmd)
	rootCmd.AddCommand(verifyCmd)

	return rootCmd
}
