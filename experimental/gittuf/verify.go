// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package gittuf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	verifyopts "github.com/gittuf/gittuf/experimental/gittuf/options/verify"
	verifymergeableopts "github.com/gittuf/gittuf/experimental/gittuf/options/verifymergeable"
	"github.com/gittuf/gittuf/internal/dev"
	"github.com/gittuf/gittuf/internal/policy"
	"github.com/gittuf/gittuf/pkg/githash"
	"github.com/gittuf/gittuf/pkg/gitinterface"
	"github.com/gittuf/gittuf/pkg/rsl"
)

// ErrRefStateDoesNotMatchRSL is returned when a Git reference being verified
// does not have the same tip as identified in the latest RSL entry for the
// reference. This can happen for a number of reasons such as incorrectly
// modifying reference state away from what's recorded in the RSL to not
// creating an RSL entry for some new changes. Depending on the context, one
// resolution is to update the reference state to match the RSL entry, while
// another is to create a new RSL entry for the current state.
var ErrRefStateDoesNotMatchRSL = errors.New("current state of Git reference does not match latest RSL entry")

func (r *Repository) VerifyRef(ctx context.Context, refName string, opts ...verifyopts.Option) error {
	var (
		expectedTip githash.Hash
		err         error
	)

	options := &verifyopts.Options{}
	for _, fn := range opts {
		fn(options)
	}

	slog.Debug("Identifying absolute reference path...")
	refName, err = r.r.AbsoluteReference(refName)
	if err != nil {
		return err
	}

	// Track localRefName to check the expected tip as we may override refName
	localRefName := refName

	if options.RefNameOverride != "" {
		// remote ref name is different
		// We must consider RSL entries that have refNameOverride rather than
		// refName
		slog.Debug("Name of reference overridden to match remote reference name, identifying absolute reference path...")
		refNameOverride, err := r.r.AbsoluteReference(options.RefNameOverride)
		if err != nil {
			return err
		}

		refName = refNameOverride
	}

	slog.Debug(fmt.Sprintf("Verifying gittuf policies for '%s'", refName))

	verifier := policy.NewPolicyVerifier(r.r)

	if options.LatestOnly {
		expectedTip, err = verifier.VerifyRef(ctx, refName)
	} else {
		expectedTip, err = verifier.VerifyRefFull(ctx, refName)
	}
	if err != nil {
		return err
	}

	// To verify the tip, we _must_ use the localRefName
	slog.Debug("Verifying if tip of reference matches expected value from RSL...")
	if err := r.verifyRefTip(localRefName, expectedTip); err != nil {
		return err
	}

	slog.Debug("Verification successful!")
	return nil
}

func (r *Repository) VerifyRefFromEntry(ctx context.Context, refName, entryID string, opts ...verifyopts.Option) error {
	if !dev.InDevMode() {
		return dev.ErrNotInDevMode
	}

	options := &verifyopts.Options{}
	for _, fn := range opts {
		fn(options)
	}

	var err error

	slog.Debug("Identifying absolute reference path...")
	refName, err = r.r.AbsoluteReference(refName)
	if err != nil {
		return err
	}

	entryIDHash, err := gitinterface.NewHash(entryID)
	if err != nil {
		return err
	}

	// Track localRefName to check the expected tip as we may override refName
	localRefName := refName

	if options.RefNameOverride != "" {
		// remote ref name is different
		// We must consider RSL entries that have refNameOverride rather than
		// refName
		slog.Debug("Name of reference overridden to match remote reference name, identifying absolute reference path...")
		refNameOverride, err := r.r.AbsoluteReference(options.RefNameOverride)
		if err != nil {
			return err
		}

		refName = refNameOverride
	}

	slog.Debug(fmt.Sprintf("Verifying gittuf policies for '%s' from entry '%s'", refName, entryID))
	verifier := policy.NewPolicyVerifier(r.r)
	expectedTip, err := verifier.VerifyRefFromEntry(ctx, refName, entryIDHash)
	if err != nil {
		return err
	}

	// To verify the tip, we _must_ use the localRefName
	slog.Debug("Verifying if tip of reference matches expected value from RSL...")
	if err := r.verifyRefTip(localRefName, expectedTip); err != nil {
		return err
	}

	slog.Debug("Verification successful!")
	return nil
}

// VerifyMergeable checks if the targetRef can be updated to reflect the changes
// in featureRef. It checks if sufficient authorizations / approvals exist for
// the merge to happen, indicated by the error being nil. Additionally, a
// boolean value is also returned that indicates whether a final authorized
// signature is still necessary via the RSL entry for the merge.
//
// Summary of return combinations:
// (false, err) -> merge is not possible
// (false, nil) -> merge is possible and can be performed by anyone
// (true,  nil) -> merge is possible but it MUST be performed by an authorized
// person for the rule, i.e., an authorized person must sign the merge's RSL
// entry
func (r *Repository) VerifyMergeable(ctx context.Context, targetRef, featureRef string, opts ...verifymergeableopts.Option) (bool, error) {
	var err error

	options := &verifymergeableopts.Options{}
	for _, fn := range opts {
		fn(options)
	}

	slog.Debug("Identifying absolute reference paths...")
	targetRef, err = r.r.AbsoluteReference(targetRef)
	if err != nil {
		return false, err
	}
	featureRef, err = r.r.AbsoluteReference(featureRef)
	if err != nil {
		return false, err
	}

	slog.Debug(fmt.Sprintf("Inspecting gittuf policies to identify if '%s' can be merged into '%s' with current approvals...", featureRef, targetRef))
	verifier := policy.NewPolicyVerifier(r.r)

	var needRSLSignature bool

	if options.BypassRSLForFeatureRef {
		slog.Debug("Not using RSL for feature ref...")
		featureID, err := r.r.GetReference(featureRef)
		if err != nil {
			return false, err
		}

		needRSLSignature, err = verifier.VerifyMergeableForCommit(ctx, targetRef, featureID)
		if err != nil {
			return false, err
		}
	} else {
		needRSLSignature, err = verifier.VerifyMergeable(ctx, targetRef, featureRef)
		if err != nil {
			return false, err
		}
	}

	if needRSLSignature {
		slog.Debug("Merge is allowed but must be performed by authorized user who has not already issued an approval!")
	} else {
		slog.Debug("Merge is allowed and can be performed by any user!")
	}

	return needRSLSignature, nil
}

func (r *Repository) VerifyNetwork(ctx context.Context) error {
	verifier := policy.NewPolicyVerifier(r.r)
	return verifier.VerifyNetwork(ctx)
}

// VerifyRefCrossEpoch performs a full cross-epoch verification of a reference
// across both the current (SHA-256) and prior (SHA-1) epochs. This implements
// the GAP-1 cross-epoch verify-ref walk.
//
// Security model (Option B — Bridge File as Cryptographic Anchor):
//  1. Load the Genesis Bridge JSON (bridgeFilePath) and verify its internal
//     commitment digest.
//  2. Load the SHA-1 repository (sha1RepoPath) and read its actual RSL tip.
//  3. Compare the actual SHA-1 RSL tip against bridge.SHA1RSLTip — if they
//     don't match, reject immediately. This prevents a wrong/malicious SHA-1
//     repo from being substituted.
//  4. Verify the current SHA-256 epoch using the standard VerifyRef flow.
//  5. Verify the SHA-1 epoch's full RSL using the same policy engine.
func (r *Repository) VerifyRefCrossEpoch(ctx context.Context, refName, bridgeFilePath, sha1RepoPath string, opts ...verifyopts.Option) error {
	// ── Phase 1: Load and verify the Genesis Bridge JSON ──────────────────────
	slog.Info("GAP-1 cross-epoch verify: loading Genesis Bridge record...")
	bridge, err := gitinterface.LoadGenesisBridge(bridgeFilePath)
	if err != nil {
		return fmt.Errorf("cannot load genesis bridge file '%s': %w", bridgeFilePath, err)
	}

	slog.Info("GAP-1 cross-epoch verify: verifying bridge commitment digest AND SSH signature...")
	sigResult, err := gitinterface.VerifyGenesisBridgeSignature(bridge)
	if err != nil {
		// Distinguish between "no signature" and "bad signature"
		if errors.Is(err, gitinterface.ErrBridgeNotSigned) {
			return fmt.Errorf(
				"GAP-1 security check FAILED: bridge record '%s' has no embedded SSH signature — "+
					"sign the bridge with 'gittuf bridge create --signing-key <key>' before verifying cross-epoch",
				bridgeFilePath,
			)
		}
		return fmt.Errorf("genesis bridge verification failed: %w", err)
	}
	slog.Info(fmt.Sprintf(
		"GAP-1 bridge commitment ✔  signature ✔  sha1_rsl_tip=%s  sha256_rsl_tip=%s  signer=%s",
		sigResult.SHA1RSLTip, sigResult.SHA256RSLTip, bridge.SignerPublicKey[:min(40, len(bridge.SignerPublicKey))]+"...",
	))

	// ── Phase 2: Load SHA-1 repo and anchor-check its RSL tip ─────────────────
	slog.Info(fmt.Sprintf("GAP-1 cross-epoch verify: loading SHA-1 repository from '%s'...", sha1RepoPath))
	sha1Repo, err := gitinterface.LoadRepository(sha1RepoPath)
	if err != nil {
		return fmt.Errorf("cannot load SHA-1 repository from '%s': %w", sha1RepoPath, err)
	}

	slog.Info("GAP-1 cross-epoch verify: reading SHA-1 RSL tip...")
	sha1RSLTipHash, err := sha1Repo.GetReference(rsl.Ref)
	if err != nil {
		return fmt.Errorf("cannot read SHA-1 RSL tip from repo: %w", err)
	}

	// SECURITY CHECK: actual SHA-1 RSL tip must match bridge record
	if sha1RSLTipHash.String() != bridge.SHA1RSLTip {
		return fmt.Errorf(
			"GAP-1 security check FAILED: SHA-1 repo RSL tip (%s) does not match bridge record (%s) — wrong or tampered repository",
			sha1RSLTipHash.String(), bridge.SHA1RSLTip,
		)
	}
	slog.Info(fmt.Sprintf(
		"GAP-1 SHA-1 RSL tip anchor check ✔  actual=%s  bridge=%s",
		sha1RSLTipHash.String(), bridge.SHA1RSLTip,
	))

	// ── Phase 3: Verify current (SHA-256) epoch ───────────────────────────────
	slog.Info("GAP-1 cross-epoch verify: verifying SHA-256 epoch RSL...")
	if err := r.VerifyRef(ctx, refName, opts...); err != nil {
		return fmt.Errorf("SHA-256 epoch verification failed: %w", err)
	}
	slog.Info("GAP-1 SHA-256 epoch verification ✔")

	// ── Phase 4: Verify SHA-1 epoch RSL ──────────────────────────────────────
	slog.Info("GAP-1 cross-epoch verify: verifying SHA-1 epoch RSL...")
	sha1Verifier := policy.NewPolicyVerifier(sha1Repo)

	sha1RefName, err := sha1Repo.AbsoluteReference(refName)
	if err != nil {
		return fmt.Errorf("cannot resolve ref '%s' in SHA-1 repo: %w", refName, err)
	}

	sha1ExpectedTip, err := sha1Verifier.VerifyRefFull(ctx, sha1RefName)
	if err != nil {
		return fmt.Errorf("SHA-1 epoch RSL verification failed: %w", err)
	}

	// Verify that the SHA-1 repo's HEAD OID matches the bridge record
	if sha1ExpectedTip.String() != bridge.SHA1HeadOID {
		return fmt.Errorf(
			"GAP-1 security check FAILED: SHA-1 epoch verified tip (%s) does not match bridge HEAD OID (%s)",
			sha1ExpectedTip.String(), bridge.SHA1HeadOID,
		)
	}
	slog.Info(fmt.Sprintf(
		"GAP-1 SHA-1 epoch verification ✔  verified tip=%s matches bridge HEAD=%s",
		sha1ExpectedTip.String(), bridge.SHA1HeadOID,
	))

	slog.Info("GAP-1 cross-epoch verify: full chain of trust established across both epochs ✔")
	return nil
}

// verifyRefTip inspects the specified reference in the local repository to
// check if it points to the expected Git object.
func (r *Repository) verifyRefTip(target string, expectedTip githash.Hash) error {
	refTip, err := r.r.GetReference(target)
	if err != nil {
		return err
	}

	if !refTip.Equal(expectedTip) {
		return ErrRefStateDoesNotMatchRSL
	}

	return nil
}
