// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package rsl

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gittuf/gittuf/pkg/customfields"
	"github.com/gittuf/gittuf/pkg/githash"
	"github.com/gittuf/gittuf/pkg/gitstore"
)

const (
	// GenesisBridgeEntryHeader is the commit message header for a GAP-1 Genesis Bridge entry.
	GenesisBridgeEntryHeader = "RSL Genesis Bridge Entry"

	// Keys used in the GenesisBridgeEntry message.
	PriorEpochHashAlgoKey   = "priorEpochHashAlgo"
	PriorEpochRSLTipKey     = "priorEpochRSLTip"
	PriorEpochHeadOIDKey    = "priorEpochHeadOID"
	CurrentEpochHeadOIDKey  = "currentEpochHeadOID"
	CommitmentDigestKey     = "commitmentDigest"
	FrozenTimestampKey      = "frozenTimestamp"
)

var (
	// ErrInvalidGenesisBridgeEntry is returned when a genesis bridge entry is malformed.
	ErrInvalidGenesisBridgeEntry = errors.New("invalid RSL genesis bridge entry")
)

// GenesisBridgeEntry represents a native RSL entry that links two distinct cryptographic hash epochs
// (e.g., migrating from SHA-1 to SHA-256). It satisfies the rsl.Entry interface.
type GenesisBridgeEntry struct {
	// ID is the Git commit ID of this entry in the current repository's object format.
	ID githash.Hash

	// PriorEpochHashAlgo is the algorithm of the prior epoch (e.g. "sha1").
	PriorEpochHashAlgo string

	// PriorEpochRSLTip is the final RSL tip OID of the prior epoch.
	PriorEpochRSLTip string

	// PriorEpochHeadOID is the tip commit of the default branch in the prior epoch.
	PriorEpochHeadOID string

	// CurrentEpochHeadOID is the migrated tip commit in the new epoch.
	CurrentEpochHeadOID string

	// CommitmentDigest is the SHA-256 digest binding the two epochs cryptographically.
	CommitmentDigest string

	// FrozenTimestamp is the UTC timestamp recorded at migration freeze.
	FrozenTimestamp string

	// Number contains the strictly increasing RSL sequence number.
	Number uint64

	// CustomFields holds any user/application metadata.
	CustomFields CustomFields
}

// NewGenesisBridgeEntry constructs an in-memory GenesisBridgeEntry.
func NewGenesisBridgeEntry(
	priorEpochHashAlgo, priorEpochRSLTip, priorEpochHeadOID, currentEpochHeadOID string,
	opts ...EntryOption,
) (*GenesisBridgeEntry, error) {
	if priorEpochRSLTip == "" || priorEpochHeadOID == "" || currentEpochHeadOID == "" {
		return nil, ErrInvalidGenesisBridgeEntry
	}

	if priorEpochHashAlgo == "" {
		priorEpochHashAlgo = "sha1"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	raw := fmt.Sprintf("genesis-bridge|%s|%s|%s|%s|%s", priorEpochHashAlgo, priorEpochRSLTip, priorEpochHeadOID, currentEpochHeadOID, now)
	h := sha256.Sum256([]byte(raw))
	commitment := hex.EncodeToString(h[:])

	options := applyEntryOptions(opts)

	return &GenesisBridgeEntry{
		PriorEpochHashAlgo:  priorEpochHashAlgo,
		PriorEpochRSLTip:    priorEpochRSLTip,
		PriorEpochHeadOID:   priorEpochHeadOID,
		CurrentEpochHeadOID: currentEpochHeadOID,
		CommitmentDigest:    commitment,
		FrozenTimestamp:     now,
		CustomFields:        options.customFields,
	}, nil
}

func (e *GenesisBridgeEntry) GetID() githash.Hash {
	return e.ID
}

func (e *GenesisBridgeEntry) GetNumber() uint64 {
	return e.Number
}

func (e *GenesisBridgeEntry) GetCustomField(key string) (string, bool) {
	value, has := e.CustomFields[key]
	return value, has
}

func (e *GenesisBridgeEntry) Commit(storer gitstore.Storer, sign bool) error {
	if err := e.setEntryNumber(storer); err != nil {
		return err
	}

	message, err := e.createCommitMessage(true)
	if err != nil {
		return err
	}

	return commitEntry(storer, message, sign)
}

func (e *GenesisBridgeEntry) CommitUsingSpecificKey(storer gitstore.Storer, signingKeyBytes []byte) error {
	if err := e.setEntryNumber(storer); err != nil {
		return err
	}

	message, err := e.createCommitMessage(true)
	if err != nil {
		return err
	}

	return commitEntryUsingSpecificKey(storer, message, signingKeyBytes)
}

func (e *GenesisBridgeEntry) setEntryNumber(storer gitstore.Storer) error {
	latestEntry, err := GetLatestEntry(storer)
	if err == nil {
		e.Number = latestEntry.GetNumber() + 1
	} else {
		if errors.Is(err, ErrRSLEntryNotFound) {
			e.Number = 1
		} else {
			return err
		}
	}
	return nil
}

func (e *GenesisBridgeEntry) createCommitMessage(includeNumber bool) (string, error) {
	lines := []string{
		GenesisBridgeEntryHeader,
		"",
		fmt.Sprintf("%s: %s", PriorEpochHashAlgoKey, e.PriorEpochHashAlgo),
		fmt.Sprintf("%s: %s", PriorEpochRSLTipKey, e.PriorEpochRSLTip),
		fmt.Sprintf("%s: %s", PriorEpochHeadOIDKey, e.PriorEpochHeadOID),
		fmt.Sprintf("%s: %s", CurrentEpochHeadOIDKey, e.CurrentEpochHeadOID),
		fmt.Sprintf("%s: %s", CommitmentDigestKey, e.CommitmentDigest),
		fmt.Sprintf("%s: %s", FrozenTimestampKey, e.FrozenTimestamp),
	}

	if includeNumber && e.Number > 0 {
		lines = append(lines, fmt.Sprintf("%s: %d", NumberKey, e.Number))
	}

	lines, err := appendCustomFieldLines(lines, e.CustomFields)
	if err != nil {
		return "", err
	}

	return strings.Join(lines, "\n"), nil
}

// parseGenesisBridgeEntryText parses a Genesis Bridge commit message into a GenesisBridgeEntry.
func parseGenesisBridgeEntryText(id githash.Hash, text string) (*GenesisBridgeEntry, error) {
	body, err := entryBody(text, GenesisBridgeEntryHeader)
	if err != nil {
		return nil, err
	}

	entry := &GenesisBridgeEntry{ID: id}

	for _, line := range body {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return nil, ErrInvalidRSLEntry
		}
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)

		switch key {
		case PriorEpochHashAlgoKey:
			entry.PriorEpochHashAlgo = value
		case PriorEpochRSLTipKey:
			entry.PriorEpochRSLTip = value
		case PriorEpochHeadOIDKey:
			entry.PriorEpochHeadOID = value
		case CurrentEpochHeadOIDKey:
			entry.CurrentEpochHeadOID = value
		case CommitmentDigestKey:
			entry.CommitmentDigest = value
		case FrozenTimestampKey:
			entry.FrozenTimestamp = value
		case NumberKey:
			if err := setNumber(&entry.Number, value); err != nil {
				return nil, err
			}
		default:
			if strings.HasPrefix(key, customfields.Prefix) {
				setCustomField(&entry.CustomFields, key, value)
			}
		}
	}

	if entry.PriorEpochRSLTip == "" || entry.PriorEpochHeadOID == "" || entry.CurrentEpochHeadOID == "" {
		return nil, ErrInvalidRSLEntry
	}

	return entry, nil
}
