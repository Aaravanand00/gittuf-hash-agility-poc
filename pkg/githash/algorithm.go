// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package githash

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"fmt"
)

// HashAlgorithm identifies the cryptographic hash algorithm that produced a
// Git object ID. It is intentionally a string so that future algorithms
// (SHA-512, BLAKE3, SHA-3, post-quantum, etc.) can be added without changing
// the type system.
type HashAlgorithm string

const (
	// HashAlgoSHA1 represents the SHA-1 algorithm (20 raw bytes, 40 hex chars).
	HashAlgoSHA1 HashAlgorithm = "sha1"

	// HashAlgoSHA256 represents the SHA-256 algorithm (32 raw bytes, 64 hex chars).
	HashAlgoSHA256 HashAlgorithm = "sha256"
)

// knownAlgorithms maps each supported algorithm to its expected raw byte length.
// Adding a future algorithm is a one-line addition here — no other code needs
// to change.
var knownAlgorithms = map[HashAlgorithm]int{
	HashAlgoSHA1:   sha1.Size,   // 20
	HashAlgoSHA256: sha256.Size, // 32
}

var (
	// ErrUnknownHashAlgorithm is returned when a HashAlgorithm string is not
	// recognized.
	ErrUnknownHashAlgorithm = fmt.Errorf("unknown hash algorithm")
)

// ByteLength returns the expected raw byte length for the algorithm.
func (a HashAlgorithm) ByteLength() (int, error) {
	size, ok := knownAlgorithms[a]
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrUnknownHashAlgorithm, string(a))
	}
	return size, nil
}

// HexLength returns the expected hex-encoded string length for the algorithm.
func (a HashAlgorithm) HexLength() (int, error) {
	size, err := a.ByteLength()
	if err != nil {
		return 0, err
	}
	return size * 2, nil
}

// String returns the canonical name of the algorithm.
func (a HashAlgorithm) String() string {
	return string(a)
}

// DetectAlgorithm infers the hash algorithm from raw byte length.
// This is the core of hybrid parsing: the same function can distinguish a
// SHA-1 hash from a SHA-256 hash (and from any future algorithm) purely
// by examining its length, without any external context about which
// "epoch" or "repository format" the hash comes from.
func DetectAlgorithm(raw []byte) (HashAlgorithm, error) {
	for algo, size := range knownAlgorithms {
		if len(raw) == size {
			return algo, nil
		}
	}
	return "", fmt.Errorf("%w: raw length %d does not match any known algorithm", ErrUnknownHashAlgorithm, len(raw))
}

// DetectAlgorithmFromHex infers the hash algorithm from a hex-encoded string
// length. This is the entry point for hybrid cross-epoch parsing: a single
// function that accepts *any* valid Git OID hex string and returns the
// algorithm that produced it.
func DetectAlgorithmFromHex(hexStr string) (HashAlgorithm, error) {
	for algo, size := range knownAlgorithms {
		if len(hexStr) == size*2 {
			return algo, nil
		}
	}
	return "", fmt.Errorf("%w: hex length %d does not match any known algorithm", ErrUnknownHashAlgorithm, len(hexStr))
}

// IsKnownAlgorithm reports whether the algorithm name is recognized.
func IsKnownAlgorithm(algo HashAlgorithm) bool {
	_, ok := knownAlgorithms[algo]
	return ok
}

// RegisteredAlgorithms returns a copy of all currently known algorithm names.
// Tests and informational commands can use this to enumerate supported
// algorithms without hardcoding them.
func RegisteredAlgorithms() []HashAlgorithm {
	algos := make([]HashAlgorithm, 0, len(knownAlgorithms))
	for algo := range knownAlgorithms {
		algos = append(algos, algo)
	}
	return algos
}

// ZeroHashForAlgorithm returns the all-zeroes Hash of the appropriate length
// for the given algorithm. This is used to generate sentinel values for any
// supported algorithm without hardcoding byte sizes.
func ZeroHashForAlgorithm(algo HashAlgorithm) (Hash, error) {
	size, err := algo.ByteLength()
	if err != nil {
		return nil, err
	}
	return Hash(make([]byte, size)), nil
}
