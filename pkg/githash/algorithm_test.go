// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package githash

import (
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashAlgorithmByteLength(t *testing.T) {
	t.Parallel()

	sha1Len, err := HashAlgoSHA1.ByteLength()
	require.NoError(t, err)
	assert.Equal(t, sha1.Size, sha1Len)

	sha256Len, err := HashAlgoSHA256.ByteLength()
	require.NoError(t, err)
	assert.Equal(t, sha256.Size, sha256Len)

	_, err = HashAlgorithm("sha512").ByteLength()
	assert.ErrorIs(t, err, ErrUnknownHashAlgorithm)
}

func TestHashAlgorithmHexLength(t *testing.T) {
	t.Parallel()

	sha1HexLen, err := HashAlgoSHA1.HexLength()
	require.NoError(t, err)
	assert.Equal(t, 40, sha1HexLen)

	sha256HexLen, err := HashAlgoSHA256.HexLength()
	require.NoError(t, err)
	assert.Equal(t, 64, sha256HexLen)
}

func TestDetectAlgorithm(t *testing.T) {
	t.Parallel()

	t.Run("SHA-1 raw bytes", func(t *testing.T) {
		t.Parallel()
		raw := make([]byte, sha1.Size)
		algo, err := DetectAlgorithm(raw)
		require.NoError(t, err)
		assert.Equal(t, HashAlgoSHA1, algo)
	})

	t.Run("SHA-256 raw bytes", func(t *testing.T) {
		t.Parallel()
		raw := make([]byte, sha256.Size)
		algo, err := DetectAlgorithm(raw)
		require.NoError(t, err)
		assert.Equal(t, HashAlgoSHA256, algo)
	})

	t.Run("unknown length", func(t *testing.T) {
		t.Parallel()
		raw := make([]byte, 64) // 64 raw bytes = no known algo
		_, err := DetectAlgorithm(raw)
		assert.ErrorIs(t, err, ErrUnknownHashAlgorithm)
	})
}

func TestDetectAlgorithmFromHex(t *testing.T) {
	t.Parallel()

	sha1Hex := "abcdef12345678900987654321fedcbaabcdef12"
	sha256Hex := "abcdef12345678900987654321fedcbaabcdef12345678900987654321fedcba"

	t.Run("40-char hex is SHA-1", func(t *testing.T) {
		t.Parallel()
		algo, err := DetectAlgorithmFromHex(sha1Hex)
		require.NoError(t, err)
		assert.Equal(t, HashAlgoSHA1, algo)
	})

	t.Run("64-char hex is SHA-256", func(t *testing.T) {
		t.Parallel()
		algo, err := DetectAlgorithmFromHex(sha256Hex)
		require.NoError(t, err)
		assert.Equal(t, HashAlgoSHA256, algo)
	})

	t.Run("wrong length hex is error", func(t *testing.T) {
		t.Parallel()
		_, err := DetectAlgorithmFromHex("abcdef")
		assert.ErrorIs(t, err, ErrUnknownHashAlgorithm)
	})

	t.Run("128-char hex is unknown (no SHA-512 registered)", func(t *testing.T) {
		t.Parallel()
		longHex := "abcdef12345678900987654321fedcbaabcdef12345678900987654321fedcbaabcdef12345678900987654321fedcbaabcdef12345678900987654321fedcba"
		_, err := DetectAlgorithmFromHex(longHex)
		assert.ErrorIs(t, err, ErrUnknownHashAlgorithm)
	})
}

func TestIsKnownAlgorithm(t *testing.T) {
	t.Parallel()

	assert.True(t, IsKnownAlgorithm(HashAlgoSHA1))
	assert.True(t, IsKnownAlgorithm(HashAlgoSHA256))
	assert.False(t, IsKnownAlgorithm(HashAlgorithm("sha512")))
	assert.False(t, IsKnownAlgorithm(HashAlgorithm("blake3")))
	assert.False(t, IsKnownAlgorithm(HashAlgorithm("")))
}

func TestRegisteredAlgorithms(t *testing.T) {
	t.Parallel()

	algos := RegisteredAlgorithms()
	assert.Len(t, algos, 2) // sha1 and sha256

	found := map[HashAlgorithm]bool{}
	for _, algo := range algos {
		found[algo] = true
	}
	assert.True(t, found[HashAlgoSHA1])
	assert.True(t, found[HashAlgoSHA256])
}

func TestZeroHashForAlgorithm(t *testing.T) {
	t.Parallel()

	t.Run("SHA-1 zero hash", func(t *testing.T) {
		t.Parallel()
		h, err := ZeroHashForAlgorithm(HashAlgoSHA1)
		require.NoError(t, err)
		assert.Len(t, h, sha1.Size)
		assert.True(t, h.IsZero())
	})

	t.Run("SHA-256 zero hash", func(t *testing.T) {
		t.Parallel()
		h, err := ZeroHashForAlgorithm(HashAlgoSHA256)
		require.NoError(t, err)
		assert.Len(t, h, sha256.Size)
		assert.True(t, h.IsZero())
	})

	t.Run("unknown algo returns error", func(t *testing.T) {
		t.Parallel()
		_, err := ZeroHashForAlgorithm(HashAlgorithm("sha512"))
		assert.ErrorIs(t, err, ErrUnknownHashAlgorithm)
	})
}

func TestAlgorithmMethod(t *testing.T) {
	t.Parallel()

	// Existing Hash type should return correct algo via DetectAlgorithm
	sha1Hash, err := NewHash("abcdef12345678900987654321fedcbaabcdef12")
	require.NoError(t, err)
	algo1, err := DetectAlgorithm(sha1Hash.Bytes())
	require.NoError(t, err)
	assert.Equal(t, HashAlgoSHA1, algo1)

	sha256Hash, err := NewHash("abcdef12345678900987654321fedcbaabcdef12345678900987654321fedcba")
	require.NoError(t, err)
	algo256, err := DetectAlgorithm(sha256Hash.Bytes())
	require.NoError(t, err)
	assert.Equal(t, HashAlgoSHA256, algo256)
}

func TestHashAlgorithmStringMethod(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "sha1", HashAlgoSHA1.String())
	assert.Equal(t, "sha256", HashAlgoSHA256.String())
}
