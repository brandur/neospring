package main

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	samplePrivateKey = "90ba51828ecc30132d4707d55d24456fbd726514cf56ab4668b62392798e2540"
	samplePublicKey  = "e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124"
)

func TestParseKeyPair(t *testing.T) {
	t.Run("GoGenerated", func(t *testing.T) {
		keyPair, err := ParseKeyPair(samplePrivateKey, samplePublicKey)
		require.NoError(t, err)
		require.Equal(t, samplePrivateKey, keyPair.PrivateKey)
		require.Equal(t, samplePublicKey, keyPair.PublicKey)
	})

	t.Run("TestKeyPair", func(t *testing.T) {
		keyPair, err := ParseKeyPair(TestPrivateKey, TestPublicKey)
		require.NoError(t, err)
		require.Equal(t, TestPrivateKey, keyPair.PrivateKey)
		require.Equal(t, TestPublicKey, keyPair.PublicKey)
	})
}

func TestKeyPairRoundTrip(t *testing.T) {
	message := "this is a message that will be signed"

	t.Run("GoGenerated", func(t *testing.T) {
		keyPair, err := ParseKeyPair(samplePrivateKey, samplePublicKey)
		require.NoError(t, err)

		sig := keyPair.Sign([]byte(message))
		require.True(t, keyPair.Verify([]byte(message), sig))
	})

	t.Run("TestKeyPair", func(t *testing.T) {
		keyPair, err := ParseKeyPair(TestPrivateKey, TestPublicKey)
		require.NoError(t, err)

		sig := keyPair.Sign([]byte(message))
		require.True(t, keyPair.Verify([]byte(message), sig))
	})
}

func TestParseKey(t *testing.T) {
	const key = "e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124"

	yearMonthDate := func(year, month int) time.Time {
		return time.Date(year, time.Month(month), 9, 10, 11, 12, 0, time.UTC)
	}

	t.Run("Okay", func(t *testing.T) {
		keyBytes, err := parseKey(key, yearMonthDate(2022, 11))
		require.NoError(t, err)
		require.Equal(t, key, hex.EncodeToString(keyBytes))
	})

	t.Run("BadFormat", func(t *testing.T) {
		// Too short
		{
			_, err := parseKey("194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124", yearMonthDate(2022, 11))
			require.ErrorIs(t, err, ErrKeyInvalid)
		}

		// Missing magic `83e` near end
		{
			_, err := parseKey("e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883f1124", yearMonthDate(2022, 11))
			require.ErrorIs(t, err, ErrKeyInvalid)
		}

		// Invalid month 13
		{
			_, err := parseKey("e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1324", yearMonthDate(2022, 11))
			require.ErrorIs(t, err, ErrKeyInvalid)
		}
	})

	t.Run("Expired", func(t *testing.T) {
		_, err := parseKey(key, yearMonthDate(2024, 12))
		require.ErrorIs(t, err, ErrKeyExpired)
	})

	t.Run("NotYetValid", func(t *testing.T) {
		_, err := parseKey(key, yearMonthDate(2022, 10))
		require.ErrorIs(t, err, ErrKeyNotYetValid)
	})
}
