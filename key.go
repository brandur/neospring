package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/xerrors"
)

const (
	keyLifetime = 2 * 365 * 24 * time.Hour
)

var (
	ErrKeyExpired     = xerrors.New("key is expired")
	ErrKeyInvalid     = xerrors.New("key is invalid")
	ErrKeyNotYetValid = xerrors.New("key is not yet valid")
)

type KeyPair struct {
	PrivateKey string
	PublicKey  string

	privateKeyBytes ed25519.PrivateKey
	publicKeyBytes  ed25519.PublicKey
}

func ParseKeyPair(privateKey, publicKey string) (*KeyPair, error) {
	seedBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, xerrors.Errorf("error parsing private key: %w", err)
	}

	// Note that Go refers to private keys encoded for RFC 8032 as "seeds", but
	// this is the format expected by Spring '83 and probably many other Ed25519
	// libraries elsewhere.
	if len(seedBytes) != ed25519.SeedSize {
		return nil, xerrors.Errorf("private key's length is %d, but should be %d", len(seedBytes), ed25519.SeedSize)
	}

	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, xerrors.Errorf("error parsing private key: %w", err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, xerrors.Errorf("public key's length is %d, but should be %d", len(publicKeyBytes), ed25519.PublicKeySize)
	}

	return &KeyPair{
		PrivateKey:      privateKey,
		PublicKey:       publicKey,
		privateKeyBytes: ed25519.NewKeyFromSeed(seedBytes),
		publicKeyBytes:  ed25519.PublicKey(publicKeyBytes),
	}, nil
}

func MustParseKeyPair(privateKey, publicKey string) *KeyPair {
	keyPair, err := ParseKeyPair(privateKey, publicKey)
	if err != nil {
		panic(err)
	}
	return keyPair
}

func (kp *KeyPair) Sign(message []byte) []byte {
	return ed25519.Sign(kp.privateKeyBytes, message)
}

func (kp *KeyPair) SignHex(message []byte) string {
	return hex.EncodeToString(kp.Sign(message))
}

func (kp *KeyPair) Verify(message, sig []byte) bool {
	return ed25519.Verify(kp.publicKeyBytes, message, sig)
}

// See: https://github.com/robinsloan/spring-83/blob/main/draft-20220629.md#key-format
var keyRE = regexp.MustCompile(`\A[0-9a-f]{57}83e(0[1-9]|1[0-2])(\d\d)\z`)

// Parses a Spring '83 "key" and checks that it conforms to the various
// requirements imposed by the spec. A key is the public portion of an Ed25519
// keypair encoded as hex.
func parseKey(key string, now time.Time) ([]byte, error) {
	matches := keyRE.FindAllStringSubmatch(key, 1)
	if matches == nil {
		return nil, ErrKeyInvalid
	}

	monthStr, yearStr := matches[0][1], matches[0][2]
	month, _ := strconv.Atoi(monthStr)
	year, _ := strconv.Atoi(yearStr)

	century := now.Year() / 100 * 100
	year += century

	expiryMonth := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)

	// Add a month, then subtract down by a second to get the last second of the
	// target month we're looking for, which will be considered the last valid
	// time for a key.
	expiresAt := relativeMonth(expiryMonth, 1).Add(-1 * time.Second)
	if now.After(expiresAt) {
		return nil, ErrKeyExpired
	}

	validAt := expiryMonth.Add(-keyLifetime)
	if validAt.After(now) {
		return nil, ErrKeyNotYetValid
	}

	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		// Impossible as long as we got our regex right
		return nil, xerrors.Errorf("error decoding hex %q: %w", key, err)
	}

	return keyBytes, nil
}

func relativeMonth(t time.Time, relativeMonths int) time.Time {
	year, month := t.Year(), t.Month()

	// The seemingly obvious thing to do here would be a `AddDate(0, -1, 0)`,
	// but that's a massive footgun because doing so on something like Oct 31st
	// returns Oct 1st instead of Nov 30th (because Nov 31st doesn't exist).
	// That's basically the whole reason this function exists.
	targetYear, targetMonth := year, month+time.Month(relativeMonths)
	switch targetMonth { //nolint:exhaustive
	case 0:
		targetYear--
		targetMonth = 12
	case 13:
		targetYear++
		targetMonth = 1
	}

	return time.Date(targetYear, targetMonth, 1, 0, 0, 0, 0, time.UTC)
}
