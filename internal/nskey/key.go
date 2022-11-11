package nskey

import (
	"crypto/ed25519"
	"encoding/hex"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/xerrors"
)

const (
	// The maximum valid lifetime of a key as dictated by the Spring '83
	// specification.
	MaxLifetime = 2 * 365 * 24 * time.Hour
)

// Test private/public keypair defined by the Spring '83 specification. Attempts
// to post content for it are always rejected, and requests for it always return
// some randomized test content to help write client integrations.
const (
	TestPrivateKey = "3371f8b011f51632fea33ed0a3688c26a45498205c6097c352bd4d079d224419"
	TestPublicKey  = "ab589f4dde9fce4180fcf42c7b05185b0a02a5d682e353fa39177995083e0583"
)

var (
	ErrKeyExpired     = xerrors.New("key is expired")
	ErrKeyInvalid     = xerrors.New("key is invalid")
	ErrKeyNotYetValid = xerrors.New("key is not yet valid")
)

// See: https://github.com/robinsloan/spring-83/blob/main/draft-20220629.md#key-format
var keyRE = regexp.MustCompile(`\A[0-9a-f]{57}83e(0[1-9]|1[0-2])(\d\d)\z`)

// Key represents a Spring '83 public key. It can be used to verify content, but
// not to sign it.
type Key struct {
	PublicKey      string
	publicKeyBytes ed25519.PublicKey
}

// KeyFromRaw produces a Key from the given raw public key. This is unchecked,
// so no verification that it's a valid Spring '83 key is done.
func KeyFromRaw(publicKey ed25519.PublicKey) *Key {
	return &Key{
		PublicKey:      hex.EncodeToString([]byte(publicKey)),
		publicKeyBytes: publicKey,
	}
}

// ParseKey parses a Spring '83 "key" and checks that it conforms to the various
// requirements imposed by the spec. A key is the public portion of an Ed25519
// keypair encoded as hex.
func ParseKey(key string, now time.Time) (*Key, error) {
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

	validAt := expiryMonth.Add(-MaxLifetime)
	if validAt.After(now) {
		return nil, ErrKeyNotYetValid
	}

	return parseKeyUnchecked(key)
}

func parseKeyUnchecked(publicKey string) (*Key, error) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return nil, xerrors.Errorf("error parsing private key: %w", err)
	}

	if len(publicKeyBytes) != ed25519.PublicKeySize {
		return nil, xerrors.Errorf("public key's length is %d, but should be %d", len(publicKeyBytes), ed25519.PublicKeySize)
	}

	return &Key{publicKey, publicKeyBytes}, nil
}

func (kp *Key) Verify(message, sig []byte) bool {
	return ed25519.Verify(kp.publicKeyBytes, message, sig)
}

// KeyPair represents a Spring '83 private/public keypair. Unlike Key, it can
// also sign content.
type KeyPair struct {
	Key
	PrivateKey      string
	privateKeyBytes ed25519.PrivateKey
}

// KeyPairFromRaw produces a KeyPair from the given raw private key. This is
// unchecked, so no verification that it's a valid Spring '83 key is done.
func KeyPairFromRaw(privateKey ed25519.PrivateKey) *KeyPair {
	return &KeyPair{
		Key:             *KeyFromRaw(privateKey.Public().(ed25519.PublicKey)),
		PrivateKey:      hex.EncodeToString(privateKey),
		privateKeyBytes: privateKey,
	}
}

// ParseKeyPairUnchecked parses a keypair from the given hex-encoded private
// key. Unlike ParseKey, the key is not checked for Spring '83 validity (i.e.
// compliant with respect to time and format).
func ParseKeyPairUnchecked(privateKey string) (*KeyPair, error) {
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

	privateKeyBytes := ed25519.NewKeyFromSeed(seedBytes)

	return &KeyPair{*KeyFromRaw(privateKeyBytes.Public().(ed25519.PublicKey)), privateKey, privateKeyBytes}, nil
}

// Same as the above, but panics in case of failure.
func MustParseKeyPairUnchecked(privateKey string) *KeyPair {
	keyPair, err := ParseKeyPairUnchecked(privateKey)
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
