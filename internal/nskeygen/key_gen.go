package nskeygen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"runtime"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/brandur/neospring/internal/nskey"
)

const (
	// Month/year digits encoded into the end of a Spring '83 public key.
	expiryDigitsTimeFormat = "0106"
)

// GenerateConformingKey runs a parallel search for an Ed25519 key that expires
// in the same month as `expiryMonth`. Generally speaking, `expiryMonth` should
// target two years from the current month, which is the maximum validity period
// of a Spring '83 key.
// portion has the given target suffix.
func GenerateConformingKey(ctx context.Context, expiryMonth time.Time) (*nskey.KeyPair, int, error) {
	return generateConformingKeyWithSuffix(ctx, keySuffixWithExpiry(expiryMonth))
}

// Same as above, but specifically targets the given hex-encoded suffix. This
// function is broken out separately to make the function easily runnable in
// tests without having to spend the time and resources to generate a real
// Spring '83 key.
func generateConformingKeyWithSuffix(ctx context.Context, targetSuffix string) (*nskey.KeyPair, int, error) {
	var (
		conformingKeyChan = make(chan *nskey.KeyPair, runtime.NumCPU())
		done              atomic.Bool
		totalIterations   int64
	)

	targetSuffixBytes, oddChars := hexBytes(targetSuffix)

	{
		errGroup, _ := errgroup.WithContext(ctx)

		for i := 0; i < runtime.NumCPU(); i++ {
			errGroup.Go(func() error {
				for numIterations := 0; ; numIterations++ {
					if done.Load() {
						atomic.AddInt64(&totalIterations, int64(numIterations))
						return nil
					}

					_, privateKey, err := ed25519.GenerateKey(rand.Reader)
					if err != nil {
						return xerrors.Errorf("error generating key: %w", err)
					}

					if !suffixBytesEqual([]byte(privateKey), targetSuffixBytes, oddChars) {
						continue
					}

					conformingKeyChan <- nskey.KeyPairFromRaw(privateKey)

					done.Store(true)
				}
			})
		}

		if err := errGroup.Wait(); err != nil {
			return nil, 0, xerrors.Errorf("error finding key: %w", err)
		}
	}

	return <-conformingKeyChan, int(totalIterations), nil
}

// Breaks the given hex string into bytes. The boolean flag indicates whether
// there was an odd number of hex characters which means that the most
// significant byte only represents half a byte worth of relevant information.
func hexBytes(s string) ([]byte, bool) {
	var oddChars bool
	if len(s)%2 == 1 {
		oddChars = true
		s = "0" + s
	}

	sBytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}

	return sBytes, oddChars
}

// Bytewise suffix comparison that lets us avoid encoding every single generated
// key to a hex string. The `oddChars` flag handles the case where we only care
// about the half byte at the boundary, as is the case with a Spring '83 key
// where the last seven hex characters are relevant (each two characters are a
// byte).
func suffixBytesEqual(b, suffix []byte, oddChars bool) bool {
	if len(suffix) < 1 {
		return true
	}

	if oddChars {
		bBoundary := b[len(b)-len(suffix)]
		suffixBoundary := suffix[0]

		// Compare the half byte at the boundary, and then the rest of suffix
		// bytes as usual.
		return bBoundary&0x0f == suffixBoundary&0x0f &&
			bytes.Equal(b[len(b)-len(suffix)+1:], suffix[1:])
	}

	return bytes.Equal(b[len(b)-len(suffix):], suffix)
}

func keySuffixWithExpiry(t time.Time) string {
	return "83e" + t.Add(nskey.MaxLifetime).Format(expiryDigitsTimeFormat)
}
