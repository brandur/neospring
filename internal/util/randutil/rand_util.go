package randutil

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Intn is a shortcut for generating a random integer between 0 and max using
// crypto/rand.
func Intn(max int64) int64 {
	nBig, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(fmt.Sprintf("error generating random int: %v", err))
	}
	return nBig.Int64()
}
