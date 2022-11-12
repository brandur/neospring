package nsmemstore

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/brandur/neospring/internal/nskey"
	"github.com/brandur/neospring/internal/nsstore"
)

const (
	samplePrivateKey = "90ba51828ecc30132d4707d55d24456fbd726514cf56ab4668b62392798e2540"
	samplePublicKey  = "e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124"
)

func TestMemoryBoardStore(t *testing.T) {
	ctx := context.Background()
	keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
	store := NewMemoryBoardStore()

	_, err := store.Get(ctx, keyPair.PublicKey)
	require.ErrorIs(t, nsstore.ErrKeyNotFound, err)

	content := "some board content"
	board := &nsstore.Board{
		Content:   []byte(content),
		Signature: hex.EncodeToString(keyPair.Sign([]byte(content))),
		Timestamp: stableTime,
	}

	err = store.Put(ctx, keyPair.PublicKey, board)
	require.NoError(t, err)

	boardFromStore, err := store.Get(ctx, keyPair.PublicKey)
	require.NoError(t, err)
	require.Equal(t, board, boardFromStore)
}

var stableTime = time.Date(2022, 11, 9, 10, 11, 12, 0, time.UTC)
