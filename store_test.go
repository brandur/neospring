package main

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryBoardStore(t *testing.T) {
	ctx := context.Background()
	keyPair := MustParseKeyPair(samplePrivateKey, samplePublicKey)
	store := NewMemoryBoardStore()

	_, err := store.Get(ctx, keyPair.PublicKey)
	require.ErrorIs(t, ErrKeyNotFound, err)

	content := "some board content"
	board := &MemoryBoard{
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
