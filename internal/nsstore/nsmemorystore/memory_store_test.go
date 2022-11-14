package nsmemorystore

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/brandur/neospring/internal/nskey"
	"github.com/brandur/neospring/internal/nsstore"
)

const (
	samplePrivateKey = "90ba51828ecc30132d4707d55d24456fbd726514cf56ab4668b62392798e2540"
	samplePublicKey  = "e90e9091b13a6e5194c1fed2728d1fdb6de7df362497d877b8c0b8f0883e1124"
)

var logger = logrus.New()

func TestMemoryBoardStore(t *testing.T) {
	ctx := context.Background()
	keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
	store := NewMemoryStore(logger)
	store.SetTimeNow(func() time.Time { return stableTime })

	// Nothing stored initially.
	{
		_, err := store.Get(ctx, keyPair.PublicKey)
		require.ErrorIs(t, nsstore.ErrKeyNotFound, err)
	}

	const content = "some board content"
	board := &nsstore.Board{
		Content:   []byte(content),
		Signature: hex.EncodeToString(keyPair.Sign([]byte(content))),
		Timestamp: stableTime,
	}
	err := store.Put(ctx, keyPair.PublicKey, board)
	require.NoError(t, err)

	// After putting content, we now get the same content back.
	{
		boardFromStore, err := store.Get(ctx, keyPair.PublicKey)
		require.NoError(t, err)
		require.Equal(t, board, boardFromStore)
	}

	// When pushing time far into the future so that the content is after it's
	// expiry, content is considered not present again.
	{
		store.SetTimeNow(func() time.Time { return stableTime.Add(nsstore.MaxContentAge).Add(10 * time.Minute) })
		_, err := store.Get(ctx, keyPair.PublicKey)
		require.ErrorIs(t, nsstore.ErrKeyNotFound, err)
	}
}

func TestMemoryBoardStoreReap(t *testing.T) {
	ctx := context.Background()
	keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
	store := NewMemoryStore(logger)

	const content = "some board content"
	board := &nsstore.Board{
		Content:   []byte(content),
		Signature: hex.EncodeToString(keyPair.Sign([]byte(content))),
		Timestamp: stableTime,
	}
	err := store.Put(ctx, keyPair.PublicKey, board)
	require.NoError(t, err)
	require.Len(t, store.boards, 1)

	// Move into the future
	store.SetTimeNow(func() time.Time { return stableTime.Add(nsstore.MaxContentAge).Add(10 * time.Minute) })

	numReaped := store.reap()
	require.Equal(t, 1, numReaped)
	require.Len(t, store.boards, 0)
}

func TestMemoryBoardStoreReapLoop(t *testing.T) {
	ctx := context.Background()
	keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
	store := NewMemoryStore(logger)

	const content = "some board content"
	board := &nsstore.Board{
		Content:   []byte(content),
		Signature: hex.EncodeToString(keyPair.Sign([]byte(content))),
		Timestamp: stableTime,
	}
	err := store.Put(ctx, keyPair.PublicKey, board)
	require.NoError(t, err)
	require.Len(t, store.boards, 1)

	// Move into the future
	store.SetTimeNow(func() time.Time { return stableTime.Add(nsstore.MaxContentAge).Add(10 * time.Minute) })

	shutdown := make(chan struct{}, 1)
	close(shutdown)

	// We pre-closed the shutdown channel, so this should run once, notice the
	// shutdown, and exit.
	store.ReapLoop(ctx, shutdown)

	require.Len(t, store.boards, 0)
}

var stableTime = time.Date(2022, 11, 9, 10, 11, 12, 0, time.UTC)
