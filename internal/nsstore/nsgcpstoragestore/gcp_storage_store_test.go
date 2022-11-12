package nsgcpstoragestore

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
	"time"

	"cloud.google.com/go/storage"
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

//go:embed service-account-key-storage-sample.json
var sampleServiceAccountJSON string

var stableTime = time.Date(2022, 11, 9, 10, 11, 12, 0, time.UTC)

func TestGCPStorageStoreRead(t *testing.T) {
	ctx := context.Background()
	keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
	store := NewGCPStorageStore(ctx, logger, sampleServiceAccountJSON, "neospring_board")

	store.storageReader = func(_ context.Context, bucket, key string) (io.Reader, error) {
		require.Equal(t, "neospring_board", bucket)
		require.Equal(t, samplePublicKey, key)
		return nil, storage.ErrObjectNotExist
	}

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

	store.storageReader = func(_ context.Context, bucket, key string) (io.Reader, error) {
		require.Equal(t, "neospring_board", bucket)
		require.Equal(t, samplePublicKey, key)

		return bytes.NewReader(mustJSONMarshal(t, board)), nil
	}

	{
		boardFromStore, err := store.Get(ctx, keyPair.PublicKey)
		require.NoError(t, err)
		require.Equal(t, board, boardFromStore)
	}

	// When pushing time far into the future so that the content is after it's
	// expiry, content is considered not present again.
	{
		store.timeNow = func() time.Time { return stableTime.Add(nsstore.MaxContentAge).Add(10 * time.Minute) }
		_, err := store.Get(ctx, keyPair.PublicKey)
		require.ErrorIs(t, nsstore.ErrKeyNotFound, err)
	}
}

func TestGCPStorageStorePut(t *testing.T) {
	var b bytes.Buffer
	ctx := context.Background()
	keyPair := nskey.MustParseKeyPairUnchecked(samplePrivateKey)
	store := NewGCPStorageStore(ctx, logger, sampleServiceAccountJSON, "neospring_board")

	store.storageWriter = func(ctx context.Context, bucket, key string) io.WriteCloser {
		require.Equal(t, "neospring_board", bucket)
		require.Equal(t, samplePublicKey, key)

		return &writeCloser{bufio.NewWriter(&b)}
	}

	const content = "some board content"
	board := &nsstore.Board{
		Content:   []byte(content),
		Signature: hex.EncodeToString(keyPair.Sign([]byte(content))),
		Timestamp: stableTime,
	}
	err := store.Put(ctx, keyPair.PublicKey, board)
	require.NoError(t, err)

	var boardFromStore serializedBoard
	mustJSONUnmarshal(t, b.Bytes(), &boardFromStore)
	require.Equal(t, board, boardFromStore.ToBoard())
}

type writeCloser struct {
	*bufio.Writer
}

func (wc *writeCloser) Close() error {
	return wc.Flush() //nolint:wrapcheck
}

func mustJSONMarshal(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func mustJSONUnmarshal(t *testing.T, data []byte, v any) {
	err := json.Unmarshal(data, v)
	require.NoError(t, err)
}
