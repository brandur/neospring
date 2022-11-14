// Package nsgcpstoragestore implements nsstore's `BoardStore` interface for
// GCP's storage service. Note that this should be configured out-of-band in
// that a bucket needs to be created, and a "delete" lifecycle on it that'll
// remove updated objects after 22 days.
package nsgcpstoragestore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"cloud.google.com/go/storage"
	"github.com/googleapis/gax-go"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"google.golang.org/api/option"

	"github.com/brandur/neospring/internal/nsstore"
	"github.com/brandur/neospring/internal/nsstore/nsmemorystore"
)

type GCPStorageStore struct {
	bucket        string
	logger        *logrus.Logger
	memoryStore   *nsmemorystore.MemoryStore
	name          string
	storageClient *storage.Client

	// All for purposes of testability.
	storageReader func(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	storageWriter func(ctx context.Context, bucket, key string) io.WriteCloser
	timeNow       func() time.Time
}

func NewGCPStorageStore(ctx context.Context, logger *logrus.Logger, serviceAccountJSON, bucket string) *GCPStorageStore { //nolint:lll
	storageClient, err := storage.NewClient(ctx, option.WithCredentialsJSON([]byte(serviceAccountJSON)))
	if err != nil {
		panic(err)
	}
	storageClient.SetRetry(
		storage.WithBackoff(gax.Backoff{
			Initial: 1 * time.Second,
			Max:     5 * time.Second,
		}),
		// Always retries, even for non-idempotent operations.
		storage.WithPolicy(storage.RetryAlways),
	)

	return &GCPStorageStore{
		bucket:        bucket,
		logger:        logger,
		memoryStore:   nsmemorystore.NewMemoryStore(logger),
		name:          reflect.TypeOf(GCPStorageStore{}).Name(),
		storageClient: storageClient,
		storageReader: func(ctx context.Context, bucket, key string) (io.ReadCloser, error) {
			return storageClient.Bucket(bucket).Object(key).NewReader(ctx) //nolint:wrapcheck
		},
		storageWriter: func(ctx context.Context, bucket, key string) io.WriteCloser {
			return storageClient.Bucket(bucket).Object(key).NewWriter(ctx)
		},
		timeNow: time.Now,
	}
}

func (s *GCPStorageStore) Get(ctx context.Context, key string) (*nsstore.Board, error) {
	// Check to see if we might have this cached in our memory store first
	// before going to slower GCP storage.
	board, err := s.memoryStore.Get(ctx, key)
	if err == nil {
		return board, nil
	}

	reader, err := s.storageReader(ctx, s.bucket, key)
	if err != nil {
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, nsstore.ErrKeyNotFound
		}

		return nil, xerrors.Errorf("error getting key reader: %w", err)
	}
	defer reader.Close()

	var storageBoard serializedBoard
	if err := json.NewDecoder(reader).Decode(&storageBoard); err != nil {
		return nil, xerrors.Errorf("error decoding board: %w", err)
	}

	// Just in case lifecycle expiration is behind, aggressively prune possibly
	// outdated content.
	if s.timeNow().After(storageBoard.Timestamp.Add(nsstore.MaxContentAge)) {
		s.logger.Infof(s.name+": Returning not found for stale key %q created %v", key, storageBoard.Timestamp)
		return nil, nsstore.ErrKeyNotFound
	}

	board = storageBoard.ToBoard()

	if err := s.memoryStore.Put(ctx, key, board); err != nil {
		return nil, err
	}

	return board, nil
}

func (s *GCPStorageStore) Put(ctx context.Context, key string, board *nsstore.Board) error {
	writer := s.storageWriter(ctx, s.bucket, key)

	if err := json.NewEncoder(writer).Encode(serializedBoardFrom(board)); err != nil {
		return xerrors.Errorf("error encoding board: %w", err)
	}

	if err := writer.Close(); err != nil {
		return xerrors.Errorf("error closing writer: %w", err)
	}

	s.logger.Infof(s.name+": Stored key %q to GCP storage", key)

	if err := s.memoryStore.Put(ctx, key, board); err != nil {
		return err
	}

	return nil
}

// For testing purposes only.
func (s *GCPStorageStore) SetTimeNow(timeNow func() time.Time) {
	s.memoryStore.SetTimeNow(timeNow)
	s.timeNow = timeNow
}

// ReapLoop starts a reaper forever loop that periodically cleans up expired
// keys. It blocks, so should be started on a goroutine.
//
// Only reaps the struct's internal memory store rather than GCP itself, so a
// delete lifetime policy still needs to be set on the GCP bucket in use.
func (s *GCPStorageStore) ReapLoop(ctx context.Context, shutdown <-chan struct{}) {
	s.memoryStore.ReapLoop(ctx, shutdown)
}

// Very similar to `nsstore.Board`, but a specific serialized format stored to a
// GCP key as an object.
type serializedBoard struct {
	Content   []byte    `json:"content"`
	Signature string    `json:"signature"`
	Timestamp time.Time `json:"timestamp"`
}

func serializedBoardFrom(b *nsstore.Board) *serializedBoard {
	return &serializedBoard{
		Content:   b.Content,
		Signature: b.Signature,
		Timestamp: b.Timestamp,
	}
}

func (b *serializedBoard) ToBoard() *nsstore.Board {
	return &nsstore.Board{
		Content:   b.Content,
		Signature: b.Signature,
		Timestamp: b.Timestamp,
	}
}
