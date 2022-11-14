package nsstore

import (
	"context"
	"errors"
	"time"
)

const (
	// Spring '83 dictates a max content age of 22 days, after which content expires.
	MaxContentAge = 22 * 24 * time.Hour
)

var ErrKeyNotFound = errors.New("key not found")

type Board struct {
	Content   []byte
	Signature string
	Timestamp time.Time
}

type BoardStore interface {
	Get(ctx context.Context, key string) (*Board, error)
	Put(ctx context.Context, key string, board *Board) error

	// ReapLoop gives the store an opportunity to start a "reap loop" to help
	// expire boards that are passed their maximum age. The function is called
	// on a goroutine, so it's not necessary for implementations to start their
	// own. Stores may no-op if they have an alternative expiration mechanism.
	ReapLoop(ctx context.Context, shutdown <-chan struct{})
}
