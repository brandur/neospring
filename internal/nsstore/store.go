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
}
