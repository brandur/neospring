package nsmemstore

import (
	"context"
	"time"

	"github.com/brandur/neospring/internal/nsstore"
)

type MemoryBoardStore struct {
	boards  map[string]*nsstore.Board
	timeNow func() time.Time
}

func NewMemoryBoardStore() *MemoryBoardStore {
	return &MemoryBoardStore{
		boards:  make(map[string]*nsstore.Board),
		timeNow: time.Now,
	}
}

func (s *MemoryBoardStore) Get(ctx context.Context, key string) (*nsstore.Board, error) {
	board, ok := s.boards[key]
	if !ok {
		return nil, nsstore.ErrKeyNotFound
	}

	// Just in case the cleaner is behind, aggressively prune possibly outdated
	// content.
	if s.timeNow().After(board.Timestamp.Add(nsstore.MaxContentAge)) {
		return nil, nsstore.ErrKeyNotFound
	}

	return board, nil
}

func (s *MemoryBoardStore) Put(ctx context.Context, key string, board *nsstore.Board) error {
	s.boards[key] = board
	return nil
}
