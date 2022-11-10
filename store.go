package main

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

type BoardStore interface {
	Get(ctx context.Context, key string) (*MemoryBoard, error)
	Put(ctx context.Context, key string, board *MemoryBoard) error
}

type MemoryBoard struct {
	Content   []byte
	Signature string
	Timestamp time.Time
}

type MemoryBoardStore struct {
	boards  map[string]*MemoryBoard
	timeNow func() time.Time
}

func NewMemoryBoardStore() *MemoryBoardStore {
	return &MemoryBoardStore{
		boards:  make(map[string]*MemoryBoard),
		timeNow: time.Now,
	}
}

func (s *MemoryBoardStore) Get(ctx context.Context, key string) (*MemoryBoard, error) {
	board, ok := s.boards[key]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Just in case the cleaner is behind, aggressively prune possibly outdated
	// content.
	if s.timeNow().After(board.Timestamp.Add(MaxContentAge)) {
		return nil, ErrKeyNotFound
	}

	return board, nil
}

func (s *MemoryBoardStore) Put(ctx context.Context, key string, board *MemoryBoard) error {
	s.boards[key] = board
	return nil
}
