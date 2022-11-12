package nsmemstore

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/brandur/neospring/internal/nsstore"
)

type MemoryBoardStore struct {
	boards          map[string]*nsstore.Board
	logger          *logrus.Logger
	mut             sync.RWMutex
	reapLoopStarted bool
	timeNow         func() time.Time
}

func NewMemoryBoardStore(logger *logrus.Logger) *MemoryBoardStore {
	return &MemoryBoardStore{
		boards:  make(map[string]*nsstore.Board),
		logger:  logger,
		timeNow: time.Now,
	}
}

func (s *MemoryBoardStore) Get(ctx context.Context, key string) (*nsstore.Board, error) {
	s.mut.RLock()
	defer s.mut.RUnlock()

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
	s.mut.Lock()
	defer s.mut.Unlock()

	s.boards[key] = board
	return nil
}

func (s *MemoryBoardStore) ReapLoop(shutdown <-chan struct{}) {
	if s.reapLoopStarted {
		panic("ReapLoop already started -- should only be run once")
	}

	s.reapLoopStarted = true

	for {
		_ = s.reap()

		select {
		case <-shutdown:
			s.logger.Infof("Received shutdown signal")
			return

		case <-time.After(10 * time.Second):
		}
	}
}

func (s *MemoryBoardStore) reap() int {
	s.mut.Lock()
	defer s.mut.Unlock()

	now := s.timeNow()
	var numReaped int

	for key, board := range s.boards {
		if now.After(board.Timestamp.Add(nsstore.MaxContentAge)) {
			delete(s.boards, key)
			numReaped++
		}
	}

	s.logger.WithFields(logrus.Fields{
		"num_reaped": numReaped,
	}).Infof("Reaped %d board(s)", numReaped)

	return numReaped
}