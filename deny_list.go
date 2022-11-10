package main

import "golang.org/x/exp/maps"

const (
	InfernalPublicKey = "d17eef211f510479ee6696495a2589f7e9fb055c2576749747d93444883e0123"
)

// A base deny list containing the infernal key listed in the specification.
// Deny list implementations should always start with this bsae list and augment
// it from there.
var baseDenyList = map[string]struct{}{
	InfernalPublicKey: {},
}

type DenyList interface {
	Contains(key string) bool
}

type MemoryDenyList struct {
	denied map[string]struct{}
}

func NewMemoryDenyList() *MemoryDenyList {
	return &MemoryDenyList{
		denied: maps.Clone(baseDenyList),
	}
}

func (l *MemoryDenyList) Contains(key string) bool {
	_, ok := l.denied[key]
	return ok
}
