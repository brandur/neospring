package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemoryDenyList(t *testing.T) {
	denyList := NewMemoryDenyList()
	require.True(t, denyList.Contains(InfernalPublicKey))
	require.False(t, denyList.Contains(samplePublicKey))
}
