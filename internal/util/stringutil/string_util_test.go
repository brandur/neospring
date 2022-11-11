package stringutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSampleLongString(t *testing.T) {
	require.Equal(t,
		"not very long",
		SampleLong("not very long"),
	)

	// Exactly one hundred characters (not sampled).
	require.Equal(t,
		"****************************************************************************************************",
		SampleLong("****************************************************************************************************"),
	)

	// 101 characters (sampled).
	require.Equal(t,
		"************************************************** ... [TRUNCATED; total_length: 101 characters] ... *************************************************", //nolint:lll
		SampleLong("*****************************************************************************************************"),
	)
}
