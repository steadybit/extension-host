// Copyright 2026 steadybit GmbH. All rights reserved.

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFillMemoryOomScoreAdj(t *testing.T) {
	for _, score := range []int{-1000, -996, 0, 1000} {
		require.NoError(t, Specification{FillMemoryOomScoreAdj: score}.validate(), "score %d should be valid", score)
	}
	for _, score := range []int{-1001, 1001, 5000} {
		err := Specification{FillMemoryOomScoreAdj: score}.validate()
		require.Error(t, err, "score %d should be rejected", score)
		assert.Contains(t, err.Error(), "FILL_MEMORY_OOM_SCORE_ADJ")
	}
}
