// Copyright 2026 steadybit GmbH. All rights reserved.

package exthost

import (
	"testing"
	"time"

	action_kit_api "github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/memfill"
	"github.com/steadybit/extension-host/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func withFillMemoryConfig(t *testing.T, reserve string, oomScoreAdj int) {
	t.Helper()
	prevReserve, prevOom := config.Config.FillMemoryReserve, config.Config.FillMemoryOomScoreAdj
	config.Config.FillMemoryReserve = reserve
	config.Config.FillMemoryOomScoreAdj = oomScoreAdj
	t.Cleanup(func() {
		config.Config.FillMemoryReserve = prevReserve
		config.Config.FillMemoryOomScoreAdj = prevOom
	})
}

func TestFillMemoryOpts_UsageMode(t *testing.T) {
	withFillMemoryConfig(t, "512MiB", -996)

	opts, err := fillMemoryOpts(action_kit_api.PrepareActionRequestBody{
		Config: map[string]interface{}{
			"mode":     string(memfill.ModeUsage),
			"unit":     string(memfill.UnitPercent),
			"size":     100,
			"duration": 120000, // ms
		},
	})
	require.NoError(t, err)

	assert.Equal(t, 100, opts.Size)
	assert.Equal(t, memfill.ModeUsage, opts.Mode)
	assert.Equal(t, memfill.UnitPercent, opts.Unit)
	assert.Equal(t, 120*time.Second, opts.Duration)
	assert.True(t, opts.IgnoreCgroup)

	// Configured host-safety values flow into the fill.
	assert.Equal(t, "512MiB", opts.Reserve)
	require.NotNil(t, opts.OomScoreAdj)
	assert.Equal(t, -996, *opts.OomScoreAdj)
	assert.True(t, opts.Adaptive, "adaptive should be enabled in usage mode")
}

func TestFillMemoryOpts_AbsoluteModeDisablesAdaptive(t *testing.T) {
	// Distinct values prove the config actually flows through (not hardcoded).
	withFillMemoryConfig(t, "1GiB", -500)

	opts, err := fillMemoryOpts(action_kit_api.PrepareActionRequestBody{
		Config: map[string]interface{}{
			"mode":     string(memfill.ModeAbsolute),
			"unit":     string(memfill.UnitMegabyte),
			"size":     1024,
			"duration": 30000,
		},
	})
	require.NoError(t, err)

	// memfill rejects --adaptive outside usage mode, so it must be off here.
	assert.False(t, opts.Adaptive, "adaptive must be disabled in absolute mode")
	// Reserve/oom-score flow through regardless of mode.
	assert.Equal(t, "1GiB", opts.Reserve)
	require.NotNil(t, opts.OomScoreAdj)
	assert.Equal(t, -500, *opts.OomScoreAdj)
}
