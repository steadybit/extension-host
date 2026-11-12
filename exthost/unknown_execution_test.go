// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"testing"

	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_status_of_an_unknown_execution_is_an_error(t *testing.T) {
	tests := map[string]func() (*action_kit_api.StatusResult, error){
		"fill disk":           statusOfUnknownExecution(NewFillDiskHostAction(nil), nil),
		"fill memory":         statusOfUnknownExecution(NewFillMemoryHostAction(nil), nil),
		"stress cpu":          statusOfUnknownExecution(NewStressCpuAction(nil), nil),
		"stop process":        statusOfUnknownExecution(NewStopProcessAction(), nil),
		"http delay":          statusOfUnknownExecution(NewNetworkDelayDependencyAction(nil), nil),
		"dns error":           statusOfUnknownExecution(NewNetworkDNSErrorInjectionAction(nil), nil),
		"tcp reset (L7 mode)": statusOfUnknownExecution(NewNetworkTcpResetAction(nil), func(s *NetworkTcpResetState) { s.L7 = true }),
	}
	for name, status := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := status()

			require.NoError(t, err)
			require.NotNil(t, result.Error)
			assert.Equal(t, action_kit_api.Errored, *result.Error.Status)
		})
	}
}

func statusOfUnknownExecution[T any](action action_kit_sdk.Action[T], modify func(*T)) func() (*action_kit_api.StatusResult, error) {
	return func() (*action_kit_api.StatusResult, error) {
		state := action.NewEmptyState()
		if modify != nil {
			modify(&state)
		}
		return action.(action_kit_sdk.ActionWithStatus[T]).Status(context.Background(), &state)
	}
}
