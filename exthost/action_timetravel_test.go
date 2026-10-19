// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package exthost

import (
	"context"
	"github.com/google/uuid"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/steadybit/action-kit/go/action_kit_commons/network/netfault"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestActionTimeTravel_Prepare(t *testing.T) {
	osHostname = func() (string, error) {
		return "myhostname", nil
	}
	executionId := uuid.New()
	tests := []struct {
		name        string
		requestBody action_kit_api.PrepareActionRequestBody
		wantedError string
		wantedState *TimeTravelActionState
	}{
		{
			name: "Should return config",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]any{
					"action":     "prepare",
					"duration":   "1000",
					"offset":     "1000",
					"disableNtp": "true",
				},
				ExecutionId: executionId,
				ExecutionContext: &action_kit_api.ExecutionContext{
					ExperimentKey: new("EXP-1"),
					ExecutionId:   new(42),
				},
				Target: new(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedState: &TimeTravelActionState{
				Offset:        1 * time.Second,
				DisableNtp:    true,
				OffsetApplied: false,
				ExecutionContext: netfault.ExecutionContext{
					ExperimentKey:         "EXP-1",
					ExperimentExecutionId: 42,
					TargetExecutionId:     executionId.String(),
				},
			},
		}, {
			name: "Should return error too low duration",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]any{
					"action":     "prepare",
					"duration":   "0",
					"offset":     "999",
					"disableNtp": "true",
				},
				ExecutionId: uuid.New(),
				Target: new(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},

			wantedError: "Duration must be greater / equal than 1s",
		},
	}
	action := NewTimetravelAction(nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//Given
			state := TimeTravelActionState{}
			request := tt.requestBody
			//When
			result, err := action.Prepare(context.Background(), &state, request)

			//Then
			if tt.wantedError != "" {
				if err != nil {
					assert.EqualError(t, err, tt.wantedError)
				} else if result != nil && result.Error != nil {
					assert.Equal(t, tt.wantedError, result.Error.Title)
				} else {
					assert.Fail(t, "Expected error but no error or result with error was returned")
				}
			}
			if tt.wantedState != nil {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantedState.OffsetApplied, state.OffsetApplied)
				assert.Equal(t, tt.wantedState.Offset, state.Offset)
				assert.Equal(t, tt.wantedState.DisableNtp, state.DisableNtp)
				assert.Equal(t, tt.wantedState.ExecutionContext, state.ExecutionContext)
			}
		})
	}
}
