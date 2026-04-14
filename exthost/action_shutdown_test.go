// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Steadybit GmbH

package exthost

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/steadybit/action-kit/go/action_kit_api/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

func TestActionShutdown_Prepare(t *testing.T) {
	osHostname = func() (string, error) {
		return "myhostname", nil
	}
	tests := []struct {
		name        string
		requestBody action_kit_api.PrepareActionRequestBody
		wantedError error
		wantedState *ActionState
	}{
		{
			name: "Should return config",
			requestBody: action_kit_api.PrepareActionRequestBody{
				Config: map[string]any{
					"reboot": "true",
				},
				ExecutionId: uuid.New(),
				Target: new(action_kit_api.Target{
					Attributes: map[string][]string{
						"host.hostname": {"myhostname"},
					},
				}),
			},
			wantedState: &ActionState{
				Reboot: true,
			},
		},
	}
	action := NewShutdownAction()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//Given
			state := ActionState{}
			request := tt.requestBody

			//When
			result, err := action.Prepare(context.Background(), &state, request)

			//Then
			if tt.wantedError != nil && err != nil {
				assert.EqualError(t, err, tt.wantedError.Error())
			} else if tt.wantedError != nil && result != nil {
				assert.Equal(t, result.Error.Title, tt.wantedError.Error())
			}
			if tt.wantedState != nil {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantedState.Reboot, state.Reboot)
			}
		})
	}
}

func Test_shutdownAction_Start(t *testing.T) {
	tests := []struct {
		name              string
		state             *ActionState
		prep              func(m *mockShutdown)
		wantedErrorTitle  string
		wantedErrorDetail string
	}{
		{
			name: "Should return no error when rebooting succeeds",
			state: &ActionState{
				Reboot: true,
			},
			prep: func(m *mockShutdown) {
				m.On("Reboot").Return(nil)
			},
		}, {
			name: "Should return error when rebooting fails",
			state: &ActionState{
				Reboot: true,
			},
			prep: func(m *mockShutdown) {
				m.On("Reboot").Return(errors.New("test error"))
			},
			wantedErrorTitle:  "Reboot failed",
			wantedErrorDetail: "test error",
		}, {
			name: "Should return no error when shutting down succeeds",
			state: &ActionState{
				Reboot: false,
			},
			prep: func(m *mockShutdown) {
				m.On("Shutdown").Return(nil)
			},
		}, {
			name: "Should return error when shutting down fails",
			state: &ActionState{
				Reboot: false,
			},
			prep: func(m *mockShutdown) {
				m.On("Shutdown").Return(errors.New("test error"))
			},
			wantedErrorTitle:  "Shutdown failed",
			wantedErrorDetail: "test error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &mockShutdown{}
			if tt.prep != nil {
				tt.prep(s)
			}
			l := &shutdownAction{s: s}

			result, err := l.Start(context.Background(), tt.state)
			if tt.wantedErrorTitle != "" {
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantedErrorTitle, result.Error.Title)
				assert.Equal(t, tt.wantedErrorDetail, *result.Error.Detail)
			} else {
				assert.NoError(t, err)
				assert.Nil(t, result)
			}
		})
	}
}

type mockShutdown struct {
	mock.Mock
}

func (m *mockShutdown) IsAvailable() bool {
	return m.Called().Get(0).(bool)
}

func (m *mockShutdown) Shutdown() error {
	arg := m.Called().Get(0)
	if arg == nil {
		return nil
	}
	return arg.(error)
}

func (m *mockShutdown) Reboot() error {
	arg := m.Called().Get(0)
	if arg == nil {
		return nil
	}
	return arg.(error)
}

func (m *mockShutdown) Name() string {
	return "mock"
}
